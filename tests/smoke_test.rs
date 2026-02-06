//! Milestone 4.1.5 — Consensus Smoke Test (Numerical Certainty)
//!
//! Proves we can compute the correct vTXO/tx IDs from raw sniffed hex using
//! only the `bitcoin` crate. No library logic — naked deserialize + compute_txid.

mod common;

use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use std::io::Cursor;
use std::fs;
use std::path::PathBuf;
use serde::Deserialize;
use vpack::header::{Header, TxVariant, HEADER_SIZE, FLAG_PROOF_COMPACT};
use vpack::pack::{pack, pack_from_payload};
use vpack::payload::tree::{VPackTree, VtxoLeaf};
use vpack::consensus::ConsensusEngine;
use core::str::FromStr;

const ARK_LABS_OOR_FORFEIT_TX_HEX: &str = "0300000001411d0d848ab79c0f7ae5a73742c4addd4e5b5646c2bc4bea854d287107825c750000000000feffffff02e803000000000000150014a1b2c3d4e5f6789012345678901234567890ab00000000000000000451024e7300000000";

const SECOND_TECH_ROUND_TX_HEX: &str = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff000000000001c8af000000000000225120649657f65947abfd83ff629ad8a851c795f419ed4d52a2748d3f868cc3e6c94d00000000";

/// Expected Txid of the Second Tech Round transaction (V2 + Chain).
const SECOND_TECH_ROUND_EXPECTED_TXID: &str = "abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3";

/// ROUND_1 vTXO ID we sniffed (OutPoint form). Its txid is a *child* of the round tx.
const ROUND_1_VTXO_ID_TXID_HEX: &str = "c806f5fc2cf7a5b0e8e2fa46cc9e0c7a511f43144f9d27f85a9108e4b8c4d662";

fn decode_tx_from_hex(hex: &str) -> bitcoin::Transaction {
    let bytes = hex::decode(hex).expect("hex decode");
    let mut cursor = Cursor::new(bytes);
    bitcoin::Transaction::consensus_decode(&mut cursor).expect("consensus decode tx")
}

/// Verification 1: Ark Labs OOR Forfeit (V3 + Anchor + Sequence 0xFFFFFFFE).
/// Deserialize the unsigned forfeit tx hex and compute its Txid.
/// The result is the ID of the transaction that created the payment output.
#[test]
fn smoke_ark_labs_oor_forfeit_txid() {
    let tx = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX);
    let txid = tx.compute_txid();
    let txid_display = format!("{}", txid);

    // We do not have forfeit_tx_test.go in repo; expected_vtxo_id is "COMPUTE_FROM_HEX".
    // Assert computation is deterministic and non-trivial.
    assert!(!txid_display.is_empty(), "txid must not be empty");
    assert_eq!(txid_display.len(), 64, "txid must be 32 bytes (64 hex chars)");

    let txid_again = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX).compute_txid();
    assert_eq!(txid, txid_again, "txid must be deterministic");

    eprintln!("[smoke] Ark Labs OOR Forfeit tx hex -> Txid (reversed/Big-Endian): {}", txid_display);
    eprintln!("[smoke] Compare this to the ID of the payment in forfeit_tx_test.go log.");
}

/// Verification 2: Second Tech Round (V2 + Chain).
/// Deserialize the round tx hex and compute Txid; must match expected exactly.
#[test]
fn smoke_second_tech_round_txid() {
    let tx = decode_tx_from_hex(SECOND_TECH_ROUND_TX_HEX);
    let txid = tx.compute_txid();
    let txid_display = format!("{}", txid);

    assert_eq!(
        txid_display,
        SECOND_TECH_ROUND_EXPECTED_TXID,
        "Second Tech Round tx hex must produce the expected Txid"
    );
    eprintln!("[smoke] Second Tech Round tx hex -> Txid: {} (matches expected)", txid_display);
}

// -----------------------------------------------------------------------------
// Naked hash experiments: Ark Labs version rule (Round = V2? vs OOR = V3?)
// -----------------------------------------------------------------------------

/// Helper: sha256d of preimage bytes, return display-order hex (reversed).
fn sha256d_display_hex(preimage: &[u8]) -> String {
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::Hash;
    let hash = sha256d::Hash::hash(preimage);
    let bytes = hash.to_byte_array();
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// Leaf test: Gold Standard round leaf (V3 only). sha256d(preimage) must equal expected_vtxo_id.
#[test]
fn naked_hash_ark_labs_leaf_version_2_vs_3() {
    // Gold Standard preimage: Parent ecdeb06a...:0, 1100 sats + fee anchor, V3.
    const ROUND_LEAF_HEX_V3: &str = "0300000001a4e3e646f30f8965a797d105751b4e9d11e8da56fd7711d9d707a7a56ab0deec0000000000ffffffff024c0400000000000022512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea996700000000000000000451024e7300000000";
    const EXPECTED_LEAF_ID: &str = "47ea55bcb18fe596e19e2ad50603216926d12b7f0498d5204abf5604d4a4bc7d";

    let bytes_v3 = hex::decode(ROUND_LEAF_HEX_V3).expect("leaf hex");
    let hash_v3 = sha256d_display_hex(&bytes_v3);

    assert_eq!(
        hash_v3,
        EXPECTED_LEAF_ID,
        "Ark Labs Round Leaf (V3): sha256d(preimage) must match Gold Standard ID. Got: {}",
        hash_v3
    );
}

/// Branch test: Round branch hex with version 3 vs 2. Which matches expected_vtxo_id?
#[test]
fn naked_hash_ark_labs_branch_version_2_vs_3() {
    // Round branch preimage from round_branch_v3.json (anchor internal, 3 outputs).
    const ROUND_BRANCH_HEX_V3: &str = "03000000014e51f2ceb7c3d773283f476a5ea81a7bd5c2efbf81272c2008b81f1ca41700f60000000000ffffffff035802000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3f401000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae300000000000000000451024e7300000000";
    const EXPECTED_BRANCH_ID: &str = "f259d88f76b67559f51cd3c6c22f6579219ad75000d60ee78caaedc7418b1802";

    let bytes_v3 = hex::decode(ROUND_BRANCH_HEX_V3).expect("branch hex");
    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    let v3_matches = hash_v3 == EXPECTED_BRANCH_ID;
    let v2_matches = hash_v2 == EXPECTED_BRANCH_ID;

    eprintln!("[naked] Branch V3 hash: {} -> matches expected: {}", hash_v3, v3_matches);
    eprintln!("[naked] Branch V2 hash: {} -> matches expected: {}", hash_v2, v2_matches);

    assert!(v3_matches, "Ark Labs Round Branch expected ID f259... should match V3 preimage");
    assert!(!v2_matches, "Ark Labs Round Branch should NOT match V2 preimage");
}

/// OOR test: OOR forfeit hex. Confirm it only matches as Version 3 (not V2).
#[test]
fn naked_hash_ark_labs_oor_version_2_vs_3() {
    // OOR forfeit preimage (already version 3 in hex).
    let bytes_v3 = hex::decode(ARK_LABS_OOR_FORFEIT_TX_HEX).expect("oor hex");
    let tx_v3 = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX);
    let expected_oor_txid = format!("{}", tx_v3.compute_txid());

    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    let v3_matches = hash_v3 == expected_oor_txid;
    let v2_matches = hash_v2 == expected_oor_txid;

    eprintln!("[naked] OOR V3 hash: {} -> matches compute_txid: {}", hash_v3, v3_matches);
    eprintln!("[naked] OOR V2 hash: {} -> matches compute_txid: {}", hash_v2, v2_matches);
    eprintln!("[naked] OOR expected (from V3 hex): {}", expected_oor_txid);

    assert!(v3_matches, "Ark Labs OOR Forfeit must match as V3");
    assert!(!v2_matches, "Ark Labs OOR Forfeit must NOT match as V2");
}

/// Identity: ROUND_1 ID is c806f5fc...:0. If that txid does NOT appear in the
/// round tx bytes, it confirms c806 is a *child* transaction (we must reconstruct the chain).
#[test]
fn smoke_round_tx_does_not_contain_round_1_txid() {
    let round_tx_bytes = hex::decode(SECOND_TECH_ROUND_TX_HEX).expect("round tx hex decode");

    // Txid in wire format (as in outpoints) is internal byte order: reverse of display.
    let txid_display_bytes = hex::decode(ROUND_1_VTXO_ID_TXID_HEX).expect("ROUND_1 txid hex");
    let mut wire_order = txid_display_bytes.clone();
    wire_order.reverse();

    let contains_display = round_tx_bytes
        .windows(32)
        .any(|w| w == txid_display_bytes.as_slice());
    let contains_wire = round_tx_bytes.windows(32).any(|w| w == wire_order.as_slice());

    assert!(
        !contains_display && !contains_wire,
        "ROUND_1 txid (c806f5fc...) must NOT appear in the round tx hex — confirms it is a child tx"
    );
    eprintln!(
        "[smoke] ROUND_1 txid {} is not present in ROUND_TX_HEX -> child tx; chain reconstruction required.",
        ROUND_1_VTXO_ID_TXID_HEX
    );
}

// -----------------------------------------------------------------------------
// Milestone 4.6 — Master Verifier Dispatcher Tests
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AuditVector {
    meta: AuditMeta,
    raw_evidence: RawEvidence,
    #[serde(default)]
    reconstruction_ingredients: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AuditMeta {
    variant: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    borsh_hex: Option<String>,
    expected_vtxo_id: Option<String>,
}

fn variant_from_meta(s: &str) -> TxVariant {
    match s.trim() {
        "0x03" => TxVariant::V3Plain,
        "0x04" => TxVariant::V3Anchored,
        _ => TxVariant::V3Plain,
    }
}

/// Build prefix: anchor (36 bytes) + fee_anchor_script (Borsh Vec<u8>).
fn build_prefix(fee_anchor_script: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Anchor: all zeros (36 bytes)
    out.extend_from_slice(&[0u8; 36]);
    // Fee anchor script: Borsh length-prefixed Vec<u8>
    let len = fee_anchor_script.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(fee_anchor_script);
    out
}

/// Build complete V-PACK bytes from a test vector.
fn build_vpack_bytes(vector: &AuditVector, borsh_hex: &str) -> Vec<u8> {
    let tree_bytes = hex::decode(borsh_hex).expect("decode borsh_hex");

    let tx_variant = variant_from_meta(&vector.meta.variant);
    
    // Try to get fee_anchor_script from reconstruction_ingredients, otherwise use default
    let fee_script: Vec<u8> = if let Some(fee_hex) = vector.reconstruction_ingredients
        .get("fee_anchor_script")
        .and_then(|v| v.as_str())
    {
        hex::decode(fee_hex).expect("decode fee_anchor_script")
    } else {
        match tx_variant {
            TxVariant::V3Anchored => vec![0x51, 0x02, 0x4e, 0x73],
            TxVariant::V3Plain => vec![0x51, 0x02, 0x4e, 0x73], // Second Tech also uses fee anchor
        }
    };
    let prefix = build_prefix(&fee_script);

    let mut payload = prefix;
    payload.extend_from_slice(&tree_bytes);

    let header = Header {
        flags: 0,
        version: 1,
        tx_variant,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };

    pack_from_payload(&header, &payload).expect("pack_from_payload")
}

/// Milestone 4.6: Master Universal Verification
/// Tests that the same verify() function works for both Ark Labs and Second Tech variants.
#[test]
fn master_universal_verification() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Test Ark Labs (V3Anchored) - build from reconstruction_ingredients
    let ark_path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
    let ark_contents = fs::read_to_string(&ark_path).expect("read Ark Labs vector");
    let ark_json: serde_json::Value = serde_json::from_str(&ark_contents).expect("parse Ark Labs JSON");
    
    let ark_expected_id_str = ark_json["raw_evidence"]["expected_vtxo_id"]
        .as_str()
        .expect("expected_vtxo_id present");
    let ark_expected_id = vpack::VtxoId::from_str(ark_expected_id_str).expect("parse expected VTXO ID");
    
    let ri = &ark_json["reconstruction_ingredients"];
    let anchor_outpoint_str = ri["parent_outpoint"].as_str().expect("parent_outpoint");
    let anchor_id = vpack::VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
    let anchor = match anchor_id {
        vpack::VtxoId::OutPoint(op) => op,
        vpack::VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
    };
    
    let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
    let fee_anchor_script = hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
        .expect("decode fee_anchor_script");
    let outputs = ri["outputs"].as_array().expect("outputs array");
    let user_value = outputs[0]["value"].as_u64().expect("user value");
    let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script"))
        .expect("decode user script");
    
    let ark_tree = VPackTree {
        leaf: VtxoLeaf {
            amount: user_value,
            vout: 0,
            sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: user_script,
        },
        path: Vec::new(),
        anchor,
        asset_id: None,
        fee_anchor_script,
    };
    
    let ark_header = Header {
        flags: 0,
        version: 1,
        tx_variant: TxVariant::V3Anchored,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };
    
    let ark_bytes = pack(&ark_header, &ark_tree).expect("pack Ark Labs V-PACK");
    
    // Test Second Tech (V3Plain)
    let second_path = manifest_dir.join("tests/conformance/vectors/second/round_v3_borsh.json");
    let second_contents = fs::read_to_string(&second_path).expect("read Second Tech vector");
    let second_vector: AuditVector = serde_json::from_str(&second_contents).expect("parse Second Tech JSON");
    
    if let (Some(borsh_hex), Some(expected_id_str)) = 
        (&second_vector.raw_evidence.borsh_hex, &second_vector.raw_evidence.expected_vtxo_id) {
        
        let second_bytes = build_vpack_bytes(&second_vector, borsh_hex);
        let second_expected = vpack::VtxoId::from_str(expected_id_str).expect("parse expected VTXO ID");
        
        // Both should succeed using the same function
        let ark_tree_result = vpack::verify(&ark_bytes, &ark_expected_id).expect("Ark Labs verification should succeed");
        let second_tree_result = vpack::verify(&second_bytes, &second_expected).expect("Second Tech verification should succeed");
        
        // Verify the trees were parsed correctly
        assert!(!ark_tree_result.leaf.script_pubkey.is_empty() || ark_tree_result.leaf.amount > 0);
        assert!(!second_tree_result.leaf.script_pubkey.is_empty() || second_tree_result.leaf.amount > 0);
    }
}

/// Milestone 4.6: Test Iterator
/// Walks all test vectors and verifies they pass, then corrupts them to verify they fail.
#[test]
fn test_iterator() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_root = manifest_dir.join("tests/conformance/vectors");

    for subdir in ["ark_labs", "second"] {
        let dir = vectors_root.join(subdir);
        if !dir.is_dir() {
            continue;
        }
        
        for entry in fs::read_dir(&dir).expect("read vectors dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            
            if path.extension().map(|e| e.to_str()) == Some(Some("json")) {
                let contents = fs::read_to_string(&path).expect("read JSON");
                let vector: AuditVector = serde_json::from_str(&contents).expect("parse audit JSON");

                let expected_id_str = match &vector.raw_evidence.expected_vtxo_id {
                    Some(s) if s != "COMPUTE_FROM_HEX" => s.as_str(),
                    _ => continue,
                };

                let tx_variant = variant_from_meta(&vector.meta.variant);
                let fee_script: Vec<u8> = vector.reconstruction_ingredients["fee_anchor_script"]
                    .as_str()
                    .map(|h| hex::decode(h).expect("decode fee_anchor_script"))
                    .unwrap_or_else(|| vec![0x51, 0x02, 0x4e, 0x73]);
                // Logic Adapters produce Compact siblings; use FLAG_PROOF_COMPACT for reader/writer symmetry.
                let header = Header {
                    flags: FLAG_PROOF_COMPACT,
                    version: 1,
                    tx_variant,
                    tree_arity: 16,
                    tree_depth: 32,
                    node_count: 0,
                    asset_type: 0,
                    payload_len: 0,
                    checksum: 0,
                };

                let vpack_bytes = match common::tree_from_ingredients(tx_variant, &vector.reconstruction_ingredients) {
                    Some(Ok(tree)) => pack(&header, &tree).expect("pack"),
                    Some(Err(e)) => panic!("logic adapter failed for {}: {:?}", path.display(), e),
                    None => {
                        let borsh_hex = vector.raw_evidence.borsh_hex.as_ref().expect("no ingredients and no borsh_hex");
                        if tx_variant == TxVariant::V3Plain {
                            let tree_bytes = hex::decode(borsh_hex).expect("decode borsh_hex");
                            let tree = vpack::adapters::second_tech::bark_to_vpack(&tree_bytes, &fee_script)
                                .expect("bark_to_vpack");
                            pack(&header, &tree).expect("pack")
                        } else {
                            build_vpack_bytes(&vector, borsh_hex)
                        }
                    }
                };

                let expected_id = vpack::VtxoId::from_str(expected_id_str)
                    .expect("parse expected VTXO ID");

                let result = vpack::verify(&vpack_bytes, &expected_id);
                assert!(
                    result.is_ok(),
                    "Vector {} should verify successfully",
                    path.display()
                );

                let mut corrupted = vpack_bytes.clone();
                if corrupted.len() > HEADER_SIZE + 50 {
                    corrupted[HEADER_SIZE + 50] ^= 0x01;
                    let corrupt_result = vpack::verify(&corrupted, &expected_id);
                    assert!(
                        corrupt_result.is_err(),
                        "Corrupted vector {} should fail verification",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Milestone 4.6.5: Internal Consistency Verification (Round-Trip)
/// Proves that pack() and verify() work together correctly by:
/// 1. Manually creating VPackTree structs
/// 2. Packing them into bytes using our own pack() function
/// 3. Verifying those bytes using verify()
/// This bypasses any field-order issues in raw sniffed hex and proves internal coherence.
#[test]
fn test_vpack_internal_consistency_roundtrip() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // ========================================================================
    // Ark Labs (V3Anchored) Round-Trip
    // ========================================================================
    
    // Step 1: Hydrate - Manually create VPackTree from round_leaf_v3.json ingredients
    let ark_path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
    let ark_contents = fs::read_to_string(&ark_path).expect("read Ark Labs vector");
    let ark_json: serde_json::Value = serde_json::from_str(&ark_contents).expect("parse Ark Labs JSON");
    
    let ark_expected_id_str = ark_json["raw_evidence"]["expected_vtxo_id"]
        .as_str()
        .expect("expected_vtxo_id present");
    let ark_expected_id = vpack::VtxoId::from_str(ark_expected_id_str).expect("parse expected VTXO ID");
    
    let ri = &ark_json["reconstruction_ingredients"];
    let anchor_outpoint_str = ri["parent_outpoint"].as_str().expect("parent_outpoint");
    let anchor_id = vpack::VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
    let anchor = match anchor_id {
        vpack::VtxoId::OutPoint(op) => op,
        vpack::VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
    };
    
    let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
    let fee_anchor_script = hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
        .expect("decode fee_anchor_script");
    let outputs = ri["outputs"].as_array().expect("outputs array");
    let user_value = outputs[0]["value"].as_u64().expect("user value");
    let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script"))
        .expect("decode user script");
    
    let ark_tree = VPackTree {
        leaf: VtxoLeaf {
            amount: user_value,
            vout: 0,
            sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: user_script,
        },
        path: Vec::new(),
        anchor,
        asset_id: None,
        fee_anchor_script,
    };
    
    // Step 2: Pack - Use our own pack() function to create V-PACK bytes
    let ark_header = Header {
        flags: 0,
        version: 1,
        tx_variant: TxVariant::V3Anchored,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };
    
    let ark_packed_bytes = pack(&ark_header, &ark_tree).expect("pack Ark Labs V-PACK");
    
    // Step 3: Verify - Call verify() on our own packed bytes
    let ark_verified_tree = vpack::verify(&ark_packed_bytes, &ark_expected_id)
        .expect("Ark Labs round-trip verification should succeed");
    
    // Verify the tree structure matches
    assert_eq!(ark_verified_tree.leaf.amount, ark_tree.leaf.amount);
    assert_eq!(ark_verified_tree.leaf.script_pubkey, ark_tree.leaf.script_pubkey);
    assert_eq!(ark_verified_tree.anchor, ark_tree.anchor);
    assert_eq!(ark_verified_tree.fee_anchor_script, ark_tree.fee_anchor_script);
    assert_eq!(ark_verified_tree.path.len(), ark_tree.path.len());

    // ========================================================================
    // Second Tech (V3Plain) Round-Trip - 5-Step Chain
    // ========================================================================
    
    // Step 1: Hydrate - Manually create VPackTree with 5-step chain
    // Using the same structure as test_second_tech_v3_deep_recursion
    let grandparent_hash_str = "abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3";
    let second_anchor_id = vpack::VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
    let second_anchor = match second_anchor_id {
        vpack::VtxoId::Raw(hash_bytes) => {
            use bitcoin::Txid;
            let txid = Txid::from_byte_array(hash_bytes);
            bitcoin::OutPoint { txid, vout: 0 }
        }
        vpack::VtxoId::OutPoint(op) => op,
    };

    let second_fee_anchor_script = hex::decode("51024e73").expect("decode fee anchor script");

    // Step 0: From ROUND_1 test data
    let step0_child_amount = 30000u64;
    let step0_child_script = hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
        .expect("decode child script");
    let step0_siblings = vec![
        vpack::payload::tree::SiblingNode::Compact {
            hash: [0u8; 32],
            value: 5000,
            script: hex::decode("51205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd431")
                .expect("decode sibling 0 script"),
        },
        vpack::payload::tree::SiblingNode::Compact {
            hash: [0u8; 32],
            value: 5000,
            script: hex::decode("5120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2")
                .expect("decode sibling 1 script"),
        },
        vpack::payload::tree::SiblingNode::Compact {
            hash: [0u8; 32],
            value: 5000,
            script: hex::decode("512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951")
                .expect("decode sibling 2 script"),
        },
    ];
    let step0_item = vpack::payload::tree::GenesisItem {
        siblings: step0_siblings,
        parent_index: 3,
        sequence: 0,
        child_amount: step0_child_amount,
        child_script_pubkey: step0_child_script,
        signature: None,
    };

    // Steps 1-4: Intermediate steps
    let mut second_path_items = vec![step0_item];
    for i in 1..5 {
        let step_siblings = vec![
            vpack::payload::tree::SiblingNode::Compact {
                hash: [0u8; 32],
                value: 1000,
                script: hex::decode("5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3")
                    .expect("decode sibling script"),
            },
        ];
        let step_item = vpack::payload::tree::GenesisItem {
            siblings: step_siblings,
            parent_index: 1,
            sequence: 0,
            child_amount: 20000 - (i * 1000),
            child_script_pubkey: hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
                .expect("decode child script"),
            signature: None,
        };
        second_path_items.push(step_item);
    }

    // Final leaf
    let second_tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 15000,
            vout: 0,
            sequence: 0,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
                .expect("decode leaf script"),
        },
        path: second_path_items, // 5 steps in path + 1 leaf = 6 levels total
        anchor: second_anchor,
        asset_id: None,
        fee_anchor_script: second_fee_anchor_script,
    };

    // Compute expected ID using the engine
    let second_engine = vpack::consensus::SecondTechV3;
    let second_expected_id = second_engine.compute_vtxo_id(&second_tree)
        .expect("compute Second Tech VTXO ID");

    // Step 2: Pack - Use our own pack() function to create V-PACK bytes.
    // Tree uses Compact siblings, so header must set FLAG_PROOF_COMPACT for reader/writer symmetry.
    let second_header = Header {
        flags: FLAG_PROOF_COMPACT,
        version: 1,
        tx_variant: TxVariant::V3Plain,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };
    
    let second_packed_bytes = pack(&second_header, &second_tree).expect("pack Second Tech V-PACK");
    
    // Step 3: Verify - Call verify() on our own packed bytes
    let second_verified_tree = vpack::verify(&second_packed_bytes, &second_expected_id)
        .expect("Second Tech round-trip verification should succeed");
    
    // Verify the tree structure matches
    assert_eq!(second_verified_tree.leaf.amount, second_tree.leaf.amount);
    assert_eq!(second_verified_tree.leaf.script_pubkey, second_tree.leaf.script_pubkey);
    assert_eq!(second_verified_tree.anchor, second_tree.anchor);
    assert_eq!(second_verified_tree.fee_anchor_script, second_tree.fee_anchor_script);
    assert_eq!(second_verified_tree.path.len(), second_tree.path.len());
    
    // Verify the path items match
    for (verified_item, original_item) in second_verified_tree.path.iter().zip(second_tree.path.iter()) {
        assert_eq!(verified_item.parent_index, original_item.parent_index);
        assert_eq!(verified_item.child_amount, original_item.child_amount);
        assert_eq!(verified_item.child_script_pubkey, original_item.child_script_pubkey);
        assert_eq!(verified_item.siblings.len(), original_item.siblings.len());
    }
}

/// Milestone 4.6.5: Negative Gate — reject invalid sequence values.
/// Builds a simple Ark Labs V-PACK with an invalid sequence (0x00000005)
/// and asserts that vpack::verify returns an error.
#[test]
fn test_reject_invalid_sequence() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ark_path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
    let ark_contents = fs::read_to_string(&ark_path).expect("read Ark Labs vector");
    let ark_json: serde_json::Value = serde_json::from_str(&ark_contents).expect("parse Ark Labs JSON");

    let ark_expected_id_str = ark_json["raw_evidence"]["expected_vtxo_id"]
        .as_str()
        .expect("expected_vtxo_id present");
    let ark_expected_id =
        vpack::VtxoId::from_str(ark_expected_id_str).expect("parse expected VTXO ID");

    let ri = &ark_json["reconstruction_ingredients"];
    let anchor_outpoint_str = ri["parent_outpoint"].as_str().expect("parent_outpoint");
    let anchor_id = vpack::VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
    let anchor = match anchor_id {
        vpack::VtxoId::OutPoint(op) => op,
        vpack::VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
    };

    let fee_anchor_script = hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
        .expect("decode fee_anchor_script");
    let outputs = ri["outputs"].as_array().expect("outputs array");
    let user_value = outputs[0]["value"].as_u64().expect("user value");
    let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script"))
        .expect("decode user script");

    // Deliberately use an invalid sequence (0x00000005)
    let invalid_sequence = 0x0000_0005u32;

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: user_value,
            vout: 0,
            sequence: invalid_sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: user_script,
        },
        path: Vec::new(),
        anchor,
        asset_id: None,
        fee_anchor_script,
    };

    let header = Header {
        flags: 0,
        version: 1,
        tx_variant: TxVariant::V3Anchored,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };

    let packed_bytes = pack(&header, &tree).expect("pack invalid-sequence V-PACK");

    // vpack::verify must reject this V-PACK (any error variant is acceptable here).
    let result = vpack::verify(&packed_bytes, &ark_expected_id);
    assert!(
        result.is_err(),
        "V-PACK with invalid sequence should be rejected"
    );
}
