//! Forensic verification: Naked Hash parity and master universal verification.
//!
//! Proves we can compute the correct vTXO/tx IDs using only the `bitcoin` crate
//! (naked deserialize + compute_txid) and that the same verify() works for both variants.

mod common;

use core::str::FromStr;
use std::fs;
use std::path::PathBuf;

use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use serde::Deserialize;
use std::io::Cursor;

use vpack::header::{Header, TxVariant, FLAG_PROOF_COMPACT};
use vpack::pack::pack;
use vpack::payload::tree::{VPackTree, VtxoLeaf};

// Naked hash tests use hex from audit fixtures (round_leaf, round_branch, oor).
const ARK_LABS_OOR_FORFEIT_TX_HEX: &str = "0300000001411d0d848ab79c0f7ae5a73742c4addd4e5b5646c2bc4bea854d287107825c750000000000feffffff02e803000000000000150014a1b2c3d4e5f6789012345678901234567890ab00000000000000000451024e7300000000";

fn decode_tx_from_hex(hex: &str) -> bitcoin::Transaction {
    let bytes = hex::decode(hex).expect("hex decode");
    let mut cursor = Cursor::new(bytes);
    bitcoin::Transaction::consensus_decode(&mut cursor).expect("consensus decode tx")
}

fn sha256d_display_hex(preimage: &[u8]) -> String {
    use bitcoin::hashes::sha256d;
    let hash = sha256d::Hash::hash(preimage);
    let bytes = hash.to_byte_array();
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// Leaf: Gold Standard round leaf (V3). sha256d(preimage) must equal expected_vtxo_id.
#[test]
fn naked_hash_ark_labs_leaf_version_2_vs_3() {
    const ROUND_LEAF_HEX_V3: &str = "0300000001a4e3e646f30f8965a797d105751b4e9d11e8da56fd7711d9d707a7a56ab0deec0000000000ffffffff024c0400000000000022512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea996700000000000000000451024e7300000000";
    const EXPECTED_LEAF_ID: &str =
        "47ea55bcb18fe596e19e2ad50603216926d12b7f0498d5204abf5604d4a4bc7d";

    let bytes_v3 = hex::decode(ROUND_LEAF_HEX_V3).expect("leaf hex");
    let hash_v3 = sha256d_display_hex(&bytes_v3);

    assert_eq!(
        hash_v3, EXPECTED_LEAF_ID,
        "Ark Labs Round Leaf (V3): sha256d(preimage) must match Gold Standard ID. Got: {}",
        hash_v3
    );
}

/// Branch: Round branch hex V3 vs V2. Only V3 must match expected_vtxo_id.
#[test]
fn naked_hash_ark_labs_branch_version_2_vs_3() {
    const ROUND_BRANCH_HEX_V3: &str = "03000000014e51f2ceb7c3d773283f476a5ea81a7bd5c2efbf81272c2008b81f1ca41700f60000000000ffffffff035802000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3f401000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae300000000000000000451024e7300000000";
    const EXPECTED_BRANCH_ID: &str =
        "f259d88f76b67559f51cd3c6c22f6579219ad75000d60ee78caaedc7418b1802";

    let bytes_v3 = hex::decode(ROUND_BRANCH_HEX_V3).expect("branch hex");
    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    assert!(
        hash_v3 == EXPECTED_BRANCH_ID,
        "Ark Labs Round Branch expected ID f259... should match V3 preimage"
    );
    assert!(
        !(hash_v2 == EXPECTED_BRANCH_ID),
        "Ark Labs Round Branch should NOT match V2 preimage"
    );
}

/// OOR forfeit hex: only Version 3 must match compute_txid.
#[test]
fn naked_hash_ark_labs_oor_version_2_vs_3() {
    let bytes_v3 = hex::decode(ARK_LABS_OOR_FORFEIT_TX_HEX).expect("oor hex");
    let tx_v3 = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX);
    let expected_oor_txid = format!("{}", tx_v3.compute_txid());

    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    assert!(
        hash_v3 == expected_oor_txid,
        "Ark Labs OOR Forfeit must match as V3"
    );
    assert!(
        !(hash_v2 == expected_oor_txid),
        "Ark Labs OOR Forfeit must NOT match as V2"
    );
}

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
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    expected_vtxo_id: Option<String>,
}

fn variant_from_meta(s: &str) -> TxVariant {
    match s.trim() {
        "0x03" => TxVariant::V3Plain,
        "0x04" => TxVariant::V3Anchored,
        _ => TxVariant::V3Plain,
    }
}

/// Master universal verification: same verify() for both Ark Labs and Second Tech.
#[test]
fn master_universal_verification() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let ark_path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
    let ark_contents = fs::read_to_string(&ark_path).expect("read Ark Labs vector");
    let ark_json: serde_json::Value =
        serde_json::from_str(&ark_contents).expect("parse Ark Labs JSON");

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

    let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
    let fee_anchor_script =
        hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
            .expect("decode fee_anchor_script");
    let outputs = ri["outputs"].as_array().expect("outputs array");
    let user_value = outputs[0]["value"].as_u64().expect("user value");
    let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script"))
        .expect("decode user script");

    let ark_leaf_siblings = vec![vpack::payload::tree::SiblingNode::Compact {
        hash: vpack::consensus::hash_sibling_birth_tx(0, &fee_anchor_script),
        value: 0,
        script: fee_anchor_script.clone(),
    }];
    let ark_tree = VPackTree {
        leaf: VtxoLeaf {
            amount: user_value,
            vout: 0,
            sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: user_script,
        },
        leaf_siblings: ark_leaf_siblings,
        path: Vec::new(),
        anchor,
        asset_id: None,
        fee_anchor_script,
    };

    let ark_header = Header {
        flags: FLAG_PROOF_COMPACT,
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

    let second_path = manifest_dir.join("tests/conformance/vectors/second/round_v3_borsh.json");
    let second_contents = fs::read_to_string(&second_path).expect("read Second Tech vector");
    let second_vector: AuditVector =
        serde_json::from_str(&second_contents).expect("parse Second Tech JSON");

    let expected_id_str = second_vector
        .raw_evidence
        .expected_vtxo_id
        .as_deref()
        .expect("expected_vtxo_id");
    let second_expected = vpack::VtxoId::from_str(expected_id_str).expect("parse expected VTXO ID");

    let tx_variant = variant_from_meta(&second_vector.meta.variant);
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
    let second_tree = match common::tree_from_ingredients(
        tx_variant,
        &second_vector.reconstruction_ingredients,
    ) {
        Some(Ok(t)) => t,
        Some(Err(e)) => panic!("logic adapter failed for Second Tech: {:?}", e),
        None => panic!("incomplete reconstruction_ingredients for Second Tech"),
    };
    let second_bytes = pack(&header, &second_tree).expect("pack Second Tech V-PACK");

    let ark_tree_result =
        vpack::verify(&ark_bytes, &ark_expected_id).expect("Ark Labs verification should succeed");
    let second_tree_result = vpack::verify(&second_bytes, &second_expected)
        .expect("Second Tech verification should succeed");

    assert!(!ark_tree_result.leaf.script_pubkey.is_empty() || ark_tree_result.leaf.amount > 0);
    assert!(
        !second_tree_result.leaf.script_pubkey.is_empty() || second_tree_result.leaf.amount > 0
    );
}
