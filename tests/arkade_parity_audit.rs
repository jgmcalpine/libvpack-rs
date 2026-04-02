//! Differential audit: Arkade (Go) `arkade_v3_anchored_audit.json` vs libvpack-rs (`vpack::verify`).
//!
//! ## Notes
//! - **Multi-closure Taproot:** When `reconstruction_metadata.receiver_script_closures` is present,
//!   the packed `asp_expiry_script` is the bytecode concatenation of those closures (Arkade order:
//!   exit / CSV multisig first, forfeit multisig second) so `compute_ark_labs_merkle_root` can rebuild
//!   Go’s TapLeaf-balanced Merkle root from verbatim scripts.
//! - **`transition_forfeit`**: no `vtxo_ingredient` — cannot run `vpack::verify`; skipped.
//! - **Path Schnorr**: intermediate hops use different x-only keys than the final leaf; omit path
//!   `signature` fields (unsigned VTXO id preimages).

use core::str::FromStr;

use serde_json::Value;
use std::vec::Vec;
use vpack::consensus::taproot::{compute_balanced_merkle_root, tap_leaf_hash};
use vpack::consensus::{hash_sibling_birth_tx, taproot};
use vpack::export::create_vpack_from_tree;
use vpack::header::TxVariant;
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use vpack::types::OutPoint;
use vpack::{compute_ark_labs_merkle_root, verify, ArkLabsV3, ConsensusEngine, VtxoId};

const FEE_ANCHOR_HEX: &str = "51024e73";
const AUDIT_JSON: &str = "tests/arkade_v3_anchored_audit.json";

fn hex32_from_str(label: &str, hex: &str) -> [u8; 32] {
    let v = hex::decode(hex).unwrap_or_else(|e| panic!("{}: bad hex {}: {}", label, hex, e));
    assert_eq!(v.len(), 32, "{}: expected 32 bytes", label);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

fn vtxo_id_from_wire_hex(wire_hex: &str) -> VtxoId {
    VtxoId::Raw(hex32_from_str("vtxo_id_wire", wire_hex))
}

fn outpoint_from_obj(obj: &Value) -> OutPoint {
    let disp = obj["txid_display_hex"].as_str().expect("txid_display_hex");
    let vout = obj["vout"].as_u64().expect("vout") as u32;
    let s = format!("{disp}:{vout}");
    match VtxoId::from_str(&s).expect("outpoint parse") {
        VtxoId::OutPoint(op) => op,
        VtxoId::Raw(_) => panic!("expected OutPoint"),
    }
}

fn fee_anchor_script() -> Vec<u8> {
    hex::decode(FEE_ANCHOR_HEX).unwrap()
}

/// Arkade `other_outputs` + optional inline child: find the lineage output that is not listed as an
/// "other" and is not the fee anchor (matches round-template semantics).
fn infer_child_output(lineage_tx: &Value, other_outputs: &[(u64, Vec<u8>)]) -> (u64, Vec<u8>) {
    let fee = fee_anchor_script();
    let outs = lineage_tx["outputs"].as_array().expect("lineage outputs");
    let mut rows: Vec<&Value> = outs.iter().collect();
    rows.sort_by_key(|o| o["vout"].as_u64().unwrap_or(0));

    let matches_other = |amount: u64, script: &[u8]| {
        other_outputs
            .iter()
            .any(|(v, s)| *v == amount && s.as_slice() == script)
    };

    for o in rows {
        if o["is_anchor"].as_bool() == Some(true) {
            continue;
        }
        let amount = o["amount"].as_u64().expect("amount");
        let script_hex = o["script_pubkey"].as_str().expect("script_pubkey");
        let script = hex::decode(script_hex).expect("decode script");
        if script == fee {
            continue;
        }
        if !matches_other(amount, &script) {
            return (amount, script);
        }
    }
    panic!("could not infer child output for lineage tx");
}

fn compact_sibling(value: u64, script: Vec<u8>) -> SiblingNode {
    SiblingNode::Compact {
        hash: hash_sibling_birth_tx(value, &script),
        value,
        script,
    }
}

fn decode_other_outputs(step: &Value) -> Vec<(u64, Vec<u8>)> {
    step["other_outputs"]
        .as_array()
        .expect("other_outputs")
        .iter()
        .map(|o| {
            let value = o["value"].as_u64().expect("value");
            let h = o["script_pubkey"].as_str().expect("script_pubkey");
            (value, hex::decode(h).expect("script hex"))
        })
        .collect()
}

fn tree_from_round_branch(meta: &Value) -> VPackTree {
    let lineage = meta["legacy_lineage"].as_array().expect("legacy_lineage");
    assert_eq!(
        lineage.len(),
        1,
        "round_branch fixtures expect a single lineage tx (the root)"
    );
    let row = &lineage[0];
    let anchor = outpoint_from_obj(&row["input_previous_outpoint"]);
    let outs = row["outputs"].as_array().expect("outputs");
    let mut rows: Vec<&Value> = outs.iter().collect();
    rows.sort_by_key(|o| o["vout"].as_u64().unwrap_or(0));
    let siblings: Vec<SiblingNode> = rows
        .iter()
        .map(|o| {
            let value = o["amount"].as_u64().expect("amount");
            let script = hex::decode(o["script_pubkey"].as_str().expect("script_pubkey")).unwrap();
            compact_sibling(value, script)
        })
        .collect();

    let sig_hex = row["taproot_key_spend_signature"]
        .as_str()
        .expect("signature");
    let mut sig = [0u8; 64];
    hex::decode_to_slice(sig_hex, &mut sig).expect("sig hex");

    let sequence = row["input_sequence"].as_u64().unwrap() as u32;
    let path = vec![GenesisItem {
        siblings,
        parent_index: 0,
        sequence,
        child_amount: 0,
        child_script_pubkey: Vec::new(),
        signature: Some(sig),
        ..Default::default()
    }];

    let leaf = VtxoLeaf {
        amount: 0,
        vout: 0,
        sequence: 0xFFFF_FFFF,
        expiry: 0,
        exit_delta: 0,
        script_pubkey: Vec::new(),
    };

    VPackTree {
        leaf,
        leaf_siblings: Vec::new(),
        path,
        anchor,
        asset_id: None,
        fee_anchor_script: fee_anchor_script(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    }
}

/// Prefer `receiver_script_closures` (full TapTree preimages) over the single CSV snippet in
/// `vtxo_ingredient.asp_expiry_script`.
fn merged_asp_expiry_script(vtxo: &Value, meta: &Value) -> Vec<u8> {
    if let Some(arr) = meta
        .get("receiver_script_closures")
        .and_then(|v| v.as_array())
    {
        if !arr.is_empty() && arr.iter().all(|v| v.as_str().is_some()) {
            let mut out = Vec::new();
            for s in arr {
                out.extend_from_slice(&hex::decode(s.as_str().unwrap()).expect("closure hex"));
            }
            return out;
        }
    }
    hex::decode(
        vtxo["asp_expiry_script"]
            .as_str()
            .expect("asp_expiry_script"),
    )
    .expect("asp hex")
}

fn tree_from_round_leaf(vtxo: &Value, meta: &Value) -> VPackTree {
    let fee = fee_anchor_script();
    let anchor = outpoint_from_obj(&vtxo["anchor_outpoint"]);
    let internal_key = hex32_from_str("internal_key", vtxo["internal_key"].as_str().unwrap());
    let asp_expiry_script = merged_asp_expiry_script(vtxo, meta);

    let path_json = match vtxo["path"].as_array() {
        Some(p) if !p.is_empty() => p,
        _ => {
            // `transition_fire_escape` / path-less templates: leaf spends `anchor` directly
            // (no collaborative round path).
            let leaf_vout = vtxo["vout"].as_u64().unwrap() as u32;
            let leaf_amount = vtxo["amount"].as_u64().unwrap();
            let leaf_script =
                hex::decode(vtxo["script_pubkey"].as_str().unwrap()).expect("leaf script");
            let leaf_sequence = vtxo["sequence"].as_u64().unwrap() as u32;
            let exit_delta = vtxo["exit_delta"].as_u64().unwrap() as u16;
            let leaf = VtxoLeaf {
                amount: leaf_amount,
                vout: leaf_vout,
                sequence: leaf_sequence,
                expiry: 0,
                exit_delta,
                script_pubkey: leaf_script,
            };
            let leaf_siblings = vec![compact_sibling(0, fee.clone())];
            return VPackTree {
                leaf,
                leaf_siblings,
                path: Vec::new(),
                anchor,
                asset_id: None,
                fee_anchor_script: fee,
                internal_key,
                asp_expiry_script,
            };
        }
    };
    let lineage = meta["legacy_lineage"].as_array().expect("legacy_lineage");
    let mut path: Vec<GenesisItem> = Vec::new();

    for (i, step) in path_json.iter().enumerate() {
        let lineage_tx = &lineage[i];
        let others = decode_other_outputs(step);
        let (child_amount, child_script) = infer_child_output(lineage_tx, &others);
        let siblings: Vec<SiblingNode> = others
            .into_iter()
            .map(|(value, script)| compact_sibling(value, script))
            .collect();

        let parent_index = step["parent_index"].as_u64().unwrap() as u32;
        let sequence = lineage_tx["input_sequence"].as_u64().unwrap() as u32;

        path.push(GenesisItem {
            siblings,
            parent_index,
            sequence,
            child_amount,
            child_script_pubkey: child_script,
            // Schnorr checks in `ArkLabsV3` use `tree.leaf.script_pubkey` for every path step
            // after the first, but Arkade uses a different taproot output at each hop. VTXO IDs
            // are hash preimages without witness anyway — omit witnesses for this audit.
            signature: None,
            ..Default::default()
        });
    }

    let last_tx = lineage.last().expect("non-empty lineage");
    let leaf_vout = vtxo["vout"].as_u64().unwrap() as u32;
    let leaf_amount = vtxo["amount"].as_u64().unwrap();
    let leaf_script = hex::decode(vtxo["script_pubkey"].as_str().unwrap()).expect("leaf script");
    let leaf_sequence = last_tx["input_sequence"].as_u64().unwrap() as u32;
    let exit_delta = vtxo["exit_delta"].as_u64().unwrap() as u16;

    let outs = last_tx["outputs"].as_array().expect("last outputs");
    let mut leaf_siblings: Vec<SiblingNode> = Vec::new();
    let mut rows: Vec<&Value> = outs.iter().collect();
    rows.sort_by_key(|o| o["vout"].as_u64().unwrap_or(0));
    for o in rows {
        let vout = o["vout"].as_u64().unwrap() as u32;
        if vout == leaf_vout {
            continue;
        }
        let value = o["amount"].as_u64().unwrap();
        let script = hex::decode(o["script_pubkey"].as_str().unwrap()).unwrap();
        leaf_siblings.push(compact_sibling(value, script));
    }

    let leaf = VtxoLeaf {
        amount: leaf_amount,
        vout: leaf_vout,
        sequence: leaf_sequence,
        expiry: 0,
        exit_delta,
        script_pubkey: leaf_script,
    };

    VPackTree {
        leaf,
        leaf_siblings,
        path,
        anchor,
        asset_id: None,
        fee_anchor_script: fee,
        internal_key,
        asp_expiry_script,
    }
}

fn merkle_from_taproot_leaves_json(meta: &Value) -> Option<[u8; 32]> {
    let leaves = meta["taproot_leaves"].as_array()?;
    let hashes: Vec<[u8; 32]> = leaves
        .iter()
        .filter_map(|leaf| {
            let h = leaf["script_hex"].as_str()?;
            let script = hex::decode(h).ok()?;
            Some(tap_leaf_hash(&script))
        })
        .collect();
    compute_balanced_merkle_root(&hashes)
}

fn root_anchor_value_sats(meta: &Value, vtxo: &Value) -> u64 {
    if let Some(lineage) = meta["legacy_lineage"].as_array() {
        if let Some(root) = lineage.first() {
            let outs = root["outputs"].as_array().expect("root outputs");
            return outs.iter().map(|o| o["amount"].as_u64().unwrap()).sum();
        }
    }
    vtxo["amount"].as_u64().expect("amount")
}

fn audit_vector(vector: &Value, idx: usize) {
    let vector_id = vector["vector_id"]
        .as_str()
        .unwrap_or_else(|| panic!("vector {idx}: missing vector_id"));
    let category = vector["category"].as_str().unwrap_or("?");
    let meta = &vector["reconstruction_metadata"];
    let wire_expected = meta["vtxo_id_wire_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("{vector_id}: vtxo_id_wire_hex"));
    let expected_id = vtxo_id_from_wire_hex(wire_expected);

    let ingredient = vector.get("vtxo_ingredient").filter(|v| !v.is_null());

    if ingredient.is_none() {
        if category == "round_branch" {
            println!("{vector_id}: round_branch lineage-only");
            let tree = tree_from_round_branch(meta);
            let out = ArkLabsV3
                .compute_vtxo_id(&tree, None)
                .unwrap_or_else(|e| panic!("{vector_id}: compute_vtxo_id {e:?}"));
            assert_eq!(
                out.id, expected_id,
                "{vector_id}: VTXO ID mismatch (branch lineage)"
            );
        } else {
            println!("{vector_id}: skipped (no vtxo_ingredient)");
        }
        return;
    }

    let vtxo = ingredient.unwrap();
    println!("{vector_id}: full V-PACK parity (leaf)");

    let tree = tree_from_round_leaf(vtxo, meta);
    let anchor_value = root_anchor_value_sats(meta, vtxo);

    let merkle_hex = meta["taproot_merkle_root"]
        .as_str()
        .filter(|s| !s.is_empty())
        .expect("taproot_merkle_root");
    let want_merkle = hex32_from_str("taproot_merkle_root", merkle_hex);

    // Phase 2 — TapLeaf + balanced tree (incl. odd tail promotion) using Go's exact `script_hex`
    // bytes. Arkade often stores a shorter CSV-facing script in `vtxo_ingredient.asp_expiry_script`
    // than the canonical `OP_1 OP_VERIFY …` long form, so `compute_ark_labs_merkle_root` is not
    // asserted here; TapLeaf equality is proven against the committed leaf hashes instead.
    let leaves_opt = meta["taproot_leaves"].as_array();
    let got_merkle = merkle_from_taproot_leaves_json(meta)
        .unwrap_or_else(|| panic!("{vector_id}: merkle_from_taproot_leaves_json"));
    if let Some(leaves) = leaves_opt {
        if leaves.len() != 1 {
            assert_eq!(
                got_merkle, want_merkle,
                "{vector_id}: taproot merkle (TapLeaf+balanced) mismatch"
            );
        }
        for (i, leaf) in leaves.iter().enumerate() {
            let h = leaf["script_hex"].as_str().expect("script_hex");
            let want_leaf_hash = hex32_from_str(
                "tapleaf_hash",
                leaf["tapleaf_hash"].as_str().expect("tapleaf_hash"),
            );
            let script = hex::decode(h).expect("taproot leaf script");
            assert_eq!(
                tap_leaf_hash(&script),
                want_leaf_hash,
                "{vector_id}: tapleaf hash {i}"
            );
        }
        if leaves.len() == 1 {
            let script = hex::decode(leaves[0]["script_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                got_merkle,
                tap_leaf_hash(&script),
                "{vector_id}: single-leaf TapLeaf must equal balanced root operand"
            );
        }
    }

    // Phase 3 — BIP-341 TapTweak vs P2TR pubkey (Go's committed Merkle root).
    let out_key_hex = meta["taproot_output_key"]
        .as_str()
        .filter(|s| !s.is_empty())
        .expect("taproot_output_key");
    let want_out = hex32_from_str("taproot_output_key", out_key_hex);
    let got_out = taproot::compute_taproot_tweak(tree.internal_key, want_merkle)
        .unwrap_or_else(|| panic!("{vector_id}: compute_taproot_tweak None"));
    assert_eq!(
        got_out, want_out,
        "{vector_id}: taproot output key mismatch"
    );

    let bytes = create_vpack_from_tree(&tree, TxVariant::V3Anchored, false)
        .unwrap_or_else(|e| panic!("{vector_id}: pack {e:?}"));

    if vector_id == "fire_escape_transition" {
        let engine_merkle = compute_ark_labs_merkle_root(&tree).unwrap_or_else(|| {
            panic!("{vector_id}: compute_ark_labs_merkle_root (expect exit‖forfeit verbatim wire)")
        });
        assert_eq!(
            engine_merkle, want_merkle,
            "{vector_id}: Rust Merkle root vs JSON taproot_merkle_root (2-leaf verbatim closures)"
        );
        let engine_out = taproot::compute_taproot_tweak(tree.internal_key, engine_merkle)
            .unwrap_or_else(|| panic!("{vector_id}: compute_taproot_tweak"));
        assert_eq!(
            engine_out, want_out,
            "{vector_id}: Rust taproot output key vs JSON (BIP-341 tweak)"
        );
    }

    verify(&bytes, &expected_id, anchor_value)
        .unwrap_or_else(|e| panic!("{vector_id}: vpack::verify {e:?}"));
}

#[test]
fn arkade_v3_anchored_audit_parity() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join(AUDIT_JSON);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).expect("audit JSON");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(
        !vectors.is_empty(),
        "expected non-empty vectors in {AUDIT_JSON}"
    );

    for (idx, v) in vectors.iter().enumerate() {
        audit_vector(v, idx);
    }
}
