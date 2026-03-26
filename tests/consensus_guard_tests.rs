//! Negative tests for consensus engine variant confusion and index/bounds guards.
//!
//! Kills "delete !" mutants (variant identity enforcement) and ">/== +/*" mutants
//! (vout and parent_index bounds checks in `compute_vtxo_id` / `reconstruct_link`).

use vpack::consensus::{ArkLabsV3, ConsensusEngine, SecondTechV3, VtxoId};
use vpack::error::VPackError;
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use vpack::types::hashes::Hash;
use vpack::types::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

fn dummy_anchor() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0x11u8; 32]),
        vout: 0,
    }
}

fn compact_sibling(value: u64) -> SiblingNode {
    SiblingNode::Compact {
        hash: [0xAAu8; 32],
        value,
        script: vec![0x51, 0x01, 0x00],
    }
}

fn p2tr_script() -> Vec<u8> {
    let mut s = vec![0x51u8, 0x20];
    s.extend_from_slice(&[0xCCu8; 32]);
    s
}

fn base_leaf(vout: u32) -> VtxoLeaf {
    VtxoLeaf {
        amount: 1000,
        vout,
        sequence: 0xFFFF_FFFF,
        expiry: 0,
        exit_delta: 0,
        script_pubkey: p2tr_script(),
    }
}

fn leaf_only_tree(vout: u32, siblings: Vec<SiblingNode>) -> VPackTree {
    VPackTree {
        leaf: base_leaf(vout),
        leaf_siblings: siblings,
        path: Vec::new(),
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Step 1: Variant Confusion — engine identity is non-interchangeable
// ---------------------------------------------------------------------------

#[test]
fn test_ark_labs_tree_rejected_by_second_tech() {
    let tree = VPackTree {
        leaf: base_leaf(0),
        leaf_siblings: vec![compact_sibling(0)],
        path: vec![GenesisItem {
            siblings: vec![compact_sibling(500)],
            child_amount: 1000,
            child_script_pubkey: p2tr_script(),
            ..Default::default()
        }],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let ark_result = ArkLabsV3
        .compute_vtxo_id(&tree, None)
        .expect("ArkLabsV3 should succeed");
    let second_result = SecondTechV3.compute_vtxo_id(&tree, None);

    match second_result {
        Ok(output) => {
            assert_ne!(
                core::mem::discriminant(&ark_result.id),
                core::mem::discriminant(&output.id),
                "Same tree must produce different VtxoId variants (Raw vs OutPoint)"
            );
        }
        Err(_) => {
            // Error is also acceptable — engines are incompatible
        }
    }
}

#[test]
fn test_second_tech_tree_uses_full_sibling_rejected_by_ark_labs() {
    let full_txout = TxOut {
        value: Amount::from_sat(500),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x01, 0x00]),
    };
    let tree = VPackTree {
        leaf: base_leaf(0),
        leaf_siblings: vec![SiblingNode::Full(full_txout)],
        path: Vec::new(),
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let ark_result = ArkLabsV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(ark_result, Err(VPackError::EncodingError)),
        "ArkLabsV3 must reject SiblingNode::Full with EncodingError, got: {:?}",
        ark_result.err()
    );

    let second_result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        second_result.is_ok(),
        "SecondTechV3 should accept Full siblings: {:?}",
        second_result.err()
    );
}

#[test]
fn test_engine_variant_mismatch_id_types_diverge() {
    let tree = leaf_only_tree(0, vec![compact_sibling(0)]);

    let ark_id = ArkLabsV3
        .compute_vtxo_id(&tree, None)
        .expect("ArkLabsV3 leaf")
        .id;
    let second_id = SecondTechV3
        .compute_vtxo_id(&tree, None)
        .expect("SecondTechV3 leaf")
        .id;

    assert!(
        matches!(ark_id, VtxoId::Raw(_)),
        "ArkLabsV3 must produce Raw"
    );
    assert!(
        matches!(second_id, VtxoId::OutPoint(_)),
        "SecondTechV3 must produce OutPoint"
    );
    assert_ne!(
        format!("{}", ark_id),
        format!("{}", second_id),
        "Same tree fed to different engines must yield different identity strings"
    );
}

// ---------------------------------------------------------------------------
// Step 2: Index & Bounds Sabotage
// ---------------------------------------------------------------------------

#[test]
fn test_vtxo_id_vout_exceeds_outputs() {
    let tree = leaf_only_tree(5, vec![compact_sibling(0)]);

    let ark_result = ArkLabsV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(ark_result, Err(VPackError::InvalidVout(5))),
        "ArkLabsV3 must reject vout=5 when only 2 outputs exist, got: {:?}",
        ark_result.err()
    );

    let second_result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(second_result, Err(VPackError::InvalidVout(5))),
        "SecondTechV3 must reject vout=5 when only 2 outputs exist, got: {:?}",
        second_result.err()
    );
}

#[test]
fn test_vtxo_id_path_parent_index_out_of_range() {
    let tree = VPackTree {
        leaf: base_leaf(0),
        leaf_siblings: Vec::new(),
        path: vec![GenesisItem {
            siblings: vec![compact_sibling(500), compact_sibling(0)],
            parent_index: 3,
            child_amount: 1000,
            child_script_pubkey: p2tr_script(),
            ..Default::default()
        }],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(result, Err(VPackError::InvalidVout(3))),
        "parent_index=3 with 2 siblings (total_outputs=3) must fail: 3 >= 3, got: {:?}",
        result.err()
    );
}

#[test]
fn test_vtxo_id_vout_boundary_exact() {
    let tree = leaf_only_tree(1, vec![compact_sibling(0)]);

    let ark_result = ArkLabsV3.compute_vtxo_id(&tree, None);
    assert!(
        ark_result.is_ok(),
        "vout=1 with 1 sibling (2 outputs) must succeed for ArkLabsV3: {:?}",
        ark_result.err()
    );

    let second_result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        second_result.is_ok(),
        "vout=1 with 1 sibling (2 outputs) must succeed for SecondTechV3: {:?}",
        second_result.err()
    );
}

#[test]
fn test_vtxo_id_vout_one_past_boundary() {
    let tree = leaf_only_tree(2, vec![compact_sibling(0)]);

    let ark_result = ArkLabsV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(ark_result, Err(VPackError::InvalidVout(2))),
        "vout=2 with 1 sibling (2 outputs) must fail: 2 >= 2, got: {:?}",
        ark_result.err()
    );

    let second_result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(second_result, Err(VPackError::InvalidVout(2))),
        "vout=2 with 1 sibling (2 outputs) must fail: 2 >= 2, got: {:?}",
        second_result.err()
    );
}
