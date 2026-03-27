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

// ---------------------------------------------------------------------------
// Root A: FeeAnchorMissing — leaf-only tree, no siblings, non-empty fee_anchor_script
// ---------------------------------------------------------------------------

#[test]
fn test_fee_anchor_missing_non_empty_script_no_siblings() {
    let tree = leaf_only_tree(0, vec![]);

    let ark_result = ArkLabsV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(ark_result, Err(VPackError::FeeAnchorMissing)),
        "ArkLabsV3: empty leaf_siblings + non-empty fee_anchor_script → FeeAnchorMissing, got: {:?}",
        ark_result
    );

    let sec_result = SecondTechV3.compute_vtxo_id(&tree, None);
    assert!(
        matches!(sec_result, Err(VPackError::FeeAnchorMissing)),
        "SecondTechV3: empty leaf_siblings + non-empty fee_anchor_script → FeeAnchorMissing, got: {:?}",
        sec_result
    );
}

#[test]
fn test_fee_anchor_empty_script_no_siblings_passes() {
    let tree = VPackTree {
        leaf: base_leaf(0),
        leaf_siblings: vec![],
        path: Vec::new(),
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    assert!(
        ArkLabsV3.compute_vtxo_id(&tree, None).is_ok(),
        "ArkLabsV3: empty siblings + empty fee_anchor_script must pass"
    );
    assert!(
        SecondTechV3.compute_vtxo_id(&tree, None).is_ok(),
        "SecondTechV3: empty siblings + empty fee_anchor_script must pass"
    );
}

// ---------------------------------------------------------------------------
// Root C: Value conservation — wrong anchor value triggers ValueMismatch
// ---------------------------------------------------------------------------

#[test]
fn test_value_conservation_wrong_anchor() {
    let tree = VPackTree {
        leaf: base_leaf(0),
        leaf_siblings: vec![compact_sibling(500)],
        path: vec![GenesisItem {
            siblings: vec![compact_sibling(500)],
            child_amount: 1500,
            child_script_pubkey: p2tr_script(),
            ..Default::default()
        }],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let correct_value = 2000u64;
    let wrong_value = correct_value + 1;

    let sec_ok = SecondTechV3.compute_vtxo_id(&tree, Some(correct_value));
    assert!(
        sec_ok.is_ok(),
        "SecondTechV3: correct anchor value must pass: {:?}",
        sec_ok.err()
    );

    let sec_err = SecondTechV3.compute_vtxo_id(&tree, Some(wrong_value));
    assert!(
        matches!(
            sec_err,
            Err(VPackError::ValueMismatch {
                expected: 2001,
                actual: 2000
            })
        ),
        "SecondTechV3: wrong anchor value must yield ValueMismatch, got: {:?}",
        sec_err
    );

    let ark_err = ArkLabsV3.compute_vtxo_id(&tree, Some(wrong_value));
    assert!(
        matches!(
            ark_err,
            Err(VPackError::ValueMismatch {
                expected: 2001,
                actual: 2000
            })
        ),
        "ArkLabsV3: wrong anchor value must yield ValueMismatch, got: {:?}",
        ark_err
    );
}

// ---------------------------------------------------------------------------
// Root D: Hand-off parent_index — observable via different VtxoId
// ---------------------------------------------------------------------------

#[test]
fn test_second_tech_handoff_parent_index_differs() {
    use vpack::consensus::TxInPreimage;
    use vpack::types::hashes::{sha256d, Hash};

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 0,
            vout: 0,
            sequence: 0xFFFF_FFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: Vec::new(),
        },
        leaf_siblings: vec![],
        path: vec![
            GenesisItem {
                siblings: vec![compact_sibling(1000)],
                parent_index: 0,
                child_amount: 5000,
                child_script_pubkey: p2tr_script(),
                ..Default::default()
            },
            GenesisItem {
                siblings: vec![compact_sibling(500)],
                parent_index: 1,
                child_amount: 4000,
                child_script_pubkey: p2tr_script(),
                ..Default::default()
            },
        ],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let step0_outs = SecondTechV3::reconstruct_link(&tree.path[0]).unwrap();
    let step0_in = TxInPreimage {
        prev_out_txid: tree.anchor.txid.to_byte_array(),
        prev_out_vout: tree.anchor.vout,
        sequence: tree.path[0].sequence,
    };
    let step0_txid = sha256d::Hash::hash(&vpack::consensus::tx_preimage(
        3,
        &[step0_in],
        &step0_outs,
        0,
    ))
    .to_byte_array();

    let step1_in = TxInPreimage {
        prev_out_txid: step0_txid,
        prev_out_vout: tree.path[1].parent_index,
        sequence: tree.path[1].sequence,
    };
    let step1_outs = SecondTechV3::reconstruct_link(&tree.path[1]).unwrap();
    let step1_txid = sha256d::Hash::hash(&vpack::consensus::tx_preimage(
        3,
        &[step1_in],
        &step1_outs,
        0,
    ))
    .to_byte_array();

    let result = SecondTechV3
        .compute_vtxo_id(&tree, None)
        .expect("should succeed");
    match result.id {
        VtxoId::OutPoint(op) => {
            assert_eq!(
                op.txid.to_byte_array(),
                step1_txid,
                "Hand-off txid must match manual computation using path[1].parent_index"
            );
            assert_eq!(op.vout, 0, "Final vout must be leaf.vout");
        }
        _ => panic!("expected OutPoint variant"),
    }
}

// ---------------------------------------------------------------------------
// Root B: Engine schnorr verification inside compute_vtxo_id
// ---------------------------------------------------------------------------

#[cfg(feature = "schnorr-verify")]
mod engine_schnorr {
    use super::*;
    use vpack::consensus::taproot_sighash::{sign_sighash_for_test, taproot_sighash};
    use vpack::consensus::TxInPreimage;
    use vpack::types::hashes::{sha256d, Hash};

    fn test_pubkey() -> [u8; 32] {
        let dummy = [0u8; 32];
        let (_sig, pk) = sign_sighash_for_test(&dummy);
        pk
    }

    fn p2tr_script_for_key(pubkey: &[u8; 32]) -> Vec<u8> {
        let mut s = Vec::with_capacity(34);
        s.push(0x51);
        s.push(0x20);
        s.extend_from_slice(pubkey);
        s
    }

    fn build_engine_schnorr_tree(leaf_script_pubkey: Vec<u8>) -> (VPackTree, u64) {
        let pk = test_pubkey();
        let p2tr = p2tr_script_for_key(&pk);
        let fee_script = vec![0x51, 0x02, 0x4e, 0x73];

        let anchor_value: u64 = 10_000;
        let child_amount_0: u64 = 9_000;
        let sibling_value_0: u64 = 1_000;
        let child_amount_1: u64 = 8_000;
        let sibling_value_1: u64 = 1_000;

        let step0_outputs = vec![
            vpack::consensus::TxOutPreimage {
                value: child_amount_0,
                script_pubkey: p2tr.as_slice(),
            },
            vpack::consensus::TxOutPreimage {
                value: sibling_value_0,
                script_pubkey: fee_script.as_slice(),
            },
        ];
        let step0_input = TxInPreimage {
            prev_out_txid: dummy_anchor().txid.to_byte_array(),
            prev_out_vout: dummy_anchor().vout,
            sequence: 0xFFFF_FFFF,
        };
        let step0_txid = sha256d::Hash::hash(&vpack::consensus::tx_preimage(
            3,
            &[step0_input],
            &step0_outputs,
            0,
        ))
        .to_byte_array();

        let step1_outputs = vec![
            vpack::consensus::TxOutPreimage {
                value: child_amount_1,
                script_pubkey: p2tr.as_slice(),
            },
            vpack::consensus::TxOutPreimage {
                value: sibling_value_1,
                script_pubkey: fee_script.as_slice(),
            },
        ];
        let step1_input = TxInPreimage {
            prev_out_txid: step0_txid,
            prev_out_vout: 0,
            sequence: 0xFFFF_FFFF,
        };

        let sighash = taproot_sighash(
            3,
            0,
            &step1_input,
            child_amount_0,
            &p2tr,
            &step1_outputs,
            0x00,
        );
        let (sig, _) = sign_sighash_for_test(&sighash);

        let sibling0 = SiblingNode::Compact {
            hash: [0u8; 32],
            value: sibling_value_0,
            script: fee_script.clone(),
        };
        let sibling1 = SiblingNode::Compact {
            hash: [0u8; 32],
            value: sibling_value_1,
            script: fee_script.clone(),
        };

        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: child_amount_1,
                vout: 0,
                sequence: 0xFFFF_FFFF,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: leaf_script_pubkey,
            },
            leaf_siblings: vec![],
            path: vec![
                GenesisItem {
                    siblings: vec![sibling0],
                    child_amount: child_amount_0,
                    child_script_pubkey: p2tr.clone(),
                    signature: Some([0x42u8; 64]),
                    ..Default::default()
                },
                GenesisItem {
                    siblings: vec![sibling1],
                    child_amount: child_amount_1,
                    child_script_pubkey: p2tr.clone(),
                    signature: Some(sig),
                    ..Default::default()
                },
            ],
            anchor: dummy_anchor(),
            asset_id: None,
            fee_anchor_script: fee_script,
            internal_key: [0u8; 32],
            asp_expiry_script: Vec::new(),
        };

        (tree, anchor_value)
    }

    #[test]
    fn test_engine_schnorr_valid_p2tr() {
        let pk = test_pubkey();
        let p2tr = p2tr_script_for_key(&pk);
        let (tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        let ark = ArkLabsV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            ark.is_ok(),
            "ArkLabsV3: valid sig at step 1 must pass: {:?}",
            ark.err()
        );

        let sec = SecondTechV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            sec.is_ok(),
            "SecondTechV3: valid sig at step 1 must pass: {:?}",
            sec.err()
        );
    }

    #[test]
    fn test_engine_schnorr_valid_33byte() {
        let pk = test_pubkey();
        let mut compressed = Vec::with_capacity(33);
        compressed.push(0x02);
        compressed.extend_from_slice(&pk);
        let (tree, anchor_value) = build_engine_schnorr_tree(compressed);

        let ark = ArkLabsV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            ark.is_ok(),
            "ArkLabsV3: valid sig with 33-byte key must pass: {:?}",
            ark.err()
        );

        let sec = SecondTechV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            sec.is_ok(),
            "SecondTechV3: valid sig with 33-byte key must pass: {:?}",
            sec.err()
        );
    }

    #[test]
    fn test_engine_schnorr_corrupted_sig() {
        let pk = test_pubkey();
        let p2tr = p2tr_script_for_key(&pk);
        let (mut tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        if let Some(ref mut sig) = tree.path[1].signature {
            sig[0] ^= 0xFF;
        }

        let ark = ArkLabsV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(ark, Err(VPackError::InvalidSignature)),
            "ArkLabsV3: corrupted sig at step 1 must yield InvalidSignature, got: {:?}",
            ark
        );

        let sec = SecondTechV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(sec, Err(VPackError::InvalidSignature)),
            "SecondTechV3: corrupted sig at step 1 must yield InvalidSignature, got: {:?}",
            sec
        );
    }

    /// x-only pubkey for scalar 1 — distinct from `sign_sighash_for_test`'s fixed key (`0x42…`).
    /// Used to sabotage a path step output script so the step-1 sighash no longer matches the signature.
    fn wrong_leaf_commitment_pubkey() -> [u8; 32] {
        use k256::schnorr::SigningKey;
        let mut scalar_one = [0u8; 32];
        scalar_one[31] = 1;
        let signing_key = SigningKey::from_bytes(&scalar_one[..]).expect("valid test scalar");
        signing_key.verifying_key().to_bytes().into()
    }

    #[test]
    fn test_ark_engine_sabotage_only_key_mismatch() {
        let pk = test_pubkey();
        assert_ne!(
            pk,
            wrong_leaf_commitment_pubkey(),
            "sanity: path[1] child script must differ from the P2TR that step 1 was signed against"
        );
        let p2tr = p2tr_script_for_key(&pk);
        let (mut tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        tree.path[1].child_script_pubkey = p2tr_script_for_key(&wrong_leaf_commitment_pubkey());

        let ark = ArkLabsV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(ark, Err(VPackError::InvalidSignature)),
            "ArkLabsV3: path[1] child_script_pubkey must match signed outputs; got: {:?}",
            ark
        );
    }

    #[test]
    fn test_ark_engine_sabotage_only_sig_math_mismatch() {
        let pk = test_pubkey();
        let p2tr = p2tr_script_for_key(&pk);
        let (mut tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        // Sabotage the signed step (i == 1): signature on path[1], not the leaf.
        if let Some(ref mut sig) = tree.path[1].signature {
            sig[0] ^= 0xFF;
        }

        let ark = ArkLabsV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(ark, Err(VPackError::InvalidSignature)),
            "ArkLabsV3: single-byte sig corruption must yield InvalidSignature, got: {:?}",
            ark
        );
    }

    #[test]
    fn test_second_tech_engine_sabotage_only_key_mismatch() {
        let pk = test_pubkey();
        assert_ne!(pk, wrong_leaf_commitment_pubkey());
        let p2tr = p2tr_script_for_key(&pk);
        let (mut tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        tree.path[1].child_script_pubkey = p2tr_script_for_key(&wrong_leaf_commitment_pubkey());

        let sec = SecondTechV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(sec, Err(VPackError::InvalidSignature)),
            "SecondTechV3: path[1] child_script_pubkey must match signed outputs; got: {:?}",
            sec
        );
    }

    #[test]
    fn test_second_tech_engine_sabotage_only_sig_math_mismatch() {
        let pk = test_pubkey();
        let p2tr = p2tr_script_for_key(&pk);
        let (mut tree, anchor_value) = build_engine_schnorr_tree(p2tr);

        if let Some(ref mut sig) = tree.path[1].signature {
            sig[0] ^= 0xFF;
        }

        let sec = SecondTechV3.compute_vtxo_id(&tree, Some(anchor_value));
        assert!(
            matches!(sec, Err(VPackError::InvalidSignature)),
            "SecondTechV3: single-byte sig corruption must yield InvalidSignature, got: {:?}",
            sec
        );
    }
}
