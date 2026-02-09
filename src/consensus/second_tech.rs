//! Second Tech V3-Plain consensus engine (Variant 0x03).
//!
//! Reconstructs VTXO identity via a **Recursive Transaction Chain**: a chain of Bitcoin V3
//! transactions. Each link has chain-link outputs (next link + fee anchor); Double-SHA256
//! yields the TxID. The result is `VtxoId::OutPoint` (Hash:Index). Borsh is used for storage
//! only; the verified math is the chain of V3 transaction hashes.

use alloc::vec::Vec;

use crate::types::{hashes::Hash, hashes::sha256d, OutPoint, Txid};

use crate::consensus::{
    hash_sibling_birth_tx, tx_preimage, ConsensusEngine, TxInPreimage, TxOutPreimage, VtxoId,
};
use crate::error::VPackError;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree};

#[cfg(feature = "schnorr-verify")]
use crate::consensus::taproot_sighash::{extract_verify_key, taproot_sighash, verify_schnorr_bip340};

/// Second Tech V3-Plain consensus engine (Variant 0x03).
///
/// Reconstructs VTXO identity via the **Recursive Transaction Chain**: each path step is a
/// Bitcoin V3 transaction with chain-link outputs (next link + fee anchor). Sequence is
/// 0x00000000; version 3 (TRUC). Double-SHA256 produces `VtxoId::OutPoint` (TxID:vout).
pub struct SecondTechV3;

impl ConsensusEngine for SecondTechV3 {
    fn compute_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError> {
        // If path is empty, this is a leaf node
        if tree.path.is_empty() {
            if tree.leaf_siblings.is_empty() && !tree.fee_anchor_script.is_empty() {
                return Err(VPackError::FeeAnchorMissing);
            }
            return self.compute_leaf_vtxo_id(tree);
        }

        // Top-down chaining: start with on-chain anchor
        let mut current_prevout = tree.anchor;
        let mut last_outpoint = None;
        let mut prev_output_values: Option<Vec<u64>> = None;
        let mut prev_output_scripts: Option<Vec<Vec<u8>>> = None;

        // Iterate through path (top-down from root to leaf). Fee anchor is last sibling (adapter provides it).
        for (i, genesis_item) in tree.path.iter().enumerate() {
            let outputs = Self::reconstruct_link(genesis_item)?;

            // Build input spending current_prevout; use sequence from data
            let input = TxInPreimage {
                prev_out_txid: current_prevout.txid.to_byte_array(),
                prev_out_vout: current_prevout.vout,
                sequence: genesis_item.sequence,
            };

            #[cfg(feature = "schnorr-verify")]
            if let Some(sig) = genesis_item.signature {
                if i > 0 {
                    let verify_key = extract_verify_key(tree.leaf.script_pubkey.as_slice())
                        .or_else(|| {
                            if tree.leaf.script_pubkey.len() == 33 {
                                tree.leaf.script_pubkey[1..33].try_into().ok()
                            } else {
                                None
                            }
                        });
                    let verify_key = verify_key.ok_or(VPackError::InvalidSignature)?;
                    let vals = prev_output_values.as_ref().ok_or(VPackError::EncodingError)?;
                    let scripts =
                        prev_output_scripts.as_ref().ok_or(VPackError::EncodingError)?;
                    let idx = current_prevout.vout as usize;
                    if idx >= vals.len() || idx >= scripts.len() {
                        return Err(VPackError::InvalidVout(current_prevout.vout));
                    }
                    let parent_amount = vals[idx];
                    let parent_script = scripts[idx].as_slice();
                    let sighash =
                        taproot_sighash(3, 0, &input, parent_amount, parent_script, &outputs);
                    verify_schnorr_bip340(&verify_key, &sighash, &sig)?;
                }
            }

            // Hash transaction → OutPoint
            let txid_bytes = Self::hash_transaction(3, &[input], &outputs, 0)?;
            let txid = Txid::from_byte_array(txid_bytes);

            // Determine vout for hand-off: use next item's parent_index, or leaf.vout if last
            let vout = if i + 1 < tree.path.len() {
                tree.path[i + 1].parent_index
            } else {
                tree.leaf.vout
            };

            // Store the last transaction's OutPoint
            last_outpoint = Some(OutPoint { txid, vout });

            prev_output_values = Some(outputs.iter().map(|o| o.value).collect());
            prev_output_scripts = Some(
                outputs
                    .iter()
                    .map(|o| o.script_pubkey.to_vec())
                    .collect(),
            );

            // Hand-off: Convert to OutPoint for next step
            current_prevout = OutPoint { txid, vout };
        }

        // Final step: Build leaf transaction spending current_prevout (if leaf is valid)
        // If leaf has empty script_pubkey, return the ID from the last path transaction
        if tree.leaf.script_pubkey.is_empty() {
            // Return the OutPoint from the last transaction
            Ok(VtxoId::OutPoint(
                last_outpoint.expect("path should have at least one item"),
            ))
        } else {
            self.compute_leaf_vtxo_id_with_prevout(tree, current_prevout)
        }
    }
}

impl SecondTechV3 {
    /// Compute VTXO ID for a leaf node (no path, final link).
    ///
    /// A leaf has two outputs:
    /// - Output 0: The final leaf script - uses script_pubkey from VtxoLeaf
    /// - Output 1: The Fee Anchor (51024e73)
    fn compute_leaf_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError> {
        self.compute_leaf_vtxo_id_with_prevout(tree, tree.anchor)
    }

    /// Compute VTXO ID for a leaf node with a custom prevout.
    /// Used for the final leaf transaction in recursive path traversal.
    fn compute_leaf_vtxo_id_with_prevout(
        &self,
        tree: &VPackTree,
        prevout: OutPoint,
    ) -> Result<VtxoId, VPackError> {
        let num_outputs = 1 + tree.leaf_siblings.len();
        if tree.leaf.vout >= num_outputs as u32 {
            return Err(VPackError::InvalidVout(tree.leaf.vout));
        }
        // Build outputs from data only: [leaf output] + leaf_siblings (adapter provides fee anchor when required)
        let mut outputs = Vec::with_capacity(num_outputs);
        outputs.push(TxOutPreimage {
            value: tree.leaf.amount,
            script_pubkey: tree.leaf.script_pubkey.as_slice(),
        });
        for sibling in &tree.leaf_siblings {
            let (value, script) = match sibling {
                SiblingNode::Compact { hash, value, script } => {
                    let computed = hash_sibling_birth_tx(*value, script.as_slice());
                    if computed != *hash {
                        return Err(VPackError::SiblingHashMismatch);
                    }
                    (*value, script.as_slice())
                }
                SiblingNode::Full(txout) => {
                    (txout.value.to_sat(), txout.script_pubkey.as_bytes())
                }
            };
            outputs.push(TxOutPreimage { value, script_pubkey: script });
        }

        // Build input from prevout OutPoint; use sequence from data
        let input = TxInPreimage {
            prev_out_txid: prevout.txid.to_byte_array(),
            prev_out_vout: prevout.vout,
            sequence: tree.leaf.sequence,
        };

        // Hash the transaction: Version 3, Locktime 0
        let txid_bytes = Self::hash_transaction(3, &[input], &outputs, 0)?;

        // Convert to TxID and create OutPoint with vout from leaf
        let txid = Txid::from_byte_array(txid_bytes);
        let outpoint = OutPoint {
            txid,
            vout: tree.leaf.vout,
        };

        Ok(VtxoId::OutPoint(outpoint))
    }

    /// Reconstruct a chain link's outputs from data only.
    ///
    /// **Output Construction Rule:**
    /// - Total Outputs = siblings.len() + 1 (siblings include fee anchor as last; adapter provides it).
    /// - For each index i from 0 to total_outputs-1:
    ///   - If i == parent_index: Place the Child Coin (Amount/Script)
    ///   - Else: Place the next sibling from the siblings array (order preserved).
    pub fn reconstruct_link<'a>(
        genesis_item: &'a GenesisItem,
    ) -> Result<Vec<TxOutPreimage<'a>>, VPackError> {
        let siblings_count = genesis_item.siblings.len();
        let parent_index = genesis_item.parent_index as usize;
        let total_outputs = siblings_count + 1;

        if parent_index >= total_outputs {
            return Err(VPackError::InvalidVout(genesis_item.parent_index));
        }

        let mut outputs = Vec::with_capacity(total_outputs);
        let mut sibling_idx = 0;

        for i in 0..total_outputs {
            if i == parent_index {
                outputs.push(TxOutPreimage {
                    value: genesis_item.child_amount,
                    script_pubkey: genesis_item.child_script_pubkey.as_slice(),
                });
            } else {
                if sibling_idx >= siblings_count {
                    return Err(VPackError::EncodingError);
                }
                let sibling = &genesis_item.siblings[sibling_idx];
                let (value, script) = match sibling {
                    SiblingNode::Compact { hash, value, script } => {
                        let computed = hash_sibling_birth_tx(*value, script.as_slice());
                        if computed != *hash {
                            return Err(VPackError::SiblingHashMismatch);
                        }
                        (*value, script.as_slice())
                    }
                    SiblingNode::Full(txout) => {
                        (txout.value.to_sat(), txout.script_pubkey.as_bytes())
                    }
                };
                outputs.push(TxOutPreimage {
                    value,
                    script_pubkey: script,
                });
                sibling_idx += 1;
            }
        }

        if sibling_idx != siblings_count {
            return Err(VPackError::EncodingError);
        }

        Ok(outputs)
    }

    /// Helper function to hash a transaction.
    ///
    /// Takes transaction components, builds the preimage, applies Double-SHA256,
    /// and returns the hash bytes in internal (wire) order.
    fn hash_transaction(
        version: u32,
        inputs: &[TxInPreimage],
        outputs: &[TxOutPreimage<'_>],
        locktime: u32,
    ) -> Result<[u8; 32], VPackError> {
        // Build transaction preimage
        let preimage_bytes = tx_preimage(version, inputs, outputs, locktime);

        // Apply Double-SHA256
        let hash = sha256d::Hash::hash(&preimage_bytes);

        // Extract raw bytes in internal (wire) order
        Ok(hash.to_byte_array())
    }

    /// Helper function to get the transaction preimage bytes (for debugging).
    #[cfg(test)]
    #[allow(dead_code)]
    fn get_preimage_bytes(
        version: u32,
        inputs: &[TxInPreimage],
        outputs: &[TxOutPreimage<'_>],
        locktime: u32,
    ) -> Vec<u8> {
        tx_preimage(version, inputs, outputs, locktime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::hash_sibling_birth_tx;
    use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
    use alloc::format;
    use alloc::vec;
    use core::str::FromStr;
    use std::path::PathBuf;

    #[test]
    fn test_second_tech_v3_link_verification() {
        // Gold Standard: ROUND_1 Step 0 — ingredients loaded from fixture (no forensic hex in src/).
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture_path = manifest_dir.join("tests/fixtures/second_tech_round1_step0.json");
        let contents = std::fs::read_to_string(&fixture_path).expect("read step0 fixture");
        let j: serde_json::Value = serde_json::from_str(&contents).expect("parse fixture JSON");

        let grandparent_hash_str = j["grandparent_hash"].as_str().expect("grandparent_hash");
        let anchor_id = VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
        let anchor = match anchor_id {
            VtxoId::Raw(hash_bytes) => {
                use crate::types::Txid;
                let txid = Txid::from_byte_array(hash_bytes);
                OutPoint { txid, vout: 0 }
            }
            VtxoId::OutPoint(op) => op,
        };

        let child_amount = j["child_amount"].as_u64().expect("child_amount") as u64;
        let child_script = hex::decode(j["child_script"].as_str().expect("child_script"))
            .expect("decode child script");
        let fee_anchor_script =
            hex::decode(j["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee anchor");
        let sibling_value = j["sibling_value"].as_u64().expect("sibling_value") as u64;
        let parent_index = j["parent_index"].as_u64().expect("parent_index") as u32;
        let sibling_scripts: Vec<Vec<u8>> = j["sibling_scripts"]
            .as_array()
            .expect("sibling_scripts array")
            .iter()
            .map(|v| hex::decode(v.as_str().expect("script")).expect("decode sibling script"))
            .collect();

        let mut siblings: Vec<SiblingNode> = sibling_scripts
            .into_iter()
            .map(|script| SiblingNode::Compact {
                hash: hash_sibling_birth_tx(sibling_value, &script),
                value: sibling_value,
                script,
            })
            .collect();
        siblings.push(SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        });

        let genesis_item = GenesisItem {
            siblings,
            parent_index,
            sequence: 0,
            child_amount,
            child_script_pubkey: child_script,
            signature: None,
        };

        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 0,
                vout: 0,
                sequence: 0,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: Vec::new(),
            },
            leaf_siblings: Vec::new(),
            path: vec![genesis_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = SecondTechV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        let expected_str = j["expected_vtxo_id"].as_str().expect("expected_vtxo_id");
        let expected_id = VtxoId::from_str(expected_str).expect("parse expected VTXO ID");

        assert_eq!(
            computed_id, expected_id,
            "VTXO ID mismatch: expected {} (display), got {}",
            expected_str, computed_id
        );

        match computed_id {
            VtxoId::OutPoint(op) => {
                let txid_display = format!("{}", op.txid);
                let expected_hash = expected_str.split(':').next().expect("Hash:Index");
                assert_eq!(txid_display, expected_hash, "TxID hash mismatch");
                assert_eq!(op.vout, 0, "vout must be 0");
            }
            VtxoId::Raw(_) => panic!("expected OutPoint variant"),
        }
    }

    /// Verification gate: engine must be reactive. Sabotaged anchor (wrong script) must produce IdMismatch.
    #[test]
    fn test_second_tech_v3_link_sabotage_anchor_mismatch() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture_path = manifest_dir.join("tests/fixtures/second_tech_round1_step0.json");
        let contents = std::fs::read_to_string(&fixture_path).expect("read step0 fixture");
        let j: serde_json::Value = serde_json::from_str(&contents).expect("parse fixture JSON");

        let _expected_str = j["expected_vtxo_id"].as_str().expect("expected_vtxo_id");

        let grandparent_hash_str = j["grandparent_hash"].as_str().expect("grandparent_hash");
        let anchor_id = VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
        let anchor = match anchor_id {
            VtxoId::Raw(hash_bytes) => {
                use crate::types::Txid;
                let txid = Txid::from_byte_array(hash_bytes);
                OutPoint { txid, vout: 0 }
            }
            VtxoId::OutPoint(op) => op,
        };

        let child_amount = j["child_amount"].as_u64().expect("child_amount") as u64;
        let child_script = hex::decode(j["child_script"].as_str().expect("child_script"))
            .expect("decode child script");
        let fee_anchor_script =
            hex::decode(j["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee anchor");
        let sibling_value = j["sibling_value"].as_u64().expect("sibling_value") as u64;
        let parent_index = j["parent_index"].as_u64().expect("parent_index") as u32;
        let sibling_scripts: Vec<Vec<u8>> = j["sibling_scripts"]
            .as_array()
            .expect("sibling_scripts array")
            .iter()
            .map(|v| hex::decode(v.as_str().expect("script")).expect("decode sibling script"))
            .collect();

        let mut siblings: Vec<SiblingNode> = sibling_scripts
            .into_iter()
            .map(|script| SiblingNode::Compact {
                hash: [0u8; 32],
                value: sibling_value,
                script,
            })
            .collect();
        // Sabotage: wrong script on the fee anchor (engine must detect SiblingHashMismatch)
        siblings.push(SiblingNode::Compact {
            hash: [0u8; 32],
            value: 0,
            script: vec![0x00],
        });

        let genesis_item = GenesisItem {
            siblings,
            parent_index,
            sequence: 0,
            child_amount,
            child_script_pubkey: child_script,
            signature: None,
        };

        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 0,
                vout: 0,
                sequence: 0,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: Vec::new(),
            },
            leaf_siblings: Vec::new(),
            path: vec![genesis_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = SecondTechV3;
        let result = engine.compute_vtxo_id(&tree);
        assert!(
            matches!(result, Err(VPackError::SiblingHashMismatch)),
            "Sabotage test: wrong fee anchor script must yield SiblingHashMismatch, got {:?}",
            result
        );
    }

    #[test]
    fn test_second_tech_v3_deep_recursion() {
        // Test deep recursion: 5-step path traversal (ROUND_1 scenario).
        // Step 0 data from fixture; intermediate steps use same scripts from fixture.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture_path = manifest_dir.join("tests/fixtures/second_tech_round1_step0.json");
        let contents = std::fs::read_to_string(&fixture_path).expect("read step0 fixture");
        let j: serde_json::Value = serde_json::from_str(&contents).expect("parse fixture JSON");

        let grandparent_hash_str = j["grandparent_hash"].as_str().expect("grandparent_hash");
        let anchor_id = VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
        let anchor = match anchor_id {
            VtxoId::Raw(hash_bytes) => {
                use crate::types::Txid;
                let txid = Txid::from_byte_array(hash_bytes);
                OutPoint { txid, vout: 0 }
            }
            VtxoId::OutPoint(op) => op,
        };

        let fee_anchor_script =
            hex::decode(j["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee anchor");
        let child_script = hex::decode(j["child_script"].as_str().expect("child_script"))
            .expect("decode child script");
        let sibling_value = j["sibling_value"].as_u64().expect("sibling_value") as u64;
        let parent_index = j["parent_index"].as_u64().expect("parent_index") as u32;
        let step0_child_amount = j["child_amount"].as_u64().expect("child_amount") as u64;

        let sibling_scripts: Vec<Vec<u8>> = j["sibling_scripts"]
            .as_array()
            .expect("sibling_scripts")
            .iter()
            .map(|v| hex::decode(v.as_str().expect("script")).expect("decode sibling script"))
            .collect();
        let mut step0_siblings: Vec<SiblingNode> = sibling_scripts
            .into_iter()
            .map(|script| SiblingNode::Compact {
                hash: hash_sibling_birth_tx(sibling_value, &script),
                value: sibling_value,
                script,
            })
            .collect();
        step0_siblings.push(SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        });
        let step0_item = GenesisItem {
            siblings: step0_siblings,
            parent_index,
            sequence: 0,
            child_amount: step0_child_amount,
            child_script_pubkey: child_script.clone(),
            signature: None,
        };

        // Intermediate step script from round_branch vector (single script for steps 1–4)
        let branch_path =
            manifest_dir.join("tests/conformance/vectors/ark_labs/round_branch_v3.json");
        let branch_contents =
            std::fs::read_to_string(&branch_path).expect("read round_branch_v3.json");
        let branch_json: serde_json::Value =
            serde_json::from_str(&branch_contents).expect("parse branch JSON");
        let intermediate_script = hex::decode(
            branch_json["reconstruction_ingredients"]["siblings"][0]["script"]
                .as_str()
                .expect("sibling script"),
        )
        .expect("decode intermediate script");

        let mut path_items = vec![step0_item];
        for i in 1..5 {
            let step_siblings = vec![
                SiblingNode::Compact {
                    hash: hash_sibling_birth_tx(1000, &intermediate_script),
                    value: 1000,
                    script: intermediate_script.clone(),
                },
                SiblingNode::Compact {
                    hash: hash_sibling_birth_tx(0, &fee_anchor_script),
                    value: 0,
                    script: fee_anchor_script.clone(),
                },
            ];
            let step_item = GenesisItem {
                siblings: step_siblings,
                parent_index: 1,
                sequence: 0,
                child_amount: 20000 - (i * 1000),
                child_script_pubkey: child_script.clone(),
                signature: None,
            };
            path_items.push(step_item);
        }

        let leaf_siblings = vec![SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        }];
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 15000,
                vout: 0,
                sequence: 0,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script,
            },
            leaf_siblings,
            path: path_items,
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = SecondTechV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        // Verify it's an OutPoint (Second Tech format)
        match computed_id {
            VtxoId::OutPoint(op) => {
                // Verify the TxID is non-zero (sanity check)
                let txid_bytes = op.txid.to_byte_array();
                assert!(
                    !txid_bytes.iter().all(|&b| b == 0),
                    "TxID should not be all zeros"
                );
                // Verify vout matches leaf.vout
                assert_eq!(op.vout, tree.leaf.vout, "vout should match leaf.vout");
            }
            VtxoId::Raw(_) => panic!("expected OutPoint variant for Second Tech"),
        }

        // Note: The expected final ID for ROUND_1 is c806f5fc2cf7a5b0e8e2fa46cc9e0c7a511f43144f9d27f85a9108e4b8c4d662:0
        // This test verifies the recursive logic works; exact value matching requires
        // the complete ROUND_1 test data with all 5 steps' exact values and scripts.
    }
}
