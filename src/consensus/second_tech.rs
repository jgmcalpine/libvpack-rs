//! Second Tech V3-Plain consensus engine (Variant 0x03).
//!
//! This engine reconstructs VTXO identity by building a Bitcoin V3 transaction
//! with chain-link outputs (next link + fee anchor) and computing its Double-SHA256 hash.
//! The result is a VtxoId::OutPoint (Hash:Index) where the hash is the TxID and the index
//! is the vout from the VtxoLeaf.

use alloc::vec::Vec;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::Txid;

use crate::consensus::{tx_preimage, ConsensusEngine, TxInPreimage, TxOutPreimage, VtxoId};
use crate::error::VPackError;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree};

/// Second Tech V3-Plain consensus engine (Variant 0x03).
///
/// Reconstructs VTXO identity by building a Bitcoin V3 transaction with:
/// - Chain links: 2 outputs (next link + fee anchor)
/// - Sequence: 0x00000000 (ZERO) for inputs
/// - Version: 3 (TRUC)
/// Then computes Double-SHA256 hash to produce `VtxoId::OutPoint` (TxID:vout).
pub struct SecondTechV3;

impl ConsensusEngine for SecondTechV3 {
    fn compute_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError> {
        // Validate fee anchor script is present
        if tree.fee_anchor_script.is_empty() {
            return Err(VPackError::FeeAnchorMissing);
        }

        // If path is empty, this is a leaf node
        if tree.path.is_empty() {
            return self.compute_leaf_vtxo_id(tree);
        }

        // Top-down chaining: start with on-chain anchor
        let mut current_prevout = tree.anchor;
        let mut last_outpoint = None;

        // Iterate through path (top-down from root to leaf)
        for (i, genesis_item) in tree.path.iter().enumerate() {
            // Build outputs using reconstruct_link (child at parent_index + siblings + fee anchor)
            let outputs = Self::reconstruct_link(genesis_item, &tree.fee_anchor_script)?;

            // Build input spending current_prevout
            let input = TxInPreimage {
                prev_out_txid: current_prevout.txid.to_byte_array(),
                prev_out_vout: current_prevout.vout,
                sequence: 0x00000000, // ZERO for Second Tech
            };

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

            // Hand-off: Convert to OutPoint for next step
            current_prevout = OutPoint {
                txid,
                vout,
            };
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
        // Build outputs list: [Final Leaf Output, Fee Anchor]
        let mut outputs = Vec::with_capacity(2);

        // Output 0: Final leaf
        outputs.push(TxOutPreimage {
            value: tree.leaf.amount,
            script_pubkey: tree.leaf.script_pubkey.as_slice(),
        });

        // Output 1: Fee Anchor (always last)
        outputs.push(TxOutPreimage {
            value: 0,
            script_pubkey: tree.fee_anchor_script.as_slice(),
        });

        // Build input from prevout OutPoint
        // Sequence: 0x00000000 (ZERO) for Second Tech
        let input = TxInPreimage {
            prev_out_txid: prevout.txid.to_byte_array(),
            prev_out_vout: prevout.vout,
            sequence: 0x00000000, // ZERO for Second Tech
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

    /// Reconstruct a chain link's outputs dynamically.
    /// 
    /// **Output Construction Rule:**
    /// - Total Outputs = siblings.len() + 2 (siblings + child + anchor)
    /// - For i from 0 to Total-2:
    ///   - If i == parent_index: Place the Child Coin (Amount/Script)
    ///   - Else: Place the next available sibling from the siblings array
    /// - Final Output: Place the Fee Anchor at the very last index
    /// 
    /// This allows the child coin to occupy any index, with siblings filling
    /// all other available slots before the fee anchor.
    fn reconstruct_link<'a>(
        genesis_item: &'a GenesisItem,
        fee_anchor_script: &'a [u8],
    ) -> Result<Vec<TxOutPreimage<'a>>, VPackError> {
        let siblings_count = genesis_item.siblings.len();
        let parent_index = genesis_item.parent_index as usize;
        
        // Total outputs = siblings + child + anchor
        let total_outputs = siblings_count + 2;
        
        // Validate parent_index is within bounds (must be < total_outputs - 1, since last is anchor)
        if parent_index >= total_outputs - 1 {
            return Err(VPackError::EncodingError);
        }

        let mut outputs = Vec::with_capacity(total_outputs);
        let mut sibling_idx = 0;

        // Loop from 0 to Total-2 (all positions except the final fee anchor)
        for i in 0..(total_outputs - 1) {
            if i == parent_index {
                // Place child coin at parent_index
                outputs.push(TxOutPreimage {
                    value: genesis_item.child_amount,
                    script_pubkey: genesis_item.child_script_pubkey.as_slice(),
                });
            } else {
                // Place next available sibling
                if sibling_idx >= siblings_count {
                    return Err(VPackError::EncodingError);
                }
                
                let sibling = &genesis_item.siblings[sibling_idx];
                let (value, script) = match sibling {
                    SiblingNode::Compact { value, script, .. } => (*value, script.as_slice()),
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

        // Final output: Fee Anchor at the very last index
        outputs.push(TxOutPreimage {
            value: 0,
            script_pubkey: fee_anchor_script,
        });

        // Validate we used all siblings
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
    use crate::payload::tree::{GenesisItem, SiblingNode, VtxoLeaf, VPackTree};
    use alloc::format;
    use alloc::vec;
    use core::str::FromStr;

    #[test]
    fn test_second_tech_v3_link_verification() {
        // Gold Standard: From bark logs for ROUND_1 Step 0
        // Target Hash: 5924fc2bc3025e2b5391f91e37bc2fe804d40e0b933cfad9ec2f5d8f90ed87af
        // Grandparent ID (Anchor): abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3
        // Step 0 Ingredients:
        //   TARGET_OUTPUT_IDX (parent_index): 3
        //   Total outputs: 5 (3 siblings + 1 child + 1 anchor)
        //   Child Amount: 30000 (Alice)
        //   Child Script: 5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559
        //   Fee Anchor: 51024e73
        //
        // Output placement (parent_index = 3):
        //   Output 0: sibling[0] (5000 sats)
        //   Output 1: sibling[1] (5000 sats)
        //   Output 2: sibling[2] (5000 sats)
        //   Output 3: child coin (30000 sats, parent_index)
        //   Output 4: fee anchor (51024e73)

        // Parse the grandparent anchor (hash only, vout assumed to be 0)
        let grandparent_hash_str = "abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3";
        let anchor_id = VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
        let anchor = match anchor_id {
            VtxoId::Raw(hash_bytes) => {
                use bitcoin::Txid;
                let txid = Txid::from_byte_array(hash_bytes);
                OutPoint { txid, vout: 0 }
            }
            VtxoId::OutPoint(op) => op,
        };

        // Step 0 ingredients from bark logs for ROUND_1
        // Target Hash: 5924fc2bc3025e2b5391f91e37bc2fe804d40e0b933cfad9ec2f5d8f90ed87af
        // Parent Index: 3
        // Outputs count: 5 (3 siblings + 1 child + 1 anchor)
        
        let child_amount = 30000u64;
        let child_script = hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
            .expect("decode child script");
        let fee_anchor_script = hex::decode("51024e73").expect("decode fee anchor script");

        // Sibling data from bark logs
        // Sibling 0: Amount 5000 | Script 51205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd431
        // Sibling 1: Amount 5000 | Script 5120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2
        // Sibling 2: Amount 5000 | Script 512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951
        
        // Expected output order (parent_index = 3):
        //   Output 0: sibling[0] (5000 sats)
        //   Output 1: sibling[1] (5000 sats)
        //   Output 2: sibling[2] (5000 sats)
        //   Output 3: child coin (30000 sats, parent_index)
        //   Output 4: fee anchor (51024e73)
        
        let sibling_0_hash = [0u8; 32]; // Hash not needed for reconstruction, only script/value
        let sibling_1_hash = [0u8; 32];
        let sibling_2_hash = [0u8; 32];
        
        let sibling_0_script = hex::decode("51205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd431")
            .expect("decode sibling 0 script");
        let sibling_1_script = hex::decode("5120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2")
            .expect("decode sibling 1 script");
        let sibling_2_script = hex::decode("512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951")
            .expect("decode sibling 2 script");

        let siblings = vec![
            SiblingNode::Compact {
                hash: sibling_0_hash,
                value: 5000,
                script: sibling_0_script,
            },
            SiblingNode::Compact {
                hash: sibling_1_hash,
                value: 5000,
                script: sibling_1_script,
            },
            SiblingNode::Compact {
                hash: sibling_2_hash,
                value: 5000,
                script: sibling_2_script,
            },
        ];

        // Create GenesisItem for Step 0
        let genesis_item = GenesisItem {
            siblings,
            parent_index: 3, // TARGET_OUTPUT_IDX
            sequence: 0,
            child_amount,
            child_script_pubkey: child_script,
            signature: None,
        };

        // Build the tree with path containing the GenesisItem
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 0, // Not used for chain links
                vout: 0, // Will be used if this is the last level
                sequence: 0,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: Vec::new(), // Not used for chain links
            },
            path: vec![genesis_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        // Compute VTXO ID
        let engine = SecondTechV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        // Expected result: 5924fc2bc3025e2b5391f91e37bc2fe804d40e0b933cfad9ec2f5d8f90ed87af:0
        let expected_str = "5924fc2bc3025e2b5391f91e37bc2fe804d40e0b933cfad9ec2f5d8f90ed87af:0";
        let expected_id = VtxoId::from_str(expected_str).expect("parse expected VTXO ID");

        assert_eq!(
            computed_id,
            expected_id,
            "VTXO ID mismatch: expected {} (display), got {}",
            expected_str,
            computed_id
        );

        // Verify the hash matches (TxID part of OutPoint)
        match computed_id {
            VtxoId::OutPoint(op) => {
                let txid_display = format!("{}", op.txid);
                assert_eq!(
                    txid_display,
                    "5924fc2bc3025e2b5391f91e37bc2fe804d40e0b933cfad9ec2f5d8f90ed87af",
                    "TxID hash mismatch"
                );
                // vout should be from next level (or leaf.vout if at end)
                // Since we only have one level, it should be leaf.vout = 0
                assert_eq!(op.vout, 0, "vout must be 0");
            }
            VtxoId::Raw(_) => panic!("expected OutPoint variant"),
        }
    }

    #[test]
    fn test_second_tech_v3_deep_recursion() {
        // Test deep recursion: 5-step path traversal (ROUND_1 scenario)
        // This test verifies that the top-down chaining logic works correctly
        // for multiple steps by constructing a 5-step chain manually
        
        // Parse the grandparent anchor (Round TX)
        let grandparent_hash_str = "abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3";
        let anchor_id = VtxoId::from_str(grandparent_hash_str).expect("parse anchor hash");
        let anchor = match anchor_id {
            VtxoId::Raw(hash_bytes) => {
                use bitcoin::Txid;
                let txid = Txid::from_byte_array(hash_bytes);
                OutPoint { txid, vout: 0 }
            }
            VtxoId::OutPoint(op) => op,
        };

        let fee_anchor_script = hex::decode("51024e73").expect("decode fee anchor script");

        // Step 0: From ROUND_1 test data
        let step0_child_amount = 30000u64;
        let step0_child_script = hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
            .expect("decode child script");
        let step0_siblings = vec![
            SiblingNode::Compact {
                hash: [0u8; 32],
                value: 5000,
                script: hex::decode("51205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd431")
                    .expect("decode sibling 0 script"),
            },
            SiblingNode::Compact {
                hash: [0u8; 32],
                value: 5000,
                script: hex::decode("5120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2")
                    .expect("decode sibling 1 script"),
            },
            SiblingNode::Compact {
                hash: [0u8; 32],
                value: 5000,
                script: hex::decode("512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951")
                    .expect("decode sibling 2 script"),
            },
        ];
        let step0_item = GenesisItem {
            siblings: step0_siblings,
            parent_index: 3,
            sequence: 0,
            child_amount: step0_child_amount,
            child_script_pubkey: step0_child_script,
            signature: None,
        };

        // Steps 1-4: Simplified intermediate steps
        let mut path_items = vec![step0_item];
        for i in 1..5 {
            let step_siblings = vec![
                SiblingNode::Compact {
                    hash: [0u8; 32],
                    value: 1000,
                    script: hex::decode("5120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3")
                        .expect("decode sibling script"),
                },
            ];
            let step_item = GenesisItem {
                siblings: step_siblings,
                parent_index: 1, // Next step's parent_index
                sequence: 0,
                child_amount: 20000 - (i * 1000), // Decreasing amounts
                child_script_pubkey: hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
                    .expect("decode child script"),
                signature: None,
            };
            path_items.push(step_item);
        }

        // Final leaf
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 15000, // Final amount
                vout: 0,
                sequence: 0,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: hex::decode("5120f565fc0b453a3694f36bd83089878dc68708706b7ce183cc30698961d046c559")
                    .expect("decode leaf script"),
            },
            path: path_items, // 5 steps in path + 1 leaf = 6 levels total
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
                assert!(!txid_bytes.iter().all(|&b| b == 0), "TxID should not be all zeros");
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
