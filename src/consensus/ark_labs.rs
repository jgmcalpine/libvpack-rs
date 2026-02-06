//! Ark Labs V3-Anchored consensus engine (Variant 0x04).
//!
//! This engine reconstructs VTXO identity by building a Bitcoin V3 transaction
//! with arity-aware outputs (user output + siblings + fee anchor) and computing
//! its Double-SHA256 hash.

use alloc::vec::Vec;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::Txid;

use crate::consensus::{tx_preimage, ConsensusEngine, TxInPreimage, TxOutPreimage, VtxoId};
use crate::error::VPackError;
use crate::payload::tree::{SiblingNode, VPackTree};

/// Ark Labs V3-Anchored consensus engine (Variant 0x04).
///
/// Reconstructs VTXO identity by building a Bitcoin V3 transaction with:
/// - Leaf nodes: 2 outputs (user + fee anchor)
/// - Branch nodes: N+1 outputs (N children + fee anchor)
/// Then computes Double-SHA256 hash to produce `VtxoId::Raw`.
pub struct ArkLabsV3;

impl ConsensusEngine for ArkLabsV3 {
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
        let mut last_txid_bytes = None;

        // Iterate through path (top-down from root to leaf)
        for genesis_item in &tree.path {
            // Build outputs: child (if present) + siblings + fee anchor
            let mut outputs = Vec::new();

            // Add child output only if present (represents the next level down)
            if !genesis_item.child_script_pubkey.is_empty() {
                outputs.push(TxOutPreimage {
                    value: genesis_item.child_amount,
                    script_pubkey: genesis_item.child_script_pubkey.as_slice(),
                });
            }

            // Add sibling outputs
            for sibling in &genesis_item.siblings {
                match sibling {
                    SiblingNode::Compact { value, script, .. } => {
                        outputs.push(TxOutPreimage {
                            value: *value,
                            script_pubkey: script.as_slice(),
                        });
                    }
                    SiblingNode::Full(_) => return Err(VPackError::EncodingError),
                }
            }

            // Add fee anchor (always last)
            outputs.push(TxOutPreimage {
                value: 0,
                script_pubkey: tree.fee_anchor_script.as_slice(),
            });

            // Build input spending current_prevout
            let input = TxInPreimage {
                prev_out_txid: current_prevout.txid.to_byte_array(),
                prev_out_vout: current_prevout.vout,
                sequence: genesis_item.sequence,
            };

            // Hash transaction → Raw Hash
            let txid_bytes = Self::hash_node_bytes(3, &[input], &outputs, 0)?;
            let txid = Txid::from_byte_array(txid_bytes);

            // Store the last transaction's hash
            last_txid_bytes = Some(txid_bytes);

            // Hand-off: Convert to OutPoint for next step (always vout 0 for Ark Labs)
            current_prevout = OutPoint { txid, vout: 0 };
        }

        // Final step: Build leaf transaction spending current_prevout (if leaf is valid)
        // If leaf has empty script_pubkey, return the ID from the last path transaction
        if tree.leaf.script_pubkey.is_empty() {
            // Return the Raw hash from the last transaction
            Ok(VtxoId::Raw(
                last_txid_bytes.expect("path should have at least one item"),
            ))
        } else {
            self.compute_leaf_vtxo_id_with_prevout(tree, current_prevout)
        }
    }
}

impl ArkLabsV3 {
    /// Compute VTXO ID for a leaf node (no path).
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
        // Build outputs list dynamically: [User Output, Fee Anchor]
        let mut outputs = Vec::with_capacity(2);

        // Add user output
        outputs.push(TxOutPreimage {
            value: tree.leaf.amount,
            script_pubkey: tree.leaf.script_pubkey.as_slice(),
        });

        // Append fee anchor (always last)
        outputs.push(TxOutPreimage {
            value: 0,
            script_pubkey: tree.fee_anchor_script.as_slice(),
        });

        // Build input from prevout OutPoint
        let input = TxInPreimage {
            prev_out_txid: prevout.txid.to_byte_array(),
            prev_out_vout: prevout.vout,
            sequence: tree.leaf.sequence,
        };

        // Hash the node: Version 3, Locktime 0
        Self::hash_node(3, &[input], &outputs, 0)
    }

    /// Helper function to hash a transaction node.
    ///
    /// Takes transaction components, builds the preimage, applies Double-SHA256,
    /// and returns `VtxoId::Raw` with bytes in internal (wire) order.
    fn hash_node(
        version: u32,
        inputs: &[TxInPreimage],
        outputs: &[TxOutPreimage<'_>],
        locktime: u32,
    ) -> Result<VtxoId, VPackError> {
        let bytes = Self::hash_node_bytes(version, inputs, outputs, locktime)?;
        Ok(VtxoId::Raw(bytes))
    }

    /// Helper function to hash a transaction node and return raw bytes.
    ///
    /// Takes transaction components, builds the preimage, applies Double-SHA256,
    /// and returns raw bytes in internal (wire) order.
    fn hash_node_bytes(
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
        // Critical: Use to_byte_array() to get the internal representation
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
    use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
    use alloc::format;
    use alloc::vec;
    use core::str::FromStr;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_ark_labs_v3_leaf_verification() {
        // Gold Standard: round_leaf_v3.json from arkd builder.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
        let contents = fs::read_to_string(&path).expect("read round_leaf_v3.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");

        let expected_vtxo_id_str = json["raw_evidence"]["expected_vtxo_id"]
            .as_str()
            .expect("expected_vtxo_id present");
        let expected_vtxo_id =
            VtxoId::from_str(expected_vtxo_id_str).expect("parse expected VTXO ID");

        let ri = &json["reconstruction_ingredients"];
        let anchor_outpoint_str = ri["parent_outpoint"].as_str().expect("parent_outpoint");
        let anchor_id = VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };

        let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
        let fee_anchor_script =
            hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee_anchor_script");
        let outputs = ri["outputs"].as_array().expect("outputs array");
        let user_value = outputs[0]["value"].as_u64().expect("user value");
        let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script"))
            .expect("decode user script");

        let tree = VPackTree {
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

        let engine = ArkLabsV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        assert_eq!(
            computed_id, expected_vtxo_id,
            "VTXO ID mismatch: expected {} (display), got {}",
            expected_vtxo_id_str, computed_id
        );

        // Verification gate: reconstructed preimage must match expected bytes (V3, strict endianness).
        let mut outputs_pre = Vec::with_capacity(2);
        outputs_pre.push(TxOutPreimage {
            value: tree.leaf.amount,
            script_pubkey: tree.leaf.script_pubkey.as_slice(),
        });
        outputs_pre.push(TxOutPreimage {
            value: 0,
            script_pubkey: tree.fee_anchor_script.as_slice(),
        });
        let input = TxInPreimage {
            prev_out_txid: tree.anchor.txid.to_byte_array(),
            prev_out_vout: tree.anchor.vout,
            sequence: tree.leaf.sequence,
        };
        let preimage_bytes = ArkLabsV3::get_preimage_bytes(3, &[input], &outputs_pre, 0);
        let fixture_path = manifest_dir.join("tests/fixtures/ark_labs_round_leaf_preimage_hex.txt");
        let gold_hex = fs::read_to_string(&fixture_path).expect("read gold preimage fixture");
        let gold_hex = gold_hex.trim();
        let gold_bytes = hex::decode(gold_hex).expect("decode gold preimage hex");
        assert_eq!(
            preimage_bytes,
            gold_bytes,
            "Reconstructed preimage must match gold transaction bytes byte-for-byte. RECONSTRUCTED_HEX: {} EXPECTED from fixture: {}",
            hex::encode(&preimage_bytes),
            gold_hex
        );
    }

    #[test]
    fn test_ark_labs_v3_branch_verification() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_branch_v3.json");
        let contents = fs::read_to_string(&path).expect("read round_branch_v3.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");

        let expected_vtxo_id_str = json["raw_evidence"]["expected_vtxo_id"]
            .as_str()
            .expect("expected_vtxo_id present");
        let expected_vtxo_id =
            VtxoId::from_str(expected_vtxo_id_str).expect("parse expected VTXO ID");

        let ri = &json["reconstruction_ingredients"];
        let anchor_outpoint_str = ri["anchor_outpoint"].as_str().expect("anchor_outpoint");
        let anchor_id = VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };
        let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
        let fee_anchor_script =
            hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee_anchor_script");
        let siblings_arr = ri["siblings"].as_array().expect("siblings array");

        let mut siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let hash_str = s["hash"].as_str().expect("sibling hash");
            let id = VtxoId::from_str(hash_str).expect("parse sibling hash");
            let hash_internal = match id {
                VtxoId::Raw(b) => b,
                VtxoId::OutPoint(_) => panic!("expected raw hash for sibling"),
            };
            let value = s["value"].as_u64().expect("sibling value");
            let script = hex::decode(s["script"].as_str().expect("sibling script"))
                .expect("decode sibling script");
            siblings.push(SiblingNode::Compact {
                hash: hash_internal,
                value,
                script,
            });
        }

        let child_output = ri.get("child_output").and_then(|co| co.as_object());
        let (child_amount, child_script_pubkey) = if let Some(co) = child_output {
            let v = co["value"].as_u64().unwrap_or(0);
            let s = co["script"]
                .as_str()
                .map(|h| hex::decode(h).unwrap_or_default())
                .unwrap_or_default();
            (v, s)
        } else {
            (0, Vec::new())
        };

        let path_item = GenesisItem {
            siblings,
            parent_index: 0,
            sequence,
            child_amount,
            child_script_pubkey: child_script_pubkey.clone(),
            signature: None,
        };

        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: child_amount,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script_pubkey,
            },
            path: vec![path_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = ArkLabsV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        assert_eq!(
            computed_id, expected_vtxo_id,
            "Branch VTXO ID mismatch: expected {} (display), got {}",
            expected_vtxo_id_str, computed_id
        );
        assert_eq!(
            format!("{}", computed_id),
            expected_vtxo_id_str,
            "Display (reversed byte order) must match expected string"
        );
    }

    #[test]
    fn test_ark_labs_v3_deep_recursion() {
        // Test deep recursion: 3-level path traversal
        // This test verifies that the top-down chaining logic works correctly
        // for multiple levels by constructing a 3-level tree manually

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_branch_v3.json");
        let contents = fs::read_to_string(&path).expect("read round_branch_v3.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");

        let ri = &json["reconstruction_ingredients"];
        let anchor_outpoint_str = ri["anchor_outpoint"].as_str().expect("anchor_outpoint");
        let anchor_id = VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };
        let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
        let fee_anchor_script =
            hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script"))
                .expect("decode fee_anchor_script");
        let siblings_arr = ri["siblings"].as_array().expect("siblings array");

        // Build first level siblings
        let mut level1_siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let hash_str = s["hash"].as_str().expect("sibling hash");
            let id = VtxoId::from_str(hash_str).expect("parse sibling hash");
            let hash_internal = match id {
                VtxoId::Raw(b) => b,
                VtxoId::OutPoint(_) => panic!("expected raw hash for sibling"),
            };
            let value = s["value"].as_u64().expect("sibling value");
            let script = hex::decode(s["script"].as_str().expect("sibling script"))
                .expect("decode sibling script");
            level1_siblings.push(SiblingNode::Compact {
                hash: hash_internal,
                value,
                script,
            });
        }

        // Child/leaf script from round_leaf_v3 (same as user output script)
        let leaf_path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
        let leaf_contents = fs::read_to_string(&leaf_path).expect("read round_leaf_v3.json");
        let leaf_json: serde_json::Value =
            serde_json::from_str(&leaf_contents).expect("parse round_leaf JSON");
        let child_script_hex = leaf_json["reconstruction_ingredients"]["outputs"][0]["script"]
            .as_str()
            .expect("user script in round_leaf");
        let child_script = hex::decode(child_script_hex).expect("decode child script");
        let sibling_script_hex = ri["siblings"][0]["script"]
            .as_str()
            .expect("sibling script");
        let sibling_script = hex::decode(sibling_script_hex).expect("decode sibling script");

        // Level 1: Branch node (from round_branch_v3.json)
        let level1_item = GenesisItem {
            siblings: level1_siblings,
            parent_index: 0,
            sequence,
            child_amount: 1100, // Child amount for next level
            child_script_pubkey: child_script.clone(),
            signature: None,
        };

        // Level 2: Intermediate node (simplified - using same structure)
        let level2_siblings = vec![SiblingNode::Compact {
            hash: [0u8; 32],
            value: 500,
            script: sibling_script.clone(),
        }];
        let level2_item = GenesisItem {
            siblings: level2_siblings,
            parent_index: 0,
            sequence,
            child_amount: 600, // Child amount for leaf
            child_script_pubkey: child_script.clone(),
            signature: None,
        };

        // Level 3: Leaf node
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 600,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script,
            },
            path: vec![level1_item, level2_item], // 2 levels in path + 1 leaf = 3 levels total
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = ArkLabsV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        // Verify it's a Raw hash (Ark Labs format)
        match computed_id {
            VtxoId::Raw(_) => {
                // Success - recursive logic worked
            }
            VtxoId::OutPoint(_) => panic!("expected Raw hash for Ark Labs"),
        }

        // Verify the ID is non-zero (sanity check)
        match computed_id {
            VtxoId::Raw(bytes) => {
                assert!(
                    !bytes.iter().all(|&b| b == 0),
                    "VTXO ID should not be all zeros"
                );
            }
            _ => {}
        }
    }
}
