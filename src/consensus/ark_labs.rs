//! Ark Labs V3-Anchored consensus engine (Variant 0x04).
//!
//! This engine reconstructs VTXO identity by building a Bitcoin V3 transaction
//! with arity-aware outputs (user output + siblings + fee anchor) and computing
//! its Double-SHA256 hash.

use alloc::vec::Vec;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;

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

        // Check if this is a leaf node (empty path) or branch node
        if tree.path.is_empty() {
            self.compute_leaf_vtxo_id(tree)
        } else {
            self.compute_branch_vtxo_id(tree)
        }
    }
}

impl ArkLabsV3 {
    /// Compute VTXO ID for a leaf node (no path).
    fn compute_leaf_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError> {
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

        // Build input from anchor OutPoint
        let input = TxInPreimage {
            prev_out_txid: tree.anchor.txid.to_byte_array(),
            prev_out_vout: tree.anchor.vout,
            sequence: tree.leaf.sequence,
        };

        // Hash the node: Version 3, Locktime 0
        Self::hash_node(3, &[input], &outputs, 0)
    }

    /// Compute VTXO ID for a branch node (path non-empty).
    /// Outputs: N child outputs (sibling script each) + fee anchor.
    fn compute_branch_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError> {
        let first = tree.path.first().ok_or(VPackError::EncodingError)?;
        let mut child_outputs: Vec<(u64, Vec<u8>)> = Vec::new();
        for sibling in &first.siblings {
            match sibling {
                SiblingNode::Compact { value, script, .. } => {
                    child_outputs.push((*value, script.clone()));
                }
                SiblingNode::Full(_) => return Err(VPackError::EncodingError),
            }
        }
        let mut outputs: Vec<TxOutPreimage<'_>> = Vec::with_capacity(child_outputs.len() + 1);
        for (value, script) in &child_outputs {
            outputs.push(TxOutPreimage {
                value: *value,
                script_pubkey: script.as_slice(),
            });
        }
        outputs.push(TxOutPreimage {
            value: 0,
            script_pubkey: tree.fee_anchor_script.as_slice(),
        });
        let sequence = first.sequence;
        let input = TxInPreimage {
            prev_out_txid: tree.anchor.txid.to_byte_array(),
            prev_out_vout: tree.anchor.vout,
            sequence,
        };
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
        // Build transaction preimage
        let preimage_bytes = tx_preimage(version, inputs, outputs, locktime);

        // Apply Double-SHA256
        let hash = sha256d::Hash::hash(&preimage_bytes);

        // Extract raw bytes in internal (wire) order
        // Critical: Use to_byte_array() to get the internal representation
        let bytes = hash.to_byte_array();

        Ok(VtxoId::Raw(bytes))
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
        let expected_vtxo_id = VtxoId::from_str(expected_vtxo_id_str).expect("parse expected VTXO ID");

        let ri = &json["reconstruction_ingredients"];
        let anchor_outpoint_str = ri["parent_outpoint"].as_str().expect("parent_outpoint");
        let anchor_id = VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };

        let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
        let fee_anchor_script = hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script")).expect("decode fee_anchor_script");
        let outputs = ri["outputs"].as_array().expect("outputs array");
        let user_value = outputs[0]["value"].as_u64().expect("user value");
        let user_script = hex::decode(outputs[0]["script"].as_str().expect("user script")).expect("decode user script");

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
            computed_id,
            expected_vtxo_id,
            "VTXO ID mismatch: expected {} (display), got {}",
            expected_vtxo_id_str,
            computed_id
        );

        // Verification gate: reconstructed preimage must match expected bytes (V3, strict endianness).
        let mut outputs_pre = Vec::with_capacity(2);
        outputs_pre.push(TxOutPreimage { value: tree.leaf.amount, script_pubkey: tree.leaf.script_pubkey.as_slice() });
        outputs_pre.push(TxOutPreimage { value: 0, script_pubkey: tree.fee_anchor_script.as_slice() });
        let input = TxInPreimage {
            prev_out_txid: tree.anchor.txid.to_byte_array(),
            prev_out_vout: tree.anchor.vout,
            sequence: tree.leaf.sequence,
        };
        let preimage_bytes = ArkLabsV3::get_preimage_bytes(3, &[input], &outputs_pre, 0);
        const GOLD_PREIMAGE_HEX: &str = "0300000001a4e3e646f30f8965a797d105751b4e9d11e8da56fd7711d9d707a7a56ab0deec0000000000ffffffff024c0400000000000022512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea996700000000000000000451024e7300000000";
        let gold_bytes = hex::decode(GOLD_PREIMAGE_HEX).expect("gold preimage hex");
        assert_eq!(
            preimage_bytes,
            gold_bytes,
            "Reconstructed preimage must match gold transaction bytes byte-for-byte. RECONSTRUCTED_HEX: {} EXPECTED_HEX: {}",
            hex::encode(&preimage_bytes),
            GOLD_PREIMAGE_HEX
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
        let expected_vtxo_id = VtxoId::from_str(expected_vtxo_id_str).expect("parse expected VTXO ID");

        let ri = &json["reconstruction_ingredients"];
        let anchor_outpoint_str = ri["anchor_outpoint"].as_str().expect("anchor_outpoint");
        let anchor_id = VtxoId::from_str(anchor_outpoint_str).expect("parse anchor OutPoint");
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };
        let sequence = ri["nSequence"].as_u64().expect("nSequence") as u32;
        let fee_anchor_script = hex::decode(ri["fee_anchor_script"].as_str().expect("fee_anchor_script")).expect("decode fee_anchor_script");
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
            let script = hex::decode(s["script"].as_str().expect("sibling script")).expect("decode sibling script");
            siblings.push(SiblingNode::Compact {
                hash: hash_internal,
                value,
                script,
            });
        }

        let path_item = GenesisItem {
            siblings,
            parent_index: 0,
            sequence,
            child_amount: 0,
            child_script_pubkey: Vec::new(),
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
            path: vec![path_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
        };

        let engine = ArkLabsV3;
        let computed_id = engine.compute_vtxo_id(&tree).expect("compute VTXO ID");

        assert_eq!(
            computed_id,
            expected_vtxo_id,
            "Branch VTXO ID mismatch: expected {} (display), got {}",
            expected_vtxo_id_str,
            computed_id
        );
        assert_eq!(
            format!("{}", computed_id),
            expected_vtxo_id_str,
            "Display (reversed byte order) must match expected string"
        );
    }
}
