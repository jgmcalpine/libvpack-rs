//! Ark Labs V3-Anchored consensus engine (Variant 0x04).
//!
//! This engine reconstructs VTXO identity by building a Bitcoin V3 transaction
//! with arity-aware outputs (user output + siblings + fee anchor) and computing
//! its Double-SHA256 hash.

use alloc::vec;
use alloc::vec::Vec;

use crate::types::{hashes::sha256d, hashes::Hash, OutPoint, Txid};

use crate::consensus::taproot::{compute_balanced_merkle_root, tap_leaf_hash};
use crate::consensus::{
    tx_preimage, tx_signed_hex, ConsensusEngine, TxInPreimage, TxOutPreimage, VerificationOutput,
    VtxoId,
};
use crate::error::VPackError;
use crate::payload::tree::{SiblingNode, VPackTree};

#[cfg(feature = "schnorr-verify")]
use crate::consensus::taproot_sighash::{
    extract_verify_key, taproot_sighash, verify_schnorr_bip340,
};

struct ReconstructedOutput {
    value: u64,
    script_pubkey: Vec<u8>,
}

/// Ark Labs V3-Anchored consensus engine (Variant 0x04).
///
/// Reconstructs VTXO identity by building a Bitcoin V3 transaction with:
/// - Leaf nodes: 2 outputs (user + fee anchor)
/// - Branch nodes: N+1 outputs (N children + fee anchor)
///   Then computes Double-SHA256 hash to produce `VtxoId::Raw`.
pub struct ArkLabsV3;

impl ConsensusEngine for ArkLabsV3 {
    fn compute_vtxo_id(
        &self,
        tree: &VPackTree,
        anchor_value: Option<u64>,
    ) -> Result<VerificationOutput, VPackError> {
        // If path is empty, this is a leaf node
        if tree.path.is_empty() {
            // Optional validation: V3-Anchored leaf must have anchor in data (leaf_siblings)
            if tree.leaf_siblings.is_empty() && !tree.fee_anchor_script.is_empty() {
                return Err(VPackError::FeeAnchorMissing);
            }
            return self.compute_leaf_vtxo_id(tree, anchor_value);
        }

        // Top-down chaining: start with on-chain anchor
        let mut current_prevout = tree.anchor;
        let mut last_txid_bytes = None;
        let mut prev_outputs: Option<Vec<ReconstructedOutput>> = None;
        let mut input_amount: Option<u64> = anchor_value;
        let mut signed_txs = Vec::with_capacity(tree.path.len() + 1);

        // Iterate through path (top-down from root to leaf). Outputs = child (if present) + siblings only.
        for (i, genesis_item) in tree.path.iter().enumerate() {
            let mut outputs = Vec::new();

            // Add child output only if present (represents the next level down)
            if !genesis_item.child_script_pubkey.is_empty() {
                outputs.push(TxOutPreimage {
                    value: genesis_item.child_amount,
                    script_pubkey: genesis_item.child_script_pubkey.as_slice(),
                });
            }

            // Add sibling outputs (fee anchor must be in siblings when required; adapter provides it).
            // Only script and value are used; sibling hash is not cross-verified (chain-of-spends).
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

            if let Some(expected) = input_amount {
                let sum = outputs
                    .iter()
                    .try_fold(0u64, |acc, o| acc.checked_add(o.value));
                match sum {
                    None => {
                        return Err(crate::consensus::value_mismatch_for_output_sum(
                            expected, &outputs,
                        ));
                    }
                    Some(s) if s != expected => {
                        return Err(VPackError::ValueMismatch {
                            expected,
                            actual: s,
                        });
                    }
                    Some(_) => {}
                }
                input_amount = outputs.first().map(|o| o.value);
            }

            // Build input spending current_prevout
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
                    let prev = prev_outputs.as_ref().ok_or(VPackError::EncodingError)?;
                    let idx = current_prevout.vout as usize;
                    if idx >= prev.len() {
                        return Err(VPackError::InvalidVout(current_prevout.vout));
                    }
                    let parent_amount = prev[idx].value;
                    let parent_script = prev[idx].script_pubkey.as_slice();
                    let sighash =
                        taproot_sighash(3, 0, &input, parent_amount, parent_script, &outputs, 0x00);
                    verify_schnorr_bip340(&verify_key, &sighash, &sig)?;
                }
            }

            let sig = [genesis_item.signature];
            let signed_hex = tx_signed_hex(3, core::slice::from_ref(&input), &outputs, &sig, 0);
            signed_txs.push(signed_hex);

            // Hash transaction → Raw Hash
            let txid_bytes = Self::hash_node_bytes(3, &[input], &outputs, 0)?;
            let txid = Txid::from_byte_array(txid_bytes);

            // Store the last transaction's hash
            last_txid_bytes = Some(txid_bytes);

            prev_outputs = Some(
                outputs
                    .iter()
                    .map(|o| ReconstructedOutput {
                        value: o.value,
                        script_pubkey: o.script_pubkey.to_vec(),
                    })
                    .collect(),
            );

            // Hand-off: Convert to OutPoint for next step (always vout 0 for Ark Labs)
            current_prevout = OutPoint { txid, vout: 0 };
        }

        // Final step: Build leaf transaction spending current_prevout (if leaf is valid)
        // If leaf has empty script_pubkey, return the ID from the last path transaction
        if tree.leaf.script_pubkey.is_empty() {
            // Return the Raw hash from the last transaction (no leaf tx in signed_txs)
            Ok(VerificationOutput {
                id: VtxoId::Raw(last_txid_bytes.expect("path should have at least one item")),
                signed_txs,
            })
        } else {
            let (id, leaf_signed_hex) =
                self.compute_leaf_vtxo_id_with_prevout(tree, current_prevout, input_amount)?;
            signed_txs.push(leaf_signed_hex);
            Ok(VerificationOutput { id, signed_txs })
        }
    }
}

impl ArkLabsV3 {
    /// Compute VTXO ID for a leaf node (no path).
    fn compute_leaf_vtxo_id(
        &self,
        tree: &VPackTree,
        anchor_value: Option<u64>,
    ) -> Result<VerificationOutput, VPackError> {
        let (id, signed_hex) =
            self.compute_leaf_vtxo_id_with_prevout(tree, tree.anchor, anchor_value)?;
        Ok(VerificationOutput {
            id,
            signed_txs: vec![signed_hex],
        })
    }

    /// Compute VTXO ID for a leaf node with a custom prevout.
    /// Used for the final leaf transaction in recursive path traversal.
    /// Returns (VtxoId, signed_tx_bytes). Leaf output is placed at index leaf.vout per V-PACK data.
    fn compute_leaf_vtxo_id_with_prevout(
        &self,
        tree: &VPackTree,
        prevout: OutPoint,
        input_amount: Option<u64>,
    ) -> Result<(VtxoId, Vec<u8>), VPackError> {
        let num_outputs = 1 + tree.leaf_siblings.len();
        if tree.leaf.vout >= num_outputs as u32 {
            return Err(VPackError::InvalidVout(tree.leaf.vout));
        }
        // Build outputs: leaf at index leaf.vout, siblings at other indices (matches reconstruct_link logic)
        let mut outputs = Vec::with_capacity(num_outputs);
        let mut sibling_iter = tree.leaf_siblings.iter();
        for i in 0..num_outputs {
            if i == tree.leaf.vout as usize {
                outputs.push(TxOutPreimage {
                    value: tree.leaf.amount,
                    script_pubkey: tree.leaf.script_pubkey.as_slice(),
                });
            } else {
                let sibling = sibling_iter.next().ok_or(VPackError::EncodingError)?;
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
        }
        if sibling_iter.next().is_some() {
            return Err(VPackError::EncodingError);
        }

        if let Some(expected) = input_amount {
            let sum = outputs
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.value));
            match sum {
                None => {
                    return Err(crate::consensus::value_mismatch_for_output_sum(
                        expected, &outputs,
                    ));
                }
                Some(s) if s != expected => {
                    return Err(VPackError::ValueMismatch {
                        expected,
                        actual: s,
                    });
                }
                Some(_) => {}
            }
        }

        // Build input from prevout OutPoint
        let input = TxInPreimage {
            prev_out_txid: prevout.txid.to_byte_array(),
            prev_out_vout: prevout.vout,
            sequence: tree.leaf.sequence,
        };

        // Signed hex: leaf has no signature in schema, use empty witness
        let signed_hex = tx_signed_hex(3, core::slice::from_ref(&input), &outputs, &[None], 0);

        // Hash the node: Version 3, Locktime 0 (TxID from unsigned preimage)
        let id = Self::hash_node(3, &[input], &outputs, 0)?;
        Ok((id, signed_hex))
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

// ---------------------------------------------------------------------------
// Ark Labs Taproot Tree Builder (Path Exclusivity)
// ---------------------------------------------------------------------------

const OP_1: u8 = 0x51;
const OP_VERIFY: u8 = 0x69;
const OP_PUSH32: u8 = 0x20;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKSIG: u8 = 0xac;
const OP_CSV: u8 = 0xb2;
const OP_DROP: u8 = 0x75;

/// The shared suffix of both Ark Labs tapscript templates:
/// `OP_PUSH32 <asp_pk> OP_CHECKSIGVERIFY OP_PUSH32 <user_pk> OP_CHECKSIG` (66 bytes).
const PUBKEY_TAIL_LEN: usize = 1 + 32 + 1 + 1 + 32 + 1; // 68

/// Parses an Ark Labs tapscript to extract the ASP x-only pubkey and user x-only pubkey.
///
/// Accepts both the **forfeit** template (no CSV prefix, 70 bytes min) and the
/// **exit/closure** template (with CSV prefix, 76+ bytes).
///
/// Returns `(asp_pubkey, user_pubkey)` or `None` if the script doesn't match
/// a recognised Ark Labs template.
pub fn parse_ark_labs_pubkeys(script: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if script.len() < 4 || script[0] != OP_1 || script[1] != OP_VERIFY {
        return None;
    }

    let tail_start = if script[2] == OP_PUSH32 {
        // Forfeit template: OP_1 OP_VERIFY OP_PUSH32 <asp> ...
        2
    } else {
        // Exit template: OP_1 OP_VERIFY <push N> <N bytes CSV> OP_CSV OP_DROP OP_PUSH32 <asp> ...
        let csv_push_len = script[2] as usize;
        let expected_csv_end = 3 + csv_push_len;
        if script.len() <= expected_csv_end + 2 {
            return None;
        }
        if script[expected_csv_end] != OP_CSV || script[expected_csv_end + 1] != OP_DROP {
            return None;
        }
        expected_csv_end + 2
    };

    // Remaining bytes must be: OP_PUSH32 <asp 32> OP_CHECKSIGVERIFY OP_PUSH32 <user 32> OP_CHECKSIG
    if script.len() < tail_start + PUBKEY_TAIL_LEN {
        return None;
    }
    if script[tail_start] != OP_PUSH32
        || script[tail_start + 33] != OP_CHECKSIGVERIFY
        || script[tail_start + 34] != OP_PUSH32
        || script[tail_start + 67] != OP_CHECKSIG
    {
        return None;
    }

    let mut asp_pk = [0u8; 32];
    let mut user_pk = [0u8; 32];
    asp_pk.copy_from_slice(&script[tail_start + 1..tail_start + 33]);
    user_pk.copy_from_slice(&script[tail_start + 35..tail_start + 67]);
    Some((asp_pk, user_pk))
}

/// Compiles the Ark Labs **forfeit** (condition) tapscript:
/// `OP_1 OP_VERIFY OP_PUSH32 <asp_pk> OP_CHECKSIGVERIFY OP_PUSH32 <user_pk> OP_CHECKSIG`
pub fn compile_forfeit_script(asp_pk: &[u8; 32], user_pk: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(70);
    script.push(OP_1);
    script.push(OP_VERIFY);
    script.push(OP_PUSH32);
    script.extend_from_slice(asp_pk);
    script.push(OP_CHECKSIGVERIFY);
    script.push(OP_PUSH32);
    script.extend_from_slice(user_pk);
    script.push(OP_CHECKSIG);
    script
}

/// Compiles the Ark Labs **exit/closure** tapscript with a CSV relative-timelock prefix:
/// `OP_1 OP_VERIFY <push csv_bytes> OP_CSV OP_DROP OP_PUSH32 <asp_pk> OP_CHECKSIGVERIFY
///  OP_PUSH32 <user_pk> OP_CHECKSIG`
///
/// `csv_bytes` is the raw minimal-encoded Script number for OP_CHECKSEQUENCEVERIFY.
pub fn compile_exit_script(asp_pk: &[u8; 32], user_pk: &[u8; 32], csv_bytes: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(70 + csv_bytes.len() + 3);
    script.push(OP_1);
    script.push(OP_VERIFY);
    script.push(csv_bytes.len() as u8);
    script.extend_from_slice(csv_bytes);
    script.push(OP_CSV);
    script.push(OP_DROP);
    script.push(OP_PUSH32);
    script.extend_from_slice(asp_pk);
    script.push(OP_CHECKSIGVERIFY);
    script.push(OP_PUSH32);
    script.extend_from_slice(user_pk);
    script.push(OP_CHECKSIG);
    script
}

/// Detects whether `asp_expiry_script` is the forfeit template (returns `true`)
/// or the exit/CSV template (returns `false`). Returns `None` if unrecognised.
fn is_forfeit_template(script: &[u8]) -> Option<bool> {
    if script.len() < 4 || script[0] != OP_1 || script[1] != OP_VERIFY {
        return None;
    }
    Some(script[2] == OP_PUSH32)
}

/// Computes the Taproot Merkle root for an Ark Labs VTXO from its `VPackTree`.
///
/// The `asp_expiry_script` field must contain a complete Ark Labs tapscript
/// (either the forfeit or exit template). The function auto-detects the template,
/// extracts the embedded pubkeys, compiles the companion script, and builds a
/// balanced Merkle tree from the resulting TapLeaf hashes.
///
/// Returns `None` if `asp_expiry_script` is empty or doesn't match a recognised
/// Ark Labs template.
pub fn compute_ark_labs_merkle_root(tree: &VPackTree) -> Option<[u8; 32]> {
    if tree.asp_expiry_script.is_empty() {
        return None;
    }

    let (asp_pk, user_pk) = parse_ark_labs_pubkeys(&tree.asp_expiry_script)?;
    let forfeit_template = is_forfeit_template(&tree.asp_expiry_script)?;

    let (forfeit_script, exit_script) = if forfeit_template {
        let csv_bytes = encode_exit_delta_csv(tree.leaf.exit_delta);
        let exit = compile_exit_script(&asp_pk, &user_pk, &csv_bytes);
        (tree.asp_expiry_script.clone(), exit)
    } else {
        let forfeit = compile_forfeit_script(&asp_pk, &user_pk);
        (forfeit, tree.asp_expiry_script.clone())
    };

    let leaf_hashes = [tap_leaf_hash(&forfeit_script), tap_leaf_hash(&exit_script)];
    compute_balanced_merkle_root(&leaf_hashes)
}

/// Tap leaf hashes in the same order as [`compute_ark_labs_merkle_root`], and the index of the
/// spend corresponding to `tree.asp_expiry_script` (`0` = forfeit arm, `1` = exit arm).
pub fn ark_labs_tap_leaf_hashes_for_merkle_path(
    tree: &VPackTree,
) -> Option<(Vec<[u8; 32]>, usize)> {
    if tree.asp_expiry_script.is_empty() {
        return None;
    }

    let (asp_pk, user_pk) = parse_ark_labs_pubkeys(&tree.asp_expiry_script)?;
    let forfeit_template = is_forfeit_template(&tree.asp_expiry_script)?;

    let (forfeit_script, exit_script) = if forfeit_template {
        let csv_bytes = encode_exit_delta_csv(tree.leaf.exit_delta);
        let exit = compile_exit_script(&asp_pk, &user_pk, &csv_bytes);
        (tree.asp_expiry_script.clone(), exit)
    } else {
        let forfeit = compile_forfeit_script(&asp_pk, &user_pk);
        (forfeit, tree.asp_expiry_script.clone())
    };

    let hashes = vec![tap_leaf_hash(&forfeit_script), tap_leaf_hash(&exit_script)];
    let leaf_idx = if forfeit_template { 0 } else { 1 };
    Some((hashes, leaf_idx))
}

/// Encodes `exit_delta` as a minimal Bitcoin Script number for use with OP_CSV.
/// Follows BIP 68 block-based relative timelock encoding (type flag bit 22 = 0).
fn encode_exit_delta_csv(exit_delta: u16) -> Vec<u8> {
    if exit_delta == 0 {
        return vec![0x00];
    }
    let val = exit_delta as u32;
    let mut bytes = Vec::with_capacity(3);
    bytes.push(val as u8);
    if val > 0x7F {
        bytes.push((val >> 8) as u8);
        if val > 0x7FFF {
            bytes.push((val >> 16) as u8);
        } else if (val >> 8) & 0x80 != 0 {
            bytes.push(0x00);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::hash_sibling_birth_tx;
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

        let leaf_siblings = vec![SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        }];
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: user_value,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: user_script,
            },
            leaf_siblings,
            path: Vec::new(),
            anchor,
            asset_id: None,
            fee_anchor_script,
            internal_key: {
                let ik_hex = ri["internal_key"].as_str().unwrap_or("");
                let ik_bytes = hex::decode(ik_hex).unwrap_or_default();
                let mut arr = [0u8; 32];
                if ik_bytes.len() >= 32 {
                    arr.copy_from_slice(&ik_bytes[..32]);
                }
                arr
            },
            asp_expiry_script: ri["asp_expiry_script"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .unwrap_or_default(),
        };

        let engine = ArkLabsV3;
        let output = engine
            .compute_vtxo_id(&tree, None)
            .expect("compute VTXO ID");
        let computed_id = output.id;

        assert_eq!(
            computed_id, expected_vtxo_id,
            "VTXO ID mismatch: expected {} (display), got {}",
            expected_vtxo_id_str, computed_id
        );
    }

    /// Verification gate: engine must be reactive. Sabotaged anchor (wrong script) must produce IdMismatch.
    #[test]
    fn test_ark_labs_v3_leaf_sabotage_anchor_mismatch() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/round_leaf_v3.json");
        let contents = fs::read_to_string(&path).expect("read round_leaf_v3.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");

        let _expected_vtxo_id_str = json["raw_evidence"]["expected_vtxo_id"]
            .as_str()
            .expect("expected_vtxo_id present");

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

        let good_sibling = SiblingNode::Compact {
            hash: [0u8; 32],
            value: 0,
            script: fee_anchor_script.clone(),
        };
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: user_value,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: user_script.clone(),
            },
            leaf_siblings: vec![good_sibling],
            path: Vec::new(),
            anchor,
            asset_id: None,
            fee_anchor_script: fee_anchor_script.clone(),
            internal_key: [0u8; 32],
            asp_expiry_script: alloc::vec![],
        };

        // Sabotage: wrong script on the fee anchor sibling → different parent tx → IdMismatch
        let leaf_siblings_sabotaged = vec![SiblingNode::Compact {
            hash: [0u8; 32],
            value: 0,
            script: vec![0x00],
        }];
        let tree_sabotaged = VPackTree {
            leaf: VtxoLeaf {
                amount: user_value,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: user_script,
            },
            leaf_siblings: leaf_siblings_sabotaged,
            path: Vec::new(),
            anchor,
            asset_id: None,
            fee_anchor_script,
            internal_key: [0u8; 32],
            asp_expiry_script: alloc::vec![],
        };

        let anchor_value = 1100u64; // round_leaf_v3 input amount
        let engine = ArkLabsV3;
        let expected_id = engine
            .compute_vtxo_id(&tree, Some(anchor_value))
            .expect("good tree")
            .id;
        let computed_bad = engine
            .compute_vtxo_id(&tree_sabotaged, Some(anchor_value))
            .expect("compute sabotaged tree")
            .id;
        let result = engine.verify(&tree_sabotaged, &expected_id, anchor_value);
        assert!(
            matches!(
                result,
                Err(VPackError::IdMismatch {
                    computed,
                    expected,
                    computed_vout,
                    expected_vout,
                }) if computed
                    == crate::consensus::vtxo_id_mismatch_diagnostic_bytes(&computed_bad)
                    && expected
                        == crate::consensus::vtxo_id_mismatch_diagnostic_bytes(&expected_id)
                    && computed_vout
                        == crate::consensus::vtxo_id_mismatch_diagnostic_vout(&computed_bad)
                    && expected_vout
                        == crate::consensus::vtxo_id_mismatch_diagnostic_vout(&expected_id)
            ),
            "Sabotage test: wrong sibling script must yield IdMismatch, got {:?}",
            result
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
            let value = s["value"].as_u64().expect("sibling value");
            let script = hex::decode(s["script"].as_str().expect("sibling script"))
                .expect("decode sibling script");
            let hash = hash_sibling_birth_tx(value, &script);
            siblings.push(SiblingNode::Compact {
                hash,
                value,
                script,
            });
        }
        // Fee anchor is last sibling (passive reconstruction: adapter puts it in data)
        siblings.push(SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        });

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
            sequence,
            child_amount,
            child_script_pubkey: child_script_pubkey.clone(),
            ..Default::default()
        };

        let leaf_siblings = vec![SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        }];
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: child_amount,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script_pubkey,
            },
            leaf_siblings,
            path: vec![path_item],
            anchor,
            asset_id: None,
            fee_anchor_script,
            internal_key: [0u8; 32],
            asp_expiry_script: alloc::vec![],
        };

        let engine = ArkLabsV3;
        let output = engine
            .compute_vtxo_id(&tree, None)
            .expect("compute VTXO ID");
        let computed_id = output.id;

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

        // Build first level siblings (canonical birth tx hash for verification)
        let mut level1_siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let value = s["value"].as_u64().expect("sibling value");
            let script = hex::decode(s["script"].as_str().expect("sibling script"))
                .expect("decode sibling script");
            level1_siblings.push(SiblingNode::Compact {
                hash: hash_sibling_birth_tx(value, &script),
                value,
                script,
            });
        }
        level1_siblings.push(SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        });

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
            sequence,
            child_amount: 1100, // Child amount for next level
            child_script_pubkey: child_script.clone(),
            ..Default::default()
        };

        // Level 2: Intermediate node (simplified - using same structure). Fee anchor last.
        let level2_siblings = vec![
            SiblingNode::Compact {
                hash: hash_sibling_birth_tx(500, &sibling_script),
                value: 500,
                script: sibling_script.clone(),
            },
            SiblingNode::Compact {
                hash: hash_sibling_birth_tx(0, &fee_anchor_script),
                value: 0,
                script: fee_anchor_script.clone(),
            },
        ];
        let level2_item = GenesisItem {
            siblings: level2_siblings,
            sequence,
            child_amount: 600, // Child amount for leaf
            child_script_pubkey: child_script.clone(),
            ..Default::default()
        };

        // Level 3: Leaf node
        let leaf_siblings = vec![SiblingNode::Compact {
            hash: hash_sibling_birth_tx(0, &fee_anchor_script),
            value: 0,
            script: fee_anchor_script.clone(),
        }];
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 600,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script,
            },
            leaf_siblings,
            path: vec![level1_item, level2_item], // 2 levels in path + 1 leaf = 3 levels total
            anchor,
            asset_id: None,
            fee_anchor_script,
            internal_key: [0u8; 32],
            asp_expiry_script: alloc::vec![],
        };

        let engine = ArkLabsV3;
        let output = engine
            .compute_vtxo_id(&tree, None)
            .expect("compute VTXO ID");
        let computed_id = output.id;

        // Verify it's a Raw hash (Ark Labs format)
        match computed_id {
            VtxoId::Raw(_) => {
                // Success - recursive logic worked
            }
            VtxoId::OutPoint(_) => panic!("expected Raw hash for Ark Labs"),
        }

        // Verify the ID is non-zero (sanity check)
        if let VtxoId::Raw(bytes) = computed_id {
            assert!(
                !bytes.iter().all(|&b| b == 0),
                "VTXO ID should not be all zeros"
            );
        }
    }
}
