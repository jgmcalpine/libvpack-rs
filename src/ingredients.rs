//! Logic-mapping adapters: build VPackTree from reconstruction_ingredients JSON.
//! Used by wasm-vpack and tests for auto-inference over Ark Labs vs Second Tech.

use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use crate::error::VPackError;
use crate::header::TxVariant;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use crate::VtxoId;

const FEE_ANCHOR_SCRIPT_HEX: &str = "51024e73";

/// Ingests reconstruction_ingredients JSON and returns a VPackTree when the format is complete.
pub trait LogicAdapter {
    fn map_ingredients(json: &serde_json::Value) -> Result<VPackTree, VPackError>;
}

/// Ark Labs (Variant 0x04): parent_outpoint, outputs (value, script hex), nSequence, fee_anchor_script.
pub struct ArkLabsAdapter;

impl LogicAdapter for ArkLabsAdapter {
    fn map_ingredients(json: &serde_json::Value) -> Result<VPackTree, VPackError> {
        let anchor_str = json["parent_outpoint"]
            .as_str()
            .or_else(|| json["anchor_outpoint"].as_str())
            .ok_or(VPackError::InvalidVtxoIdFormat)?;
        let anchor_id = VtxoId::from_str(anchor_str).map_err(|_| VPackError::InvalidVtxoIdFormat)?;
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
        };

        let fee_hex = json["fee_anchor_script"]
            .as_str()
            .unwrap_or(FEE_ANCHOR_SCRIPT_HEX);
        let fee_anchor_script = hex::decode(fee_hex).map_err(|_| VPackError::EncodingError)?;

        let sequence = json["nSequence"]
            .as_u64()
            .ok_or(VPackError::EncodingError)? as u32;

        let outputs = json["outputs"].as_array();
        let first = outputs.and_then(|a| a.first());
        let value = first.and_then(|o| o["value"].as_u64()).unwrap_or(0);
        let script_hex = first.and_then(|o| o["script"].as_str());
        let script_pubkey = script_hex
            .map(hex::decode)
            .transpose()
            .map_err(|_| VPackError::EncodingError)?
            .unwrap_or_else(Vec::new);

        let (path, leaf, leaf_siblings) = if let Some(siblings) = json["siblings"].as_array() {
            let child_output = json["child_output"].as_object().or_else(|| {
                json["outputs"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|o| o.as_object())
            });
            let (child_amount, child_script_pubkey) = if let Some(co) = child_output {
                let v = co["value"].as_u64().unwrap_or(0);
                let s = co["script"]
                    .as_str()
                    .map(|h| hex::decode(h).unwrap_or_default())
                    .unwrap_or_default();
                (v, s)
            } else {
                (value, script_pubkey.clone())
            };
            // Siblings in exact order from JSON, then fee anchor as last (adapter provides it).
            let mut sibling_nodes: Vec<SiblingNode> = siblings
                .iter()
                .filter_map(|s| {
                    let hash_hex = s["hash"].as_str()?;
                    let hash_bytes = hex::decode(hash_hex).ok()?;
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(hash_bytes.get(0..32)?);
                    let val = s["value"].as_u64()?;
                    let script = hex::decode(s["script"].as_str()?).ok()?;
                    Some(SiblingNode::Compact {
                        hash,
                        value: val,
                        script,
                    })
                })
                .collect();
            let path = if sibling_nodes.is_empty() {
                vec![]
            } else {
                sibling_nodes.push(SiblingNode::Compact {
                    hash: [0u8; 32],
                    value: 0,
                    script: fee_anchor_script.clone(),
                });
                vec![GenesisItem {
                    siblings: sibling_nodes,
                    parent_index: 0,
                    sequence,
                    child_amount,
                    child_script_pubkey: child_script_pubkey.clone(),
                    signature: None,
                }]
            };
            let leaf = VtxoLeaf {
                amount: child_amount,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: child_script_pubkey,
            };
            let leaf_siblings = vec![SiblingNode::Compact {
                hash: [0u8; 32],
                value: 0,
                script: fee_anchor_script.clone(),
            }];
            (path, leaf, leaf_siblings)
        } else {
            if script_pubkey.is_empty() {
                return Err(VPackError::EncodingError);
            }
            let leaf = VtxoLeaf {
                amount: value,
                vout: 0,
                sequence,
                expiry: 0,
                exit_delta: 0,
                script_pubkey,
            };
            // Leaf-only: leaf_siblings from outputs in exact order (outputs[1..] = fee anchor etc.).
            let leaf_siblings: Vec<SiblingNode> = outputs
                .map(|arr| {
                    arr.iter()
                        .skip(1)
                        .filter_map(|o| {
                            let val = o["value"].as_u64()?;
                            let script = hex::decode(o["script"].as_str()?).ok()?;
                            Some(SiblingNode::Compact {
                                hash: [0u8; 32],
                                value: val,
                                script,
                            })
                        })
                        .collect()
                })
                .unwrap_or_else(Vec::new);
            (Vec::new(), leaf, leaf_siblings)
        };

        Ok(VPackTree {
            leaf,
            leaf_siblings,
            path,
            anchor,
            asset_id: None,
            fee_anchor_script,
        })
    }
}

/// Second Tech (Variant 0x03): amount, script, exit_delta, nSequence=0, optional path from "genesis" or "path".
pub struct SecondTechAdapter;

impl LogicAdapter for SecondTechAdapter {
    fn map_ingredients(json: &serde_json::Value) -> Result<VPackTree, VPackError> {
        let fee_hex = json["fee_anchor_script"]
            .as_str()
            .unwrap_or(FEE_ANCHOR_SCRIPT_HEX);
        let fee_anchor_script = hex::decode(fee_hex).map_err(|_| VPackError::EncodingError)?;

        let amount = json["amount"].as_u64().ok_or(VPackError::EncodingError)?;
        let script_hex = json["script_pubkey_hex"]
            .as_str()
            .or_else(|| json["script"].as_str())
            .ok_or(VPackError::EncodingError)?;
        let script_pubkey = hex::decode(script_hex).map_err(|_| VPackError::EncodingError)?;
        let exit_delta = json["exit_delta"].as_u64().unwrap_or(0) as u16;

        let anchor_str = json["anchor_outpoint"]
            .as_str()
            .or_else(|| json["parent_outpoint"].as_str())
            .ok_or(VPackError::InvalidVtxoIdFormat)?;
        let anchor_id = VtxoId::from_str(anchor_str).map_err(|_| VPackError::InvalidVtxoIdFormat)?;
        let anchor = match anchor_id {
            VtxoId::OutPoint(op) => op,
            VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
        };

        let path_array = json["path"].as_array().or_else(|| json["genesis"].as_array());
        let path = if let Some(steps) = path_array {
            steps
                .iter()
                .filter_map(|step| {
                    let siblings = step["siblings"].as_array()?;
                    let mut sibling_nodes: Vec<SiblingNode> = siblings
                        .iter()
                        .filter_map(|s| {
                            let hash_hex = s["hash"].as_str()?;
                            let hash_bytes = hex::decode(hash_hex).ok()?;
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(hash_bytes.get(0..32)?);
                            let val = s["value"].as_u64()?;
                            let script = hex::decode(s["script"].as_str()?).ok()?;
                            Some(SiblingNode::Compact {
                                hash,
                                value: val,
                                script,
                            })
                        })
                        .collect();
                    sibling_nodes.push(SiblingNode::Compact {
                        hash: [0u8; 32],
                        value: 0,
                        script: fee_anchor_script.clone(),
                    });
                    let parent_index = step["parent_index"].as_u64().unwrap_or(0) as u32;
                    let sequence = step["sequence"].as_u64().unwrap_or(0) as u32;
                    let child_amount = step["child_amount"].as_u64()?;
                    let child_script_hex = step["child_script_pubkey"]
                        .as_str()
                        .or_else(|| step["child_script"].as_str())?;
                    let child_script_pubkey = hex::decode(child_script_hex).ok()?;
                    Some(GenesisItem {
                        siblings: sibling_nodes,
                        parent_index,
                        sequence,
                        child_amount,
                        child_script_pubkey,
                        signature: None,
                    })
                })
                .collect()
        } else {
            vec![]
        };

        let leaf = VtxoLeaf {
            amount,
            vout: json["vout"].as_u64().unwrap_or(0) as u32,
            sequence: 0,
            expiry: json["expiry_height"].as_u64().unwrap_or(0) as u32,
            exit_delta,
            script_pubkey,
        };

        let leaf_siblings = vec![SiblingNode::Compact {
            hash: [0u8; 32],
            value: 0,
            script: fee_anchor_script.clone(),
        }];

        Ok(VPackTree {
            leaf,
            leaf_siblings,
            path,
            anchor,
            asset_id: None,
            fee_anchor_script,
        })
    }
}

/// Dispatch by variant: try logic adapter first; returns None if ingredients are incomplete.
pub fn tree_from_ingredients(
    variant: TxVariant,
    reconstruction_ingredients: &serde_json::Value,
) -> Option<Result<VPackTree, VPackError>> {
    match variant {
        TxVariant::V3Anchored => {
            if reconstruction_ingredients.get("parent_outpoint").is_some()
                || reconstruction_ingredients.get("anchor_outpoint").is_some()
            {
                Some(ArkLabsAdapter::map_ingredients(reconstruction_ingredients))
            } else {
                None
            }
        }
        TxVariant::V3Plain => {
            if reconstruction_ingredients.get("amount").is_some()
                && (reconstruction_ingredients.get("script_pubkey_hex").is_some()
                    || reconstruction_ingredients.get("script").is_some())
                && (reconstruction_ingredients.get("anchor_outpoint").is_some()
                    || reconstruction_ingredients.get("parent_outpoint").is_some())
            {
                Some(SecondTechAdapter::map_ingredients(reconstruction_ingredients))
            } else {
                None
            }
        }
    }
}
