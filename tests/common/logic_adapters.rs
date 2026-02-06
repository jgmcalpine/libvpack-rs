//! Logic-mapping adapters: build VPackTree from reconstruction_ingredients JSON.
//! Dispatched by variant (0x03 Second Tech, 0x04 Ark Labs); fall back to byte transcoding when ingredients are incomplete.

use core::str::FromStr;
use vpack::error::VPackError;
use vpack::header::TxVariant;
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};

/// Converts 32-byte hash (internal/wire order) to 64-char hex in Bitcoin display order (reversed).
#[allow(dead_code)]
fn hash_to_display_hex(hash: &[u8; 32]) -> String {
    let mut rev = *hash;
    rev.reverse();
    rev.iter().map(|b| format!("{:02x}", b)).collect()
}

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
        let anchor_id =
            vpack::VtxoId::from_str(anchor_str).map_err(|_| VPackError::InvalidVtxoIdFormat)?;
        let anchor = match anchor_id {
            vpack::VtxoId::OutPoint(op) => op,
            vpack::VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
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
            .map(|h| hex::decode(h))
            .transpose()
            .map_err(|_| VPackError::EncodingError)?
            .unwrap_or_else(Vec::new);

        // Optional: one GenesisItem from "siblings" (branch case).
        let (path, leaf) = if let Some(siblings) = json["siblings"].as_array() {
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
            let sibling_nodes: Vec<SiblingNode> = siblings
                .iter()
                .filter_map(|s| {
                    let hash_hex = s["hash"].as_str()?;
                    let hash_bytes = hex::decode(hash_hex).ok()?;
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(hash_bytes.get(0..32)?);
                    let value = s["value"].as_u64()?;
                    let script = hex::decode(s["script"].as_str()?).ok()?;
                    Some(SiblingNode::Compact {
                        hash,
                        value,
                        script,
                    })
                })
                .collect();
            let path = if sibling_nodes.is_empty() {
                vec![]
            } else {
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
            (path, leaf)
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
            (vec![], leaf)
        };

        Ok(VPackTree {
            leaf,
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
        let anchor_id =
            vpack::VtxoId::from_str(anchor_str).map_err(|_| VPackError::InvalidVtxoIdFormat)?;
        let anchor = match anchor_id {
            vpack::VtxoId::OutPoint(op) => op,
            vpack::VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
        };

        let path_array = json["path"]
            .as_array()
            .or_else(|| json["genesis"].as_array());
        let path = if let Some(steps) = path_array {
            steps
                .iter()
                .filter_map(|step| {
                    let siblings = step["siblings"].as_array()?;
                    let sibling_nodes: Vec<SiblingNode> = siblings
                        .iter()
                        .filter_map(|s| {
                            let hash_hex = s["hash"].as_str()?;
                            let hash_bytes = hex::decode(hash_hex).ok()?;
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(hash_bytes.get(0..32)?);
                            let value = s["value"].as_u64()?;
                            let script = hex::decode(s["script"].as_str()?).ok()?;
                            Some(SiblingNode::Compact {
                                hash,
                                value,
                                script,
                            })
                        })
                        .collect();
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

        Ok(VPackTree {
            leaf,
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
                && (reconstruction_ingredients
                    .get("script_pubkey_hex")
                    .is_some()
                    || reconstruction_ingredients.get("script").is_some())
                && (reconstruction_ingredients.get("anchor_outpoint").is_some()
                    || reconstruction_ingredients.get("parent_outpoint").is_some())
            {
                Some(SecondTechAdapter::map_ingredients(
                    reconstruction_ingredients,
                ))
            } else {
                None
            }
        }
    }
}

/// Exports the path of a VPackTree to the JSON path array format expected by SecondTechAdapter.
/// Used to derive reconstruction_ingredients.path from borsh_hex (bark_to_vpack) for test vectors.
#[allow(dead_code)]
pub fn second_path_from_tree(tree: &VPackTree) -> serde_json::Value {
    let path: Vec<serde_json::Value> = tree
        .path
        .iter()
        .map(|item| {
            let siblings: Vec<serde_json::Value> = item
                .siblings
                .iter()
                .filter_map(|s| {
                    let (hash_hex, value, script_hex) = match s {
                        SiblingNode::Compact {
                            hash,
                            value,
                            script,
                        } => (hash_to_display_hex(hash), *value, hex::encode(script)),
                        SiblingNode::Full(_) => return None,
                    };
                    Some(serde_json::json!({
                        "hash": hash_hex,
                        "value": value,
                        "script": script_hex,
                    }))
                })
                .collect();
            serde_json::json!({
                "siblings": siblings,
                "parent_index": item.parent_index,
                "sequence": item.sequence,
                "child_amount": item.child_amount,
                "child_script_pubkey": hex::encode(&item.child_script_pubkey),
            })
        })
        .collect();
    serde_json::Value::Array(path)
}
