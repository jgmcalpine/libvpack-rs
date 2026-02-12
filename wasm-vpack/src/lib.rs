//! WASM wrapper for vpack verification with auto-inference over ArkLabs and SecondTech adapters.

use core::str::FromStr;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use vpack::{
    create_vpack_from_tree, verify, ArkLabsAdapter, ArkLabsV3, ConsensusEngine, LogicAdapter,
    SecondTechAdapter, SecondTechV3, TxVariant, VtxoId, VPackTree,
};
use vpack::payload::tree::{GenesisItem, SiblingNode};
use vpack::consensus::{tx_preimage, TxInPreimage, TxOutPreimage};
use vpack::types::hashes::{Hash, sha256d};
use vpack::types::{OutPoint, Txid};

/// Set the panic hook so Rust panics show up as readable errors in the browser console.
#[wasm_bindgen]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
struct PathDetail {
    txid: String,
    amount: u64,
    is_leaf: bool,
    vout: u32,
    has_signature: bool,
    has_fee_anchor: bool,
    exit_weight_vb: u32,
}

#[derive(Serialize)]
struct WasmVerifyResult {
    variant: String,
    status: String,
    reconstructed_tx_id: String,
    path_details: Vec<PathDetail>,
}

/// Parses anchor_value from JSON. Accepts string (decimal) or u64 for small values.
/// Use string for full 64-bit range (JS Number loses precision above 2^53).
fn parse_anchor_value(value: &serde_json::Value) -> Result<u64, JsValue> {
    if let Some(s) = value.as_str() {
        return s
            .parse::<u64>()
            .map_err(|_| JsValue::from_str("anchor_value string must be a decimal u64"));
    }
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    Err(JsValue::from_str(
        "anchor_value required as string (e.g. \"1100\") or number; use string for values > 2^53",
    ))
}

/// Estimates Bitcoin transaction size in vbytes for a V3/TRUC transaction.
/// Base: ~10 vB, Input: ~57 vB (Taproot with witness), Output: ~43 vB each.
fn estimate_exit_weight_vb(num_outputs: usize) -> u32 {
    // Base transaction overhead: version (4) + vin count (1) + vout count (1) + locktime (4) ≈ 10 vB
    let base = 10u32;
    // 1 Taproot input: prevout (36) + sequence (4) + witness (17 vB) ≈ 57 vB
    let input = 57u32;
    // Each output: value (8) + scriptPubKey with compact size ≈ 43 vB
    let outputs = (num_outputs as u32) * 43u32;
    base + input + outputs
}

/// Converts a Txid to its display string (reversed byte order for human readability).
fn txid_to_string(txid: &Txid) -> String {
    let bytes = txid.to_byte_array();
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// Extracts path details from a VPackTree (works for both ArkLabs and SecondTech variants).
/// Returns a vector of PathDetail structs representing the sovereignty path.
fn extract_path_details(tree: &VPackTree, anchor_value: u64, variant: TxVariant) -> Result<Vec<PathDetail>, JsValue> {
    
    let mut path_details = Vec::new();
    
    // Add anchor node (L1 transaction)
    let anchor_txid = txid_to_string(&tree.anchor.txid);
    let anchor_outputs = 1; // Anchor typically has 1 output
    path_details.push(PathDetail {
        txid: anchor_txid,
        amount: anchor_value,
        is_leaf: false,
        vout: tree.anchor.vout,
        has_signature: false,
        has_fee_anchor: false,
        exit_weight_vb: estimate_exit_weight_vb(anchor_outputs),
    });
    
    // Traverse path (similar to consensus engine compute_vtxo_id)
    let mut current_prevout = tree.anchor;
    let mut input_amount: Option<u64> = Some(anchor_value);
    
    for (idx, genesis_item) in tree.path.iter().enumerate() {
        let mut outputs = Vec::new();
        
        // Add child output if present
        if !genesis_item.child_script_pubkey.is_empty() {
            outputs.push(TxOutPreimage {
                value: genesis_item.child_amount,
                script_pubkey: genesis_item.child_script_pubkey.as_slice(),
            });
        }
        
        // Add sibling outputs
        let mut has_fee_anchor = false;
        for sibling in &genesis_item.siblings {
            match sibling {
                SiblingNode::Compact { value, script, .. } => {
                    outputs.push(TxOutPreimage {
                        value: *value,
                        script_pubkey: script.as_slice(),
                    });
                    // Check if this is the fee anchor script
                    if script == &tree.fee_anchor_script {
                        has_fee_anchor = true;
                    }
                }
                SiblingNode::Full(_) => return Err(JsValue::from_str("Full sibling nodes not supported")),
            }
        }
        
        // Build input
        let input = TxInPreimage {
            prev_out_txid: current_prevout.txid.to_byte_array(),
            prev_out_vout: current_prevout.vout,
            sequence: genesis_item.sequence,
        };
        
        // Compute transaction ID
        let preimage_bytes = tx_preimage(3, &[input], &outputs, 0);
        let hash = sha256d::Hash::hash(&preimage_bytes);
        let txid_bytes = hash.to_byte_array();
        let txid = Txid::from_byte_array(txid_bytes);
        let txid_str = txid_to_string(&txid);
        
        // Get amount (child amount or first output value)
        let amount = genesis_item.child_amount;
        
        // Calculate exit weight
        let exit_weight = estimate_exit_weight_vb(outputs.len());
        
        // Determine vout based on variant
        // For display purposes, we show the vout that would be used for the next transaction
        let vout = match variant {
            TxVariant::V3Anchored => 0, // Ark Labs always uses vout 0
            TxVariant::V3Plain => {
                // SecondTech uses parent_index from next item in path, or leaf.vout if last
                if idx + 1 < tree.path.len() {
                    tree.path[idx + 1].parent_index
                } else {
                    tree.leaf.vout
                }
            }
        };
        
        path_details.push(PathDetail {
            txid: txid_str,
            amount,
            is_leaf: false,
            vout,
            has_signature: genesis_item.signature.is_some(),
            has_fee_anchor,
            exit_weight_vb: exit_weight,
        });
        
        // Update for next iteration - determine which output index to use
        let next_vout = match variant {
            TxVariant::V3Anchored => 0,
            TxVariant::V3Plain => {
                // Use parent_index from next path item, or leaf.vout if last
                if idx + 1 < tree.path.len() {
                    tree.path[idx + 1].parent_index
                } else {
                    tree.leaf.vout
                }
            }
        };
        current_prevout = OutPoint { txid, vout: next_vout };
        // Get the amount from the output at the next_vout index
        input_amount = outputs.get(next_vout as usize).map(|o| o.value);
    }
    
    // Add leaf node
    let num_leaf_outputs = 1 + tree.leaf_siblings.len();
    let mut leaf_has_fee_anchor = false;
    let mut leaf_outputs = Vec::new();
    leaf_outputs.push(TxOutPreimage {
        value: tree.leaf.amount,
        script_pubkey: tree.leaf.script_pubkey.as_slice(),
    });
    for sibling in &tree.leaf_siblings {
        match sibling {
            SiblingNode::Compact { value, script, .. } => {
                leaf_outputs.push(TxOutPreimage {
                    value: *value,
                    script_pubkey: script.as_slice(),
                });
                if script == &tree.fee_anchor_script {
                    leaf_has_fee_anchor = true;
                }
            }
            SiblingNode::Full(_) => return Err(JsValue::from_str("Full sibling nodes not supported")),
        }
    }
    
    // Compute leaf transaction ID
    let leaf_input = TxInPreimage {
        prev_out_txid: current_prevout.txid.to_byte_array(),
        prev_out_vout: current_prevout.vout,
        sequence: tree.leaf.sequence,
    };
    let leaf_preimage = tx_preimage(3, &[leaf_input], &leaf_outputs, 0);
    let leaf_hash = sha256d::Hash::hash(&leaf_preimage);
    let leaf_txid_bytes = leaf_hash.to_byte_array();
    let leaf_txid = Txid::from_byte_array(leaf_txid_bytes);
    let leaf_txid_str = txid_to_string(&leaf_txid);
    
    path_details.push(PathDetail {
        txid: leaf_txid_str,
        amount: tree.leaf.amount,
        is_leaf: true,
        vout: tree.leaf.vout,
        has_signature: false,
        has_fee_anchor: leaf_has_fee_anchor,
        exit_weight_vb: estimate_exit_weight_vb(leaf_outputs.len()),
    });
    
    Ok(path_details)
}

/// Verifies reconstruction_ingredients JSON against expected_vtxo_id.
/// JSON must include anchor_value (L1 UTXO value in sats) as string or number.
/// Use string for full 64-bit range (e.g. "anchor_value": "1100").
/// Tries ArkLabs then SecondTech adapters; returns the first that parses and verifies.
/// Response: { variant, status: "Success"|"Failure", reconstructed_tx_id }.
#[wasm_bindgen]
pub fn wasm_verify(json_input: &str) -> Result<JsValue, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json_input)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let expected_id_str = value["raw_evidence"]["expected_vtxo_id"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("missing raw_evidence.expected_vtxo_id"))?;

    let expected_id = VtxoId::from_str(expected_id_str)
        .map_err(|_| JsValue::from_str("invalid expected_vtxo_id format"))?;

    let anchor_value = value
        .get("anchor_value")
        .ok_or_else(|| JsValue::from_str("missing anchor_value (L1 UTXO value in sats); use string for 64-bit, e.g. \"anchor_value\": \"1100\""))
        .and_then(parse_anchor_value)?;

    let ri = value.get("reconstruction_ingredients").ok_or_else(|| {
        JsValue::from_str("missing reconstruction_ingredients")
    })?;

    // Try ArkLabs (V3Anchored) first
    if let Ok(tree) = ArkLabsAdapter::map_ingredients(ri) {
        let bytes = create_vpack_from_tree(&tree, TxVariant::V3Anchored)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        // Use master verify() function
        verify(&bytes, &expected_id, anchor_value)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        let engine = ArkLabsV3;
        let reconstructed = engine
            .compute_vtxo_id(&tree, None)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        let path_details = extract_path_details(&tree, anchor_value, TxVariant::V3Anchored)
            .map_err(|e| e)?;
        return Ok(serde_wasm_bindgen::to_value(&WasmVerifyResult {
            variant: "0x04".to_string(),
            status: "Success".to_string(),
            reconstructed_tx_id: reconstructed.to_string(),
            path_details,
        })?);
    }

    // Try SecondTech (V3Plain)
    if let Ok(tree) = SecondTechAdapter::map_ingredients(ri) {
        let bytes = create_vpack_from_tree(&tree, TxVariant::V3Plain)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        // Use master verify() function
        verify(&bytes, &expected_id, anchor_value)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        let engine = SecondTechV3;
        let reconstructed = engine
            .compute_vtxo_id(&tree, None)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        let path_details = extract_path_details(&tree, anchor_value, TxVariant::V3Plain)
            .map_err(|e| e)?;
        return Ok(serde_wasm_bindgen::to_value(&WasmVerifyResult {
            variant: "0x03".to_string(),
            status: "Success".to_string(),
            reconstructed_tx_id: reconstructed.to_string(),
            path_details,
        })?);
    }

    Err(JsValue::from_str(
        "no adapter matched or verification failed for reconstruction_ingredients",
    ))
}

#[derive(Serialize)]
struct WasmComputeVtxoIdResult {
    variant: String,
    reconstructed_tx_id: String,
}

/// Computes the VTXO ID from reconstruction_ingredients only (no anchor_value).
/// Use for path verification before fetching L1. Tries ArkLabs then SecondTech.
/// Returns { variant, reconstructed_tx_id } or throws.
#[wasm_bindgen]
pub fn wasm_compute_vtxo_id(json_input: &str) -> Result<JsValue, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json_input)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let ri = value
        .get("reconstruction_ingredients")
        .ok_or_else(|| JsValue::from_str("missing reconstruction_ingredients"))?;

    if let Ok(tree) = ArkLabsAdapter::map_ingredients(ri) {
        let reconstructed = ArkLabsV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        return Ok(serde_wasm_bindgen::to_value(&WasmComputeVtxoIdResult {
            variant: "0x04".to_string(),
            reconstructed_tx_id: reconstructed.to_string(),
        })?);
    }

    if let Ok(tree) = SecondTechAdapter::map_ingredients(ri) {
        let reconstructed = SecondTechV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        return Ok(serde_wasm_bindgen::to_value(&WasmComputeVtxoIdResult {
            variant: "0x03".to_string(),
            reconstructed_tx_id: reconstructed.to_string(),
        })?);
    }

    Err(JsValue::from_str(
        "no adapter matched for reconstruction_ingredients",
    ))
}

/// Exports reconstruction_ingredients JSON to standard-compliant V-PACK binary.
/// Uses the same LogicAdapter mapping as verification (ArkLabs/SecondTech) for byte-perfect output.
/// JSON must include reconstruction_ingredients; anchor_value is not required for packing.
/// Returns raw bytes as Uint8Array, or throws on parse/encoding error.
#[wasm_bindgen]
pub fn wasm_export_to_vpack(json_input: &str) -> Result<Vec<u8>, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json_input)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let ri = value
        .get("reconstruction_ingredients")
        .ok_or_else(|| JsValue::from_str("missing reconstruction_ingredients"))?;

    if let Ok(tree) = ArkLabsAdapter::map_ingredients(ri) {
        return create_vpack_from_tree(&tree, TxVariant::V3Anchored)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()));
    }

    if let Ok(tree) = SecondTechAdapter::map_ingredients(ri) {
        return create_vpack_from_tree(&tree, TxVariant::V3Plain)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()));
    }

    Err(JsValue::from_str(
        "no adapter matched for reconstruction_ingredients",
    ))
}
