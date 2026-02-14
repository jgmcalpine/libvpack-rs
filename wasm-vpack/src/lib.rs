//! WASM wrapper for vpack verification with auto-inference over ArkLabs and SecondTech adapters.

use core::str::FromStr;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use vpack::consensus::{tx_preimage, TxInPreimage, TxOutPreimage};
use vpack::header::{Header, HEADER_SIZE, MAGIC_BYTES};
use vpack::payload::reader::BoundedReader;
use vpack::payload::tree::{GenesisItem, SiblingNode};
use vpack::payload::validate_invariants;
use vpack::types::hashes::{sha256d, Hash};
use vpack::types::{OutPoint, Txid};
use vpack::{
    create_vpack_from_tree, verify, ArkLabsAdapter, ArkLabsV3, ConsensusEngine, LogicAdapter,
    SecondTechAdapter, SecondTechV3, TxVariant, VPackTree, VtxoId,
};

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
    is_anchor: bool,
    vout: u32,
    has_signature: bool,
    has_fee_anchor: bool,
    exit_weight_vb: u32,
    /// Relative timelock in blocks (user must wait before exit). Leaf only; 0 for anchor/branches.
    exit_delta: u16,
    /// Raw Bitcoin transaction preimage hex (BIP-431/TRUC). Empty for anchor (L1 tx).
    tx_preimage_hex: String,
    /// Number of sibling outputs at this level (excluding fee anchor). Branch scaling factor = sibling_count + 1.
    sibling_count: u32,
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

/// Computes the output sum at the root level (for Test Mode self-consistency).
fn tree_output_sum(tree: &VPackTree) -> u64 {
    if tree.path.is_empty() {
        let leaf_sum = tree.leaf.amount
            + tree
                .leaf_siblings
                .iter()
                .filter_map(|s| match s {
                    SiblingNode::Compact { value, .. } => Some(*value),
                    SiblingNode::Full(_) => None,
                })
                .sum::<u64>();
        return leaf_sum;
    }
    let first = &tree.path[0];
    let child = first.child_amount;
    let siblings_sum: u64 = first
        .siblings
        .iter()
        .filter_map(|s| match s {
            SiblingNode::Compact { value, .. } => Some(*value),
            SiblingNode::Full(_) => None,
        })
        .sum();
    child.saturating_add(siblings_sum)
}

/// Extracts path details from a VPackTree (works for both ArkLabs and SecondTech variants).
/// Returns a vector of PathDetail structs representing the sovereignty path.
fn extract_path_details(
    tree: &VPackTree,
    anchor_value: u64,
    variant: TxVariant,
) -> Result<Vec<PathDetail>, JsValue> {
    let mut path_details = Vec::new();

    // Add anchor node (L1 transaction)
    let anchor_txid = txid_to_string(&tree.anchor.txid);
    let anchor_outputs = 1; // Anchor typically has 1 output
    path_details.push(PathDetail {
        txid: anchor_txid,
        amount: anchor_value,
        is_leaf: false,
        is_anchor: true,
        vout: tree.anchor.vout,
        has_signature: false,
        has_fee_anchor: false,
        exit_weight_vb: estimate_exit_weight_vb(anchor_outputs),
        exit_delta: 0,
        tx_preimage_hex: String::new(), // L1 tx; no virtual preimage
        sibling_count: 0,
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
        let mut sibling_count: u32 = 0;
        for sibling in &genesis_item.siblings {
            match sibling {
                SiblingNode::Compact { value, script, .. } => {
                    outputs.push(TxOutPreimage {
                        value: *value,
                        script_pubkey: script.as_slice(),
                    });
                    if script == &tree.fee_anchor_script {
                        has_fee_anchor = true;
                    } else {
                        sibling_count += 1;
                    }
                }
                SiblingNode::Full(_) => {
                    return Err(JsValue::from_str("Full sibling nodes not supported"))
                }
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
            is_anchor: false,
            vout,
            has_signature: genesis_item.signature.is_some(),
            has_fee_anchor,
            exit_weight_vb: exit_weight,
            exit_delta: 0,
            tx_preimage_hex: hex::encode(&preimage_bytes),
            sibling_count,
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
        current_prevout = OutPoint {
            txid,
            vout: next_vout,
        };
        // Get the amount from the output at the next_vout index
        input_amount = outputs.get(next_vout as usize).map(|o| o.value);
    }

    // Add leaf node
    let num_leaf_outputs = 1 + tree.leaf_siblings.len();
    let mut leaf_has_fee_anchor = false;
    let mut leaf_sibling_count: u32 = 0;
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
                } else {
                    leaf_sibling_count += 1;
                }
            }
            SiblingNode::Full(_) => {
                return Err(JsValue::from_str("Full sibling nodes not supported"))
            }
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
        is_anchor: false,
        vout: tree.leaf.vout,
        has_signature: false,
        has_fee_anchor: leaf_has_fee_anchor,
        exit_weight_vb: estimate_exit_weight_vb(leaf_outputs.len()),
        exit_delta: tree.leaf.exit_delta,
        tx_preimage_hex: hex::encode(&leaf_preimage),
        sibling_count: leaf_sibling_count,
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
    let value: serde_json::Value =
        serde_json::from_str(json_input).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let expected_id_str = value["raw_evidence"]["expected_vtxo_id"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("missing raw_evidence.expected_vtxo_id"))?;

    let expected_id = VtxoId::from_str(expected_id_str)
        .map_err(|_| JsValue::from_str("invalid expected_vtxo_id format"))?;

    let anchor_value = value
        .get("anchor_value")
        .ok_or_else(|| JsValue::from_str("missing anchor_value (L1 UTXO value in sats); use string for 64-bit, e.g. \"anchor_value\": \"1100\""))
        .and_then(parse_anchor_value)?;

    let ri = value
        .get("reconstruction_ingredients")
        .ok_or_else(|| JsValue::from_str("missing reconstruction_ingredients"))?;

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
        let path_details =
            extract_path_details(&tree, anchor_value, TxVariant::V3Anchored).map_err(|e| e)?;
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
        let path_details =
            extract_path_details(&tree, anchor_value, TxVariant::V3Plain).map_err(|e| e)?;
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
    let value: serde_json::Value =
        serde_json::from_str(json_input).map_err(|e| JsValue::from_str(&e.to_string()))?;

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
    let value: serde_json::Value =
        serde_json::from_str(json_input).map_err(|e| JsValue::from_str(&e.to_string()))?;

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

#[derive(Serialize)]
struct WasmParseHeaderResult {
    anchor_txid: String,
    anchor_vout: u32,
    tx_variant: String,
    is_testnet: bool,
}

/// Parses the V-PACK header and minimal payload prefix to extract anchor outpoint.
/// Validates magic bytes first. Returns { anchor_txid, anchor_vout, tx_variant, is_testnet }.
/// Use anchor_txid (display hex) with mempool.space for L1 fetch.
#[wasm_bindgen]
pub fn wasm_parse_vpack_header(vpack_bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    if vpack_bytes.len() < HEADER_SIZE {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    if vpack_bytes[0] != MAGIC_BYTES[0]
        || vpack_bytes[1] != MAGIC_BYTES[1]
        || vpack_bytes[2] != MAGIC_BYTES[2]
    {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])
        .map_err(|e| JsValue::from_str(&format!("Error: Not a valid V-PACK file. {}.", e)))?;

    let payload = &vpack_bytes[HEADER_SIZE..];
    let payload_len = header.payload_len as usize;
    if payload.len() < payload_len {
        return Err(JsValue::from_str("Error: Incomplete V-PACK data."));
    }
    let payload = &payload[..payload_len];

    let anchor_offset = if header.has_asset_id() { 32 } else { 0 };
    if payload.len() < anchor_offset + 36 {
        return Err(JsValue::from_str("Error: Incomplete V-PACK payload."));
    }

    let anchor_slice = &payload[anchor_offset..anchor_offset + 36];
    let mut cursor = anchor_slice;
    let anchor = vpack::types::decode_outpoint(&mut cursor)
        .map_err(|_| JsValue::from_str("Error: Failed to parse anchor outpoint."))?;

    let anchor_txid = txid_to_string(&anchor.txid);
    let tx_variant = match header.tx_variant {
        TxVariant::V3Plain => "0x03",
        TxVariant::V3Anchored => "0x04",
    };

    Ok(serde_wasm_bindgen::to_value(&WasmParseHeaderResult {
        anchor_txid,
        anchor_vout: anchor.vout,
        tx_variant: tx_variant.to_string(),
        is_testnet: header.is_testnet(),
    })?)
}

/// Unpacks a binary V-PACK to JSON ingredients (reconstruction_ingredients + raw_evidence).
/// Allows the user to "see inside" any .vpk file. Does not verify—parse only.
#[wasm_bindgen]
pub fn wasm_unpack_to_json(vpack_bytes: Vec<u8>) -> Result<String, JsValue> {
    if vpack_bytes.len() < HEADER_SIZE {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    if vpack_bytes[0] != MAGIC_BYTES[0]
        || vpack_bytes[1] != MAGIC_BYTES[1]
        || vpack_bytes[2] != MAGIC_BYTES[2]
    {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])
        .map_err(|e| JsValue::from_str(&format!("Error: Not a valid V-PACK file. {}.", e)))?;

    let payload = &vpack_bytes[HEADER_SIZE..];
    let payload_len = header.payload_len as usize;
    if payload.len() < payload_len {
        return Err(JsValue::from_str("Error: Incomplete V-PACK data."));
    }
    let payload = &payload[..payload_len];

    header
        .verify_checksum(payload)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    let tree = BoundedReader::parse(&header, payload)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    validate_invariants(&header, &tree).map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    let expected_id = match header.tx_variant {
        TxVariant::V3Anchored => ArkLabsV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?,
        TxVariant::V3Plain => SecondTechV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?,
    };

    let fee_hex = hex::encode(&tree.fee_anchor_script);

    let reconstruction_ingredients = match header.tx_variant {
        TxVariant::V3Anchored => tree_to_ark_labs_json(&tree, &fee_hex),
        TxVariant::V3Plain => tree_to_second_tech_json(&tree, &fee_hex),
    };

    let output = serde_json::json!({
        "meta": {
            "variant": match header.tx_variant {
                TxVariant::V3Anchored => "0x04",
                TxVariant::V3Plain => "0x03",
            },
            "description": "Unpacked from binary V-PACK"
        },
        "raw_evidence": {
            "expected_vtxo_id": expected_id.to_string()
        },
        "reconstruction_ingredients": reconstruction_ingredients
    });

    serde_json::to_string_pretty(&output).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn tree_to_ark_labs_json(tree: &VPackTree, fee_hex: &str) -> serde_json::Value {
    let anchor_op = format!("{}:{}", txid_to_string(&tree.anchor.txid), tree.anchor.vout);

    if tree.path.is_empty() {
        let mut outputs = vec![serde_json::json!({
            "value": tree.leaf.amount,
            "script": hex::encode(&tree.leaf.script_pubkey)
        })];
        outputs.push(serde_json::json!({
            "value": 0,
            "script": fee_hex,
            "note": "Fee Anchor"
        }));
        serde_json::json!({
            "topology": "Tree",
            "tx_version": 3,
            "nSequence": tree.leaf.sequence,
            "parent_outpoint": anchor_op,
            "fee_anchor_script": fee_hex,
            "id_type": "Hash",
            "outputs": outputs
        })
    } else {
        let first = &tree.path[0];
        let siblings: Vec<serde_json::Value> = first
            .siblings
            .iter()
            .filter_map(|s| {
                let SiblingNode::Compact {
                    hash,
                    value,
                    script,
                } = s
                else {
                    return None;
                };
                if script.as_slice() == tree.fee_anchor_script.as_slice() && *value == 0 {
                    return None;
                }
                Some(serde_json::json!({
                    "hash": hex::encode(hash),
                    "value": value,
                    "script": hex::encode(script)
                }))
            })
            .collect();
        serde_json::json!({
            "topology": "Tree",
            "tx_version": 3,
            "nSequence": first.sequence,
            "fee_anchor_script": fee_hex,
            "id_type": "Hash",
            "anchor_outpoint": anchor_op,
            "siblings": siblings,
            "child_output": {
                "value": first.child_amount,
                "script": hex::encode(&first.child_script_pubkey)
            }
        })
    }
}

fn tree_to_second_tech_json(tree: &VPackTree, fee_hex: &str) -> serde_json::Value {
    let path: Vec<serde_json::Value> = tree
        .path
        .iter()
        .map(|item| {
            let siblings: Vec<serde_json::Value> = item
                .siblings
                .iter()
                .filter_map(|s| {
                    let SiblingNode::Compact {
                        hash,
                        value,
                        script,
                    } = s
                    else {
                        return None;
                    };
                    if script.as_slice() == tree.fee_anchor_script.as_slice() && *value == 0 {
                        return None;
                    }
                    Some(serde_json::json!({
                        "hash": hex::encode(hash),
                        "value": value,
                        "script": hex::encode(script)
                    }))
                })
                .collect();
            serde_json::json!({
                "siblings": siblings,
                "parent_index": item.parent_index,
                "sequence": item.sequence,
                "child_amount": item.child_amount,
                "child_script_pubkey": hex::encode(&item.child_script_pubkey)
            })
        })
        .collect();

    serde_json::json!({
        "topology": "Chain",
        "tx_version": 3,
        "nSequence": 0,
        "fee_anchor_script": fee_hex,
        "id_type": "OutPoint",
        "amount": tree.leaf.amount,
        "script_pubkey_hex": hex::encode(&tree.leaf.script_pubkey),
        "anchor_outpoint": format!("{}:{}", txid_to_string(&tree.anchor.txid), tree.anchor.vout),
        "path": path
    })
}

/// Verifies a binary V-PACK directly (bypasses Logic Adapters).
/// Calls core vpack::verify() with bytes already in standard format.
/// anchor_value: Some(sats) for L1 verification; None for Test Mode (uses output sum).
#[wasm_bindgen]
pub fn wasm_verify_binary(
    vpack_bytes: Vec<u8>,
    anchor_value: Option<u64>,
) -> Result<JsValue, JsValue> {
    if vpack_bytes.len() < HEADER_SIZE {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    if vpack_bytes[0] != MAGIC_BYTES[0]
        || vpack_bytes[1] != MAGIC_BYTES[1]
        || vpack_bytes[2] != MAGIC_BYTES[2]
    {
        return Err(JsValue::from_str(
            "Error: Not a valid V-PACK file. Expected 'VPK' magic bytes.",
        ));
    }

    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])
        .map_err(|e| JsValue::from_str(&format!("Error: Not a valid V-PACK file. {}.", e)))?;

    let payload = &vpack_bytes[HEADER_SIZE..];
    let payload_len = header.payload_len as usize;
    if payload.len() < payload_len {
        return Err(JsValue::from_str("Error: Incomplete V-PACK data."));
    }
    let payload = &payload[..payload_len];

    header
        .verify_checksum(payload)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    let tree = BoundedReader::parse(&header, payload)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    validate_invariants(&header, &tree).map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    let expected_id = match header.tx_variant {
        TxVariant::V3Anchored => ArkLabsV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?,
        TxVariant::V3Plain => SecondTechV3
            .compute_vtxo_id(&tree, None)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?,
    };

    let anchor_val = anchor_value.unwrap_or_else(|| tree_output_sum(&tree));

    verify(vpack_bytes.as_slice(), &expected_id, anchor_val)
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;

    let variant_str = match header.tx_variant {
        TxVariant::V3Anchored => "0x04",
        TxVariant::V3Plain => "0x03",
    };
    let path_details = extract_path_details(&tree, anchor_val, header.tx_variant)?;

    Ok(serde_wasm_bindgen::to_value(&WasmVerifyResult {
        variant: variant_str.to_string(),
        status: "Success".to_string(),
        reconstructed_tx_id: expected_id.to_string(),
        path_details,
    })?)
}
