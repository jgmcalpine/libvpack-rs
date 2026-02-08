//! WASM wrapper for vpack verification with auto-inference over ArkLabs and SecondTech adapters.

use core::str::FromStr;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use vpack::{
    create_vpack_from_tree, verify, ArkLabsAdapter, ArkLabsV3, ConsensusEngine, LogicAdapter,
    SecondTechAdapter, SecondTechV3, TxVariant, VtxoId,
};

/// Set the panic hook so Rust panics show up as readable errors in the browser console.
#[wasm_bindgen]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
struct WasmVerifyResult {
    variant: String,
    status: String,
    reconstructed_tx_id: String,
}

/// Verifies reconstruction_ingredients JSON against expected_vtxo_id.
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

    let ri = value.get("reconstruction_ingredients").ok_or_else(|| {
        JsValue::from_str("missing reconstruction_ingredients")
    })?;

    // Try ArkLabs (V3Anchored) first
    if let Ok(tree) = ArkLabsAdapter::map_ingredients(ri) {
        let bytes = create_vpack_from_tree(&tree, TxVariant::V3Anchored)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        if verify(&bytes, &expected_id).is_ok() {
            let engine = ArkLabsV3;
            let reconstructed = engine
                .compute_vtxo_id(&tree)
                .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
            return Ok(serde_wasm_bindgen::to_value(&WasmVerifyResult {
                variant: "0x04".to_string(),
                status: "Success".to_string(),
                reconstructed_tx_id: reconstructed.to_string(),
            })?);
        }
    }

    // Try SecondTech (V3Plain)
    if let Ok(tree) = SecondTechAdapter::map_ingredients(ri) {
        let bytes = create_vpack_from_tree(&tree, TxVariant::V3Plain)
            .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
        if verify(&bytes, &expected_id).is_ok() {
            let engine = SecondTechV3;
            let reconstructed = engine
                .compute_vtxo_id(&tree)
                .map_err(|e: vpack::error::VPackError| JsValue::from_str(&e.to_string()))?;
            return Ok(serde_wasm_bindgen::to_value(&WasmVerifyResult {
                variant: "0x03".to_string(),
                status: "Success".to_string(),
                reconstructed_tx_id: reconstructed.to_string(),
            })?);
        }
    }

    Err(JsValue::from_str(
        "no adapter matched or verification failed for reconstruction_ingredients",
    ))
}
