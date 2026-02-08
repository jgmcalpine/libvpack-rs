//! Export parity tests: gold-standard reconstruction_ingredients → create_vpack_* → verify.
//! Uses only the public API (no pack/Header/internal adapters).

use core::str::FromStr;
use std::fs;
use std::path::PathBuf;

use vpack::export::{create_vpack_ark_labs, create_vpack_second_tech};

#[test]
fn export_ark_labs_parity() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_dir = manifest_dir.join("tests/conformance/vectors/ark_labs");
    if !vectors_dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(&vectors_dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.extension().map(|e| e.to_str()) != Some(Some("json")) {
            continue;
        }
        let contents = fs::read_to_string(&path).expect("read");
        let value: serde_json::Value = serde_json::from_str(&contents).expect("parse");
        let raw = value.get("raw_evidence").and_then(|r| r.get("expected_vtxo_id"));
        let expected_str = match raw.and_then(|v| v.as_str()) {
            Some(s) if s != "COMPUTE_FROM_HEX" && s != "PLACEHOLDER" => s,
            _ => continue,
        };
        let expected_id = vpack::VtxoId::from_str(expected_str).expect("parse expected_vtxo_id");
        let ingredients_json = value
            .get("reconstruction_ingredients")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let ingredients = crate::common::ark_labs_ingredients_from_json(&ingredients_json)
            .unwrap_or_else(|e| panic!("{}: ingredients_from_json: {}", path.display(), e));
        let bytes = create_vpack_ark_labs(ingredients).expect("create_vpack_ark_labs");
        vpack::verify(&bytes, &expected_id).expect("verify");
    }
}

#[test]
fn export_second_tech_parity() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_dir = manifest_dir.join("tests/conformance/vectors/second");
    if !vectors_dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(&vectors_dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.extension().map(|e| e.to_str()) != Some(Some("json")) {
            continue;
        }
        let contents = fs::read_to_string(&path).expect("read");
        let value: serde_json::Value = serde_json::from_str(&contents).expect("parse");
        let raw = value.get("raw_evidence").and_then(|r| r.get("expected_vtxo_id"));
        let expected_str = match raw.and_then(|v| v.as_str()) {
            Some(s) if s != "COMPUTE_FROM_HEX" && s != "PLACEHOLDER" => s,
            _ => continue,
        };
        let expected_id = vpack::VtxoId::from_str(expected_str).expect("parse expected_vtxo_id");
        let ingredients_json = value
            .get("reconstruction_ingredients")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let ingredients = crate::common::second_tech_ingredients_from_json(&ingredients_json)
            .unwrap_or_else(|e| panic!("{}: ingredients_from_json: {}", path.display(), e));
        let bytes = create_vpack_second_tech(ingredients).expect("create_vpack_second_tech");
        vpack::verify(&bytes, &expected_id).expect("verify");
    }
}
