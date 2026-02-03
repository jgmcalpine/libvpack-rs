// Conformance tests: audit-format vectors (meta.variant, raw_evidence.borsh_hex, etc.)
// Uses vpack::pack_from_payload to build V-PACK bytes, then parses and asserts.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use vpack::header::{Header, TxVariant, HEADER_SIZE};
use vpack::pack::pack_from_payload;
use vpack::payload::reader::BoundedReader;

#[derive(Debug, Deserialize)]
struct AuditVector {
    meta: AuditMeta,
    raw_evidence: RawEvidence,
    #[serde(default)]
    reconstruction_ingredients: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AuditMeta {
    variant: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    borsh_hex: Option<String>,
    #[allow(dead_code)]
    expected_vtxo_id: Option<String>,
}

fn variant_from_meta(s: &str) -> TxVariant {
    match s.trim() {
        "0x03" => TxVariant::V3Plain,
        "0x04" => TxVariant::V3Anchored,
        _ => TxVariant::V3Plain,
    }
}

/// Build prefix: no asset_id, anchor (36 bytes), fee_anchor_script (Borsh Vec<u8>).
fn build_prefix(anchor_zeros: bool, fee_anchor_script: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if anchor_zeros {
        out.extend_from_slice(&[0u8; 36]);
    }
    let len = fee_anchor_script.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(fee_anchor_script);
    out
}

#[test]
fn run_conformance_vectors() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_root = manifest_dir.join("tests/conformance/vectors");

    for subdir in ["ark_labs", "second"] {
        let dir = vectors_root.join(subdir);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).expect("read vectors dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.extension().map(|e| e.to_str()) == Some(Some("json")) {
                run_audit_vector(&path);
            }
        }
    }
}

fn run_audit_vector(path: &Path) {
    let contents = fs::read_to_string(path).expect("read JSON");
    let vector: AuditVector = serde_json::from_str(&contents).expect("parse audit JSON");

    let Some(ref borsh_hex) = vector.raw_evidence.borsh_hex else {
        // Ark vectors without borsh_hex: only load and validate JSON presence
        return;
    };

    let tree_bytes = hex::decode(borsh_hex).expect("decode borsh_hex");

    let tx_variant = variant_from_meta(&vector.meta.variant);
    let fee_script: Vec<u8> = match tx_variant {
        TxVariant::V3Anchored => vec![0x51, 0x02, 0x4e, 0x73],
        TxVariant::V3Plain => vec![],
    };
    let prefix = build_prefix(true, &fee_script);

    let mut payload = prefix;
    payload.extend_from_slice(&tree_bytes);

    let header = Header {
        flags: 0,
        version: 1,
        tx_variant,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };

    let full_bytes = pack_from_payload(&header, &payload).expect("pack_from_payload");

    let parsed_header = Header::from_bytes(&full_bytes[..HEADER_SIZE]).expect("parse header");
    assert_eq!(parsed_header.tx_variant, header.tx_variant);

    let payload_slice = &full_bytes[HEADER_SIZE..];
    let tree = BoundedReader::parse(&parsed_header, payload_slice).expect("parse payload");
    assert!(
        !tree.leaf.script_pubkey.is_empty() || tree.leaf.amount > 0,
        "leaf should have script_pubkey or amount"
    );
}
