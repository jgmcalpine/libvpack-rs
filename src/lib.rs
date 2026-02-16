#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

// Needed for Vec
extern crate alloc;

pub mod adapters;
pub mod compact_size;
pub mod consensus;
pub mod error;
pub mod export;
pub mod header;
pub mod pack;
pub mod payload;

#[cfg(any(feature = "bitcoin", feature = "wasm"))]
pub mod types;

#[cfg(any(feature = "adapter", feature = "wasm"))]
pub mod ingredients;

#[cfg(any(feature = "adapter", feature = "wasm"))]
pub use ingredients::{tree_from_ingredients, ArkLabsAdapter, LogicAdapter, SecondTechAdapter};

pub use consensus::{ArkLabsV3, ConsensusEngine, SecondTechV3, VerificationOutput, VtxoId};
pub use export::{
    create_vpack_ark_labs, create_vpack_from_tree, create_vpack_second_tech, ArkLabsIngredients,
    ArkLabsOutput, ArkLabsSibling, SecondTechGenesisStep, SecondTechIngredients, SecondTechSibling,
};
pub use header::TxVariant;
pub use payload::tree::VPackTree;

use crate::error::VPackError;
use crate::header::{Header, HEADER_SIZE};
use crate::payload::reader::BoundedReader;

/// Verifies a V-PACK byte array against an expected VTXO ID with conservation of value.
///
/// # Arguments
/// * `vpack_bytes` - Complete V-PACK byte array. The first 24 bytes must be the header.
/// * `expected_id` - The expected VTXO ID to verify against.
/// * `anchor_value` - Value (in satoshis) of the L1 UTXO that anchors the tree.
///
/// # Returns
/// * `Ok(VPackTree)` - Verification succeeded, returns the parsed tree
/// * `Err(VPackError)` - Verification failed (checksum, parsing, ID mismatch, or ValueMismatch)
pub fn verify(
    vpack_bytes: &[u8],
    expected_id: &VtxoId,
    anchor_value: u64,
) -> Result<VPackTree, VPackError> {
    // Step 1: Parse Header (first 24 bytes)
    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])?;

    // Step 2: Extract Payload
    let payload = &vpack_bytes[HEADER_SIZE..];

    // Step 3: Verify Checksum
    header.verify_checksum(payload)?;

    // Step 4: Parse Payload
    let tree = BoundedReader::parse(&header, payload)?;

    // Step 5: Validate global policy invariants (fee_anchor, sequence consistency)
    crate::payload::validate_invariants(&header, &tree)?;

    // Step 6: Dispatch by Variant and Verify (only 0x03 and 0x04 are valid per TxVariant::try_from)
    match header.tx_variant {
        crate::header::TxVariant::V3Anchored => {
            let engine = crate::consensus::ArkLabsV3;
            engine.verify(&tree, expected_id, anchor_value)?;
        }
        crate::header::TxVariant::V3Plain => {
            let engine = crate::consensus::SecondTechV3;
            engine.verify(&tree, expected_id, anchor_value)?;
        }
    }

    // Step 7: Return the parsed tree
    Ok(tree)
}

/// Test-only: compute the VTXO ID that would be verified for this V-PACK. Used to fill expected_vtxo_id in vectors.
/// Does not perform conservation-of-value checks (anchor_value is None).
#[cfg(feature = "std")]
pub fn compute_vtxo_id_from_bytes(vpack_bytes: &[u8]) -> Result<VtxoId, VPackError> {
    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])?;
    header.verify_checksum(&vpack_bytes[HEADER_SIZE..])?;
    let tree = BoundedReader::parse(&header, &vpack_bytes[HEADER_SIZE..])?;
    match header.tx_variant {
        crate::header::TxVariant::V3Anchored => crate::consensus::ArkLabsV3
            .compute_vtxo_id(&tree, None)
            .map(|o| o.id),
        crate::header::TxVariant::V3Plain => crate::consensus::SecondTechV3
            .compute_vtxo_id(&tree, None)
            .map(|o| o.id),
    }
}

/// Tests that mirror wasm_verify: auto-inference over ArkLabs then SecondTech, create_vpack_from_tree + verify.
#[cfg(all(test, feature = "adapter"))]
mod wasm_auto_inference_test {
    use core::str::FromStr;
    use std::string::{String, ToString};

    use crate::{
        create_vpack_from_tree, verify, ArkLabsAdapter, ArkLabsV3, ConsensusEngine, LogicAdapter,
        SecondTechAdapter, SecondTechV3, TxVariant, VtxoId,
    };

    fn run_auto_inference(json_path: &str) -> Result<(String, String), String> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?;
        let path = std::path::Path::new(&manifest_dir).join(json_path);
        let contents = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let value: serde_json::Value =
            serde_json::from_str(&contents).map_err(|e| e.to_string())?;

        let expected_id_str = value["raw_evidence"]["expected_vtxo_id"]
            .as_str()
            .ok_or("missing expected_vtxo_id")?;
        let expected_id = VtxoId::from_str(expected_id_str)
            .map_err(|_| "invalid expected_vtxo_id".to_string())?;
        let ri = value
            .get("reconstruction_ingredients")
            .ok_or("missing reconstruction_ingredients")?;

        if let Ok(tree) = ArkLabsAdapter::map_ingredients(ri) {
            let bytes = create_vpack_from_tree(&tree, TxVariant::V3Anchored, false)
                .map_err(|e| e.to_string())?;
            let anchor_value = value["anchor_value"].as_u64().unwrap_or(1100u64);
            verify(&bytes, &expected_id, anchor_value).map_err(|e| e.to_string())?;
            let output = ArkLabsV3
                .compute_vtxo_id(&tree, None)
                .map_err(|e| e.to_string())?;
            return Ok(("0x04".into(), output.id.to_string()));
        }

        if let Ok(tree) = SecondTechAdapter::map_ingredients(ri) {
            let bytes = create_vpack_from_tree(&tree, TxVariant::V3Plain, false)
                .map_err(|e| e.to_string())?;
            let anchor_value = value["anchor_value"].as_u64().unwrap_or(10_000u64);
            verify(&bytes, &expected_id, anchor_value).map_err(|e| e.to_string())?;
            let output = SecondTechV3
                .compute_vtxo_id(&tree, None)
                .map_err(|e| e.to_string())?;
            return Ok(("0x03".into(), output.id.to_string()));
        }

        Err("no adapter matched or verification failed".to_string())
    }

    #[test]
    fn wasm_verify_auto_inference_ark_labs_round_leaf_v3() {
        let (variant, _tx_id) =
            run_auto_inference("tests/conformance/vectors/ark_labs/round_leaf_v3.json")
                .expect("ark_labs round_leaf_v3 should verify");
        assert_eq!(variant, "0x04");
    }

    #[test]
    fn wasm_verify_auto_inference_second_round_v3_borsh() {
        let (variant, _tx_id) =
            run_auto_inference("tests/conformance/vectors/second/round_v3_borsh.json")
                .expect("second round_v3_borsh should verify");
        assert_eq!(variant, "0x03");
    }
}
