//! BIP-341 script-path control block reconstruction and witness completeness checks.
//!
//! Requires the `bitcoin` feature (rust-secp256k1). This is **not** BIP-340 signature verification;
//! it is script-tree hashing and output-key tweaking only.

use alloc::vec::Vec;

use crate::consensus::taproot::{
    self, balanced_merkle_sibling_path, compute_balanced_merkle_root, TAPLEAF_VERSION,
};
use crate::error::VPackError;
use crate::header::TxVariant;
use crate::payload::tree::VPackTree;

/// P2TR scriptPubKey prefix: OP_1 (0x51) OP_PUSHBYTES_32 (0x20).
const P2TR_PREFIX: [u8; 2] = [0x51, 0x20];

fn p2tr_output_xonly(tree: &VPackTree) -> Result<[u8; 32], VPackError> {
    let script = &tree.leaf.script_pubkey;
    if script.len() != 34 || script[..2] != P2TR_PREFIX {
        return Err(VPackError::ControlBlockReconstructionFailed);
    }
    script[2..34]
        .try_into()
        .map_err(|_| VPackError::ControlBlockReconstructionFailed)
}

fn assemble_control_block(
    internal_key: &[u8; 32],
    merkle_path: &[[u8; 32]],
    parity: u8,
) -> Vec<u8> {
    let control_byte = (TAPLEAF_VERSION & 0xfe) | (parity & 1);
    let mut out = Vec::with_capacity(33 + 32 * merkle_path.len());
    out.push(control_byte);
    out.extend_from_slice(internal_key);
    for h in merkle_path {
        out.extend_from_slice(h);
    }
    out
}

fn try_reconstruct_with_hashes(
    tree: &VPackTree,
    expected_output: &[u8; 32],
    hashes: &[[u8; 32]],
    leaf_idx: usize,
) -> Option<Vec<u8>> {
    let merkle_root = compute_balanced_merkle_root(hashes)?;
    let (x_only, parity) =
        taproot::compute_taproot_tweaked_key_x_and_parity(tree.internal_key, merkle_root)?;
    if x_only != *expected_output {
        return None;
    }
    let path = balanced_merkle_sibling_path(hashes, leaf_idx)?;
    Some(assemble_control_block(&tree.internal_key, &path, parity))
}

/// Reconstructs the raw BIP-341 control block for the spend path that uses `tree.asp_expiry_script`,
/// ordered bottom-up: `[control_byte || internal_key || merkle_path…]`.
///
/// `variant` selects the Taproot leaf construction rules (`TxVariant::V3Anchored` → Ark Labs;
/// `TxVariant::V3Plain` → Bark). The caller **must** pass the same variant as the V-PACK header;
/// the library does not infer it from script shape.
///
/// Requires a valid P2TR `script_pubkey` on the leaf that matches the tweaked key derived from
/// `internal_key` and the computed Merkle root.
pub fn reconstruct_control_block(
    tree: &VPackTree,
    variant: TxVariant,
) -> Result<Vec<u8>, VPackError> {
    if tree.asp_expiry_script.is_empty() {
        return Err(VPackError::MissingExclusivityData);
    }
    let expected = p2tr_output_xonly(tree)?;

    let (hashes, leaf_idx) = match variant {
        TxVariant::V3Anchored => {
            crate::consensus::ark_labs::ark_labs_tap_leaf_hashes_for_merkle_path(tree)
                .ok_or(VPackError::ControlBlockReconstructionFailed)?
        }
        TxVariant::V3Plain => {
            crate::consensus::second_tech::bark_tap_leaf_hashes_for_merkle_path(tree)?
        }
    };

    try_reconstruct_with_hashes(tree, &expected, &hashes, leaf_idx)
        .ok_or(VPackError::ControlBlockReconstructionFailed)
}

/// Verifies a BIP-341 control block against a tapscript leaf and expected tweaked x-only output key.
///
/// `leaf_script` must be the exact script bytes committed in the TapLeaf hash (for Bark expiry,
/// use the canonical script from [`crate::consensus::second_tech::compile_bark_expiry_script`] after
/// parsing `asp_expiry_script`).
pub fn verify_control_block(
    control_block: &[u8],
    leaf_script: &[u8],
    expected_output_key: &[u8; 32],
) -> bool {
    if control_block.len() < 33 {
        return false;
    }
    let path_len = control_block.len() - 33;
    if !path_len.is_multiple_of(32) {
        return false;
    }

    let control_byte = control_block[0];
    let leaf_version = control_byte & 0xfe;
    let expected_parity = control_byte & 1;

    let mut internal_key = [0u8; 32];
    internal_key.copy_from_slice(&control_block[1..33]);

    let mut current = taproot::tap_leaf_hash_with_version(leaf_version, leaf_script);
    let mut offset = 33;
    while offset < control_block.len() {
        let mut sib = [0u8; 32];
        sib.copy_from_slice(&control_block[offset..offset + 32]);
        current = taproot::tap_branch_hash(current, sib);
        offset += 32;
    }

    let Some((x_only, parity)) =
        taproot::compute_taproot_tweaked_key_x_and_parity(internal_key, current)
    else {
        return false;
    };

    x_only == *expected_output_key && parity == expected_parity
}
