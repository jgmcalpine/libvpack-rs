//! Unified identity model and consensus abstraction.
//!
//! Accommodates **Transaction-Native** (Ark Labs: raw 32-byte hash) and
//! **Object-Native** (Second Tech: OutPoint Hash:Index) identity philosophies.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::types::{hashes::sha256d, hashes::Hash, OutPoint, Txid};

use crate::error::VPackError;
use crate::payload::tree::VPackTree;

pub mod ark_labs;
pub mod completeness;
pub mod second_tech;
pub mod taproot;
pub mod timelocks;
pub mod tx_factory;

pub use completeness::{validate_exit_ready_completeness, validate_tree_completeness};
pub use timelocks::validate_timelocks;

#[cfg(feature = "schnorr-verify")]
pub mod taproot_sighash;

#[cfg(feature = "bitcoin")]
pub mod control_block;

#[cfg(feature = "bitcoin")]
pub use control_block::{reconstruct_control_block, verify_control_block};

pub use ark_labs::compute_ark_labs_merkle_root;
pub use ark_labs::ArkLabsV3;
pub use second_tech::compute_bark_merkle_root;
pub use second_tech::compute_bark_vtxo_tapscript_root;
pub use second_tech::SecondTechV3;
pub use tx_factory::{tx_preimage, tx_signed_hex, TxInPreimage, TxOutPreimage};

/// Conservation-of-value failure with summed output totals for auditing.
pub(crate) fn value_mismatch_for_output_sum(
    expected: u64,
    outputs: &[TxOutPreimage<'_>],
) -> VPackError {
    let actual = match outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
    {
        Some(s) => s,
        None => {
            let total: u128 = outputs.iter().map(|o| o.value as u128).sum();
            u64::try_from(total).unwrap_or(u64::MAX)
        }
    };
    VPackError::ValueMismatch { expected, actual }
}

// -----------------------------------------------------------------------------
// VtxoId
// -----------------------------------------------------------------------------

/// Unified VTXO identifier: raw hash (Variant 0x04 / Ark Labs) or OutPoint (Variant 0x03 / Second Tech).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtxoId {
    /// Transaction-native: raw 32-byte hash (Variant 0x04).
    Raw([u8; 32]),
    /// Object-native: OutPoint as Hash:Index (Variant 0x03).
    OutPoint(OutPoint),
}

/// 32-byte slice for [`crate::error::VPackError::IdMismatch`] diagnostics (internal wire order).
///
/// [`VtxoId::Raw`] returns the raw hash bytes. [`VtxoId::OutPoint`] returns the **txid only**
/// (pair with [`vtxo_id_mismatch_diagnostic_vout`] for the full Second Tech identity).
pub fn vtxo_id_mismatch_diagnostic_bytes(id: &VtxoId) -> [u8; 32] {
    match id {
        VtxoId::Raw(b) => *b,
        VtxoId::OutPoint(op) => op.txid.to_byte_array(),
    }
}

/// vout for [`crate::error::VPackError::IdMismatch`] when the ID is [`VtxoId::OutPoint`]; else `None`.
pub fn vtxo_id_mismatch_diagnostic_vout(id: &VtxoId) -> Option<u32> {
    match id {
        VtxoId::Raw(_) => None,
        VtxoId::OutPoint(op) => Some(op.vout),
    }
}

impl fmt::Display for VtxoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtxoId::Raw(bytes) => {
                for b in bytes.iter().rev() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            VtxoId::OutPoint(op) => {
                let txid_bytes = op.txid.to_byte_array();
                for b in txid_bytes.iter().rev() {
                    write!(f, "{:02x}", b)?;
                }
                write!(f, ":{}", op.vout)
            }
        }
    }
}

impl FromStr for VtxoId {
    type Err = VPackError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(colon_pos) = s.find(':') {
            let (hash_part, index_part) = s.split_at(colon_pos);
            let index_part = index_part.trim_start_matches(':');
            let hash_bytes = decode_hex_32(hash_part)?;
            let vout = index_part
                .parse::<u32>()
                .map_err(|_| VPackError::InvalidVtxoIdFormat)?;
            let mut internal = hash_bytes;
            internal.reverse();
            let txid = Txid::from_byte_array(internal);
            Ok(VtxoId::OutPoint(OutPoint { txid, vout }))
        } else {
            let mut bytes = decode_hex_32(s)?;
            bytes.reverse();
            Ok(VtxoId::Raw(bytes))
        }
    }
}

/// Decode exactly 64 hex chars into 32 bytes. No leading 0x. Fails on wrong length or non-hex.
fn decode_hex_32(s: &str) -> Result<[u8; 32], VPackError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(VPackError::InvalidVtxoIdFormat);
    }
    let mut out = [0u8; 32];
    let mut chars = s.chars();
    for byte in out.iter_mut() {
        let hi = chars
            .next()
            .and_then(hex_digit)
            .ok_or(VPackError::InvalidVtxoIdFormat)?;
        let lo = chars
            .next()
            .and_then(hex_digit)
            .ok_or(VPackError::InvalidVtxoIdFormat)?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Canonical Sibling Identity (Birth tx TxID)
// -----------------------------------------------------------------------------

/// Computes the TxID of the canonical 1-in-1-out "Birth" transaction for a sibling.
/// Used to verify the `hash` field in `SiblingNode::Compact` per V-BIP-01.
/// Canonical input: prev_out_txid = [0u8; 32], prev_out_vout = 0, sequence = 0.
pub fn hash_sibling_birth_tx(value: u64, script: &[u8]) -> [u8; 32] {
    let input = TxInPreimage {
        prev_out_txid: [0u8; 32],
        prev_out_vout: 0,
        sequence: 0,
    };
    let output = TxOutPreimage {
        value,
        script_pubkey: script,
    };
    let preimage = tx_preimage(3, &[input], &[output], 0);
    let hash = sha256d::Hash::hash(&preimage);
    hash.to_byte_array()
}

// -----------------------------------------------------------------------------
// VerificationOutput
// -----------------------------------------------------------------------------

/// Result of consensus verification: the VTXO ID and the signed transaction hexes (path witnesses).
#[derive(Debug, Clone)]
pub struct VerificationOutput {
    /// The computed VTXO ID.
    pub id: VtxoId,
    /// Signed transaction hexes ("Live Bullets") — anchor-spend first, leaf-spend last.
    pub signed_txs: Vec<Vec<u8>>,
}

// -----------------------------------------------------------------------------
// ConsensusEngine
// -----------------------------------------------------------------------------

/// Rosetta Stone for Ark verification: maps a parsed tree to a VTXO ID and verifies it.
pub trait ConsensusEngine {
    /// Compute the VTXO ID from the tree (variant-specific logic).
    /// When `anchor_value` is `Some(v)`, conservation of value is enforced during the walk.
    fn compute_vtxo_id(
        &self,
        tree: &VPackTree,
        anchor_value: Option<u64>,
    ) -> Result<VerificationOutput, VPackError>;

    /// Verify that the tree yields the expected VTXO ID with conservation of value.
    fn verify(
        &self,
        tree: &VPackTree,
        expected: &VtxoId,
        anchor_value: u64,
    ) -> Result<(), VPackError> {
        let computed = self.compute_vtxo_id(tree, Some(anchor_value))?;
        if computed.id == *expected {
            Ok(())
        } else {
            Err(VPackError::IdMismatch {
                computed: vtxo_id_mismatch_diagnostic_bytes(&computed.id),
                expected: vtxo_id_mismatch_diagnostic_bytes(expected),
                computed_vout: vtxo_id_mismatch_diagnostic_vout(&computed.id),
                expected_vout: vtxo_id_mismatch_diagnostic_vout(expected),
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Path Exclusivity Verification
// -----------------------------------------------------------------------------

/// P2TR scriptPubKey prefix: OP_1 (0x51) OP_PUSHBYTES_32 (0x20).
const P2TR_PREFIX: [u8; 2] = [0x51, 0x20];

#[cfg(feature = "schnorr-verify")]
fn p2tr_embedded_xonly_key(script: &[u8]) -> [u8; 32] {
    if script.len() == 34 && script[..2] == P2TR_PREFIX {
        let mut k = [0u8; 32];
        k.copy_from_slice(&script[2..34]);
        k
    } else {
        [0u8; 32]
    }
}

/// Zero-trust verification that the VTXO leaf's Taproot tree contains only the
/// expected spend paths. Recomputes the Merkle root from `asp_expiry_script`,
/// tweaks the `internal_key`, and asserts the result matches the x-only key
/// embedded in the leaf's P2TR `script_pubkey`.
///
/// This makes it mathematically impossible for an ASP to construct a V-PACK
/// with hidden spend paths without libvpack-rs flagging it as invalid.
#[cfg(feature = "schnorr-verify")]
pub fn verify_path_exclusivity(
    tree: &VPackTree,
    variant: crate::header::TxVariant,
) -> Result<(), VPackError> {
    if tree.asp_expiry_script.is_empty() {
        return Err(VPackError::MissingExclusivityData);
    }

    let merkle_root = match variant {
        crate::header::TxVariant::V3Anchored => {
            compute_ark_labs_merkle_root(tree).ok_or(VPackError::InvalidArkLabsScript)?
        }
        crate::header::TxVariant::V3Plain => compute_bark_merkle_root(tree)?,
    };

    let expected_from_script = p2tr_embedded_xonly_key(&tree.leaf.script_pubkey);

    let derived_key = match taproot::compute_taproot_tweak(tree.internal_key, merkle_root) {
        Some(k) => k,
        None => {
            return Err(VPackError::PathExclusivityViolation {
                derived_key: [0u8; 32],
                expected_key: expected_from_script,
            });
        }
    };

    let script = &tree.leaf.script_pubkey;
    if script.len() != 34 || script[..2] != P2TR_PREFIX {
        return Err(VPackError::PathExclusivityViolation {
            derived_key,
            expected_key: expected_from_script,
        });
    }
    let mut expected_key = [0u8; 32];
    expected_key.copy_from_slice(&script[2..34]);

    if derived_key != expected_key {
        return Err(VPackError::PathExclusivityViolation {
            derived_key,
            expected_key,
        });
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests: Verification Gate (VtxoId parsing)
// -----------------------------------------------------------------------------
//
// Both Raw (Ark Labs) and OutPoint (Second Tech) use the Bitcoin TxID convention:
// human-readable strings are in reverse byte order. We store internal order;
// Display reverses for output, FromStr reverses parsed bytes for storage.

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn vtxo_id_parse_ark_labs_raw_hex() {
        // Ark Labs (Variant 0x04): Raw ID is a Bitcoin TxID; string is display order (reversed).
        let s = "0b3803bb6bc9a886bbbf0d935248399b3b7a7bd226c730096c8e6a06818922a3";
        let id = VtxoId::from_str(s).expect("parse Ark Labs raw hex");
        let display_order: [u8; 32] = [
            0x0b, 0x38, 0x03, 0xbb, 0x6b, 0xc9, 0xa8, 0x86, 0xbb, 0xbf, 0x0d, 0x93, 0x52, 0x48,
            0x39, 0x9b, 0x3b, 0x7a, 0x7b, 0xd2, 0x26, 0xc7, 0x30, 0x09, 0x6c, 0x8e, 0x6a, 0x06,
            0x81, 0x89, 0x22, 0xa3,
        ];
        let mut internal = display_order;
        internal.reverse();
        match &id {
            VtxoId::Raw(b) => assert_eq!(
                b, &internal,
                "Raw stores internal (reversed) byte order to match Bitcoin TxID convention"
            ),
            VtxoId::OutPoint(_) => panic!("expected Raw variant"),
        }
        assert_eq!(
            format!("{}", id),
            s,
            "Display round-trip: internal bytes reversed for human-readable string"
        );
    }

    #[test]
    fn vtxo_id_parse_second_tech_outpoint() {
        // Second Tech (Variant 0x03): OutPoint Hash:Index; Hash is same Bitcoin display convention.
        let s = "c806f5fc2cf7a5b0e8e2fa46cc9e0c7a511f43144f9d27f85a9108e4b8c4d662:0";
        let id = VtxoId::from_str(s).expect("parse Second Tech Hash:Index");
        match &id {
            VtxoId::Raw(_) => panic!("expected OutPoint variant"),
            VtxoId::OutPoint(op) => {
                assert_eq!(op.vout, 0, "vout must be 0");
            }
        }
        assert_eq!(format!("{}", id), s, "Display round-trip");
    }
}
