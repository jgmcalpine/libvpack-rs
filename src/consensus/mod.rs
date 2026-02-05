//! Unified identity model and consensus abstraction.
//!
//! Accommodates **Transaction-Native** (Ark Labs: raw 32-byte hash) and
//! **Object-Native** (Second Tech: OutPoint Hash:Index) identity philosophies.

use core::fmt;
use core::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::Txid;

use crate::error::VPackError;
use crate::payload::tree::VPackTree;

pub mod tx_factory;
pub mod ark_labs;

pub use tx_factory::{tx_preimage, TxInPreimage, TxOutPreimage};
pub use ark_labs::ArkLabsV3;

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
        let hi = chars.next().and_then(hex_digit).ok_or(VPackError::InvalidVtxoIdFormat)?;
        let lo = chars.next().and_then(hex_digit).ok_or(VPackError::InvalidVtxoIdFormat)?;
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
// ConsensusEngine
// -----------------------------------------------------------------------------

/// Rosetta Stone for Ark verification: maps a parsed tree to a VTXO ID and verifies it.
pub trait ConsensusEngine {
    /// Compute the VTXO ID from the tree (variant-specific logic not implemented here).
    fn compute_vtxo_id(&self, tree: &VPackTree) -> Result<VtxoId, VPackError>;

    /// Verify that the tree yields the expected VTXO ID. Default: compute and compare.
    fn verify(&self, tree: &VPackTree, expected: &VtxoId) -> Result<(), VPackError> {
        let computed = self.compute_vtxo_id(tree)?;
        if computed == *expected {
            Ok(())
        } else {
            Err(VPackError::IdMismatch)
        }
    }
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
    use alloc::format;
    use super::*;

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
            VtxoId::Raw(b) => assert_eq!(b, &internal, "Raw stores internal (reversed) byte order to match Bitcoin TxID convention"),
            VtxoId::OutPoint(_) => panic!("expected Raw variant"),
        }
        assert_eq!(format!("{}", id), s, "Display round-trip: internal bytes reversed for human-readable string");
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
