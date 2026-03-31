//! `VpackExitWaterfall`: a compact, streaming exit proof for Bark VTXO chains.
//!
//! Stores the minimum data required to verify (and partially reconstruct) the chain of
//! Bitcoin transactions from the L1 anchor down to the user's VTXO leaf:
//! - Per-hop: the MuSig2 co-signature (64 bytes), the user output index (bits 0-6 of a flags
//!   byte), an optional amount (8 bytes, omitted when equal to the previous hop), and the P2TR
//!   output x-only key (32 bytes).
//! - Dust sibling outputs are **stripped entirely**.
//!
//! ## Wire format (variable-length per hop)
//! ```text
//! anchor:    [u8; 36]   — 32-byte txid (LE) + 4-byte vout (LE)
//! hop_count: u8         — number of hops (≤ MAX_HWW_HOPS = 75)
//! hops:      N × variable_hop
//!
//! variable_hop:
//!   flags_and_idx: u8   — bit 7 = has_amount (1 → 8-byte amount follows), bits 0-6 = output_idx
//!   sig:           [u8; 64]
//!   amount:        [u8; 8]   (only when bit 7 of flags_and_idx is set)
//!   output_xonly:  [u8; 32]
//! ```
//!
//! ## Memory budget
//! - `MAX_HWW_HOPS = 75` hops (enforced — chains longer than this exceed HWW RAM).
//! - Max per-hop wire size: 105 bytes (has_amount=1: 1+64+8+32).
//! - Compressed per-hop size: 97 bytes (has_amount=0: 1+64+32).
//! - Anchor header: 37 bytes.
//! - Worst case (all amounts different): 37 + 75 × 105 = **8,912 bytes** — fits in `WATERFALL_BUF_CAPACITY`.
//! - Typical OOR (constant amount): 37 + 105 + 74 × 97 = **7,320 bytes**.

use crate::error::VPackError;
use crate::payload::tree::VPackTree;
use crate::types::hashes::Hash;

/// Maximum bytes in the compact hop buffer (8 KB).
pub const WATERFALL_BUF_CAPACITY: usize = 8_192;

/// Maximum number of hops supported on a Hardware Wallet.
///
/// Chains longer than this return [`VPackError::ExceedsHWWCapacity`] at build time.
pub const MAX_HWW_HOPS: usize = 75;

/// Per-hop in-memory record (`Copy`, 105 bytes in memory).
///
/// Contains only the data on the **user's output path** — sibling outputs are stripped.
/// Wire size is 97 or 105 bytes depending on whether the amount changed from the prior hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopData {
    /// BIP-340 Schnorr signature authorizing this hop's transaction (64 bytes).
    /// All-zero if the genesis item had no signature (e.g., the root-anchor hop).
    pub signature: [u8; 64],
    /// The vout index of the user's output in this hop's transaction (bits 0-6).
    pub output_idx: u8,
    /// Satoshi value of the user's output at this hop.
    pub amount: u64,
    /// x-only (32-byte) Taproot public key of the user's output P2TR script at this hop.
    pub output_xonly: [u8; 32],
}

impl HopData {
    /// Maximum byte size of one serialized `HopData` record (when `has_amount = 1`).
    pub const SERIALIZED_LEN: usize = 1 + 64 + 8 + 32; // = 105
}

/// Compact, streaming exit waterfall for a Bark VTXO genesis chain.
///
/// Holds a fixed-capacity byte buffer and a streaming cursor. Dust sibling outputs
/// are discarded at build time — only the user's path data is stored per hop.
/// When consecutive hops share the same amount, only the first is stored (lineage compression).
pub struct VpackExitWaterfall {
    /// 36-byte anchor outpoint: 32-byte txid (LE) + 4-byte vout (LE).
    anchor: [u8; 36],
    /// Number of hops stored in the buffer (≤ `MAX_HWW_HOPS`).
    hop_count: u8,
    /// Read cursor position within `buf`. Advances by variable hop size during `next_hop()`.
    cursor: usize,
    /// The amount decoded from the most recent `next_hop()` call; used for decompression.
    last_amount: u64,
    /// Number of valid bytes written into `buf`.
    buf_len: usize,
    /// Fixed-capacity variable-length hop buffer.
    buf: [u8; WATERFALL_BUF_CAPACITY],
}

impl VpackExitWaterfall {
    /// Build a compact waterfall from a parsed `VPackTree`.
    ///
    /// Iterates `tree.path` top-down, writes each hop's stripped record into the internal buffer
    /// using amount-delta compression, and discards all `SiblingNode` entries.
    ///
    /// Returns `ExceedsHWWCapacity` if `tree.path.len() > MAX_HWW_HOPS`.
    /// Returns `DehydrationBufferFull` if the encoded bytes exceed `WATERFALL_BUF_CAPACITY`.
    pub fn from_tree(tree: &VPackTree) -> Result<Self, VPackError> {
        let hop_count = tree.path.len();
        if hop_count > MAX_HWW_HOPS {
            return Err(VPackError::ExceedsHWWCapacity);
        }

        let anchor = outpoint_to_bytes(&tree.anchor);
        let mut buf = [0u8; WATERFALL_BUF_CAPACITY];
        let mut offset = 0usize;
        let mut prev_amount: Option<u64> = None;

        for item in &tree.path {
            let sig = item.signature.unwrap_or([0u8; 64]);
            let output_idx = (item.parent_index as u8) & 0x7f;
            let amount = item.child_amount;
            let output_xonly = extract_p2tr_xonly(&item.child_script_pubkey);

            let has_amount = prev_amount != Some(amount);
            let flags_and_idx = output_idx | if has_amount { 0x80 } else { 0x00 };

            let hop_size = 1 + 64 + if has_amount { 8 } else { 0 } + 32;
            if offset + hop_size > WATERFALL_BUF_CAPACITY {
                return Err(VPackError::DehydrationBufferFull);
            }

            buf[offset] = flags_and_idx;
            offset += 1;
            buf[offset..offset + 64].copy_from_slice(&sig);
            offset += 64;
            if has_amount {
                buf[offset..offset + 8].copy_from_slice(&amount.to_le_bytes());
                offset += 8;
                prev_amount = Some(amount);
            }
            buf[offset..offset + 32].copy_from_slice(&output_xonly);
            offset += 32;
        }

        Ok(Self {
            anchor,
            hop_count: hop_count as u8,
            cursor: 0,
            last_amount: 0,
            buf_len: offset,
            buf,
        })
    }

    /// Parse a previously-serialized waterfall from its compact byte representation.
    ///
    /// Format: `anchor(36) | hop_count(1) | variable-length hops`.
    /// Validates structure and rejects chains longer than `MAX_HWW_HOPS`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VPackError> {
        if bytes.len() < 37 {
            return Err(VPackError::IncompleteData);
        }
        let mut anchor = [0u8; 36];
        anchor.copy_from_slice(&bytes[..36]);
        let hop_count = bytes[36] as usize;
        if hop_count > MAX_HWW_HOPS {
            return Err(VPackError::ExceedsHWWCapacity);
        }

        let payload = &bytes[37..];
        let mut scan = 0usize;
        for _ in 0..hop_count {
            if scan >= payload.len() {
                return Err(VPackError::InsufficientHopData);
            }
            let has_amount = (payload[scan] & 0x80) != 0;
            scan += 1;
            let hop_body = 64 + if has_amount { 8 } else { 0 } + 32;
            if scan + hop_body > payload.len() {
                return Err(VPackError::InsufficientHopData);
            }
            scan += hop_body;
        }

        let payload_len = scan;
        if payload_len > WATERFALL_BUF_CAPACITY {
            return Err(VPackError::DehydrationBufferFull);
        }
        let mut buf = [0u8; WATERFALL_BUF_CAPACITY];
        buf[..payload_len].copy_from_slice(&payload[..payload_len]);
        Ok(Self {
            anchor,
            hop_count: hop_count as u8,
            cursor: 0,
            last_amount: 0,
            buf_len: payload_len,
            buf,
        })
    }

    /// Serialize this waterfall into a compact byte vector.
    ///
    /// Format: `anchor(36) | hop_count(1) | variable-length hops`.
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(37 + self.buf_len);
        out.extend_from_slice(&self.anchor);
        out.push(self.hop_count);
        out.extend_from_slice(&self.buf[..self.buf_len]);
        out
    }

    /// The L1 anchor outpoint: 32-byte txid + 4-byte vout (little-endian).
    pub fn anchor_outpoint(&self) -> &[u8; 36] {
        &self.anchor
    }

    /// Number of hop records stored in this waterfall.
    pub fn hop_count(&self) -> usize {
        self.hop_count as usize
    }

    /// Total serialized byte length: `37 + encoded hop bytes`.
    pub fn serialized_size(&self) -> usize {
        37 + self.buf_len
    }

    /// Stream the next hop record from the waterfall, advancing the internal cursor.
    ///
    /// When `has_amount` is not set in the flags byte, the amount from the previous hop is
    /// repeated (lineage decompression). Returns `None` when all hops have been consumed.
    /// Call `reset()` to restart iteration.
    pub fn next_hop(&mut self) -> Option<HopData> {
        if self.cursor >= self.buf_len {
            return None;
        }

        let flags_and_idx = self.buf[self.cursor];
        self.cursor += 1;

        let has_amount = (flags_and_idx & 0x80) != 0;
        let output_idx = flags_and_idx & 0x7f;

        if self.cursor + 64 > self.buf_len {
            return None;
        }
        let signature: [u8; 64] = self.buf[self.cursor..self.cursor + 64].try_into().ok()?;
        self.cursor += 64;

        let amount = if has_amount {
            if self.cursor + 8 > self.buf_len {
                return None;
            }
            let a = u64::from_le_bytes(self.buf[self.cursor..self.cursor + 8].try_into().ok()?);
            self.cursor += 8;
            self.last_amount = a;
            a
        } else {
            self.last_amount
        };

        if self.cursor + 32 > self.buf_len {
            return None;
        }
        let output_xonly: [u8; 32] = self.buf[self.cursor..self.cursor + 32].try_into().ok()?;
        self.cursor += 32;

        Some(HopData {
            signature,
            output_idx,
            amount,
            output_xonly,
        })
    }

    /// Reset the streaming cursor to the beginning.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.last_amount = 0;
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn outpoint_to_bytes(op: &crate::types::OutPoint) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&op.txid.to_byte_array());
    buf[32..36].copy_from_slice(&op.vout.to_le_bytes());
    buf
}

/// Extract the 32-byte x-only key from a 34-byte P2TR script (`OP_1 OP_PUSHBYTES_32 <key>`).
/// Returns `[0u8; 32]` for any other encoding.
fn extract_p2tr_xonly(script: &[u8]) -> [u8; 32] {
    if script.len() == 34 && script[0] == 0x51 && script[1] == 0x20 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&script[2..34]);
        key
    } else {
        [0u8; 32]
    }
}
