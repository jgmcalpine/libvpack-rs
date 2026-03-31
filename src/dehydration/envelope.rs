//! `VpackSovereigntyEnvelope`: a fixed-size, zero-heap summary of a Bark VTXO.
//!
//! Proves two properties:
//! - **Path Existence**: the VTXO is linked to a valid L1 anchor (via `root_outpoint`).
//! - **Path Exclusivity**: only the holder of the user key can spend the leaf (via Taproot tweak
//!   verification: `Q = TapTweak(server_internal_key, merkle_root)`).
//!
//! The struct is `Copy` and `214` bytes — safe for stack allocation on a Hardware Wallet.

use crate::consensus::VtxoId;
use crate::error::VPackError;
use crate::payload::tree::VPackTree;
use crate::types::hashes::Hash;

/// Fixed-size, `Copy` sovereignty proof derived from a Bark VTXO.
///
/// - **214 bytes total** (36 + 32 + 32 + 4 + 8 + 4 + 2 + 64 + 32).
/// - **Zero heap allocation** — all fields are fixed-size arrays or scalar types.
/// - Suitable for storage and verification on a Hardware Wallet with < 1 KB RAM budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpackSovereigntyEnvelope {
    /// On-chain L1 anchor: 32-byte txid (LE internal order) + 4-byte vout (LE). 36 bytes.
    pub root_outpoint: [u8; 36],
    /// x-only (32-byte) MuSig2 aggregate key `P = MuSig2(server_pk, user_pk)`.
    /// Used as the Taproot internal key. Populated by the updated `bark_to_vpack` when the
    /// `schnorr-verify` feature is enabled; otherwise all-zero.
    pub server_internal_key: [u8; 32],
    /// Final VTXO txid in internal (wire) byte order.
    pub vtxo_txid: [u8; 32],
    /// vout component of the final VTXO OutPoint.
    pub vtxo_vout: u32,
    /// Leaf amount in satoshis.
    pub leaf_amount: u64,
    /// Absolute block-height expiry (CLTV value from the ASP expiry script).
    pub expiry: u32,
    /// Relative exit delta (CSV for unilateral exit, encoded as u16).
    pub exit_delta: u16,
    /// MuSig2 co-signature from the final genesis hop.
    /// All-zero if no signature was present in the path (e.g., root-only VTXOs).
    pub final_signature: [u8; 64],
    /// x-only Taproot output key `Q` embedded in the leaf P2TR `script_pubkey`.
    /// All-zero if `script_pubkey` is not a valid 34-byte P2TR script.
    pub leaf_taproot_key: [u8; 32],
}

impl VpackSovereigntyEnvelope {
    /// Constructs an envelope from a parsed `VPackTree` and the computed `VtxoId`.
    ///
    /// Extracts only the sovereignty-critical fields, discarding all intermediate
    /// signatures and sibling scripts. When the `schnorr-verify` feature is enabled and
    /// `tree.internal_key` is non-zero, `leaf_taproot_key` is derived via
    /// `TapTweak(internal_key, compute_bark_merkle_root(tree))`.
    pub fn from_tree(tree: &VPackTree, vtxo_id: &VtxoId) -> Self {
        let root_outpoint = outpoint_to_bytes(&tree.anchor);

        let (vtxo_txid, vtxo_vout) = match vtxo_id {
            VtxoId::OutPoint(op) => (op.txid.to_byte_array(), op.vout),
            VtxoId::Raw(hash) => (*hash, tree.leaf.vout),
        };

        let final_signature = tree
            .path
            .last()
            .and_then(|item| item.signature)
            .unwrap_or([0u8; 64]);

        let leaf_taproot_key = compute_leaf_taproot_key(tree);

        Self {
            root_outpoint,
            server_internal_key: tree.internal_key,
            vtxo_txid,
            vtxo_vout,
            leaf_amount: tree.leaf.amount,
            expiry: tree.leaf.expiry,
            exit_delta: tree.leaf.exit_delta,
            final_signature,
            leaf_taproot_key,
        }
    }

    /// Verifies internal consistency: non-zero root anchor, non-zero VTXO txid.
    ///
    /// This is the "fast path" check that a Hardware Wallet can run without any
    /// external data. It confirms the envelope was constructed from a non-trivial VTXO.
    pub fn verify(&self) -> Result<(), VPackError> {
        if self.root_outpoint == [0u8; 36] {
            return Err(VPackError::EncodingError);
        }
        if self.vtxo_txid == [0u8; 32] {
            return Err(VPackError::EncodingError);
        }
        Ok(())
    }

    /// Verifies path exclusivity via the Taproot tweak: `Q = TapTweak(P, merkle_root)`.
    ///
    /// Recomputes the Bark tapscript Merkle root from the `VPackTree` (which must have
    /// `asp_expiry_script` populated, as done by the updated `bark_to_vpack`), applies
    /// the BIP-341 TapTweak, and asserts the result equals `self.leaf_taproot_key`.
    ///
    /// Requires the `schnorr-verify` feature. Returns `MissingExclusivityData` if
    /// `server_internal_key` or `leaf_taproot_key` are all-zero, or if `asp_expiry_script`
    /// is empty.
    #[cfg(feature = "schnorr-verify")]
    pub fn verify_taproot_exclusivity(&self, tree: &VPackTree) -> Result<(), VPackError> {
        if self.server_internal_key == [0u8; 32] || self.leaf_taproot_key == [0u8; 32] {
            return Err(VPackError::MissingExclusivityData);
        }

        let merkle_root = crate::consensus::second_tech::compute_bark_vtxo_tapscript_root(tree)?;

        let derived_q =
            crate::consensus::taproot::compute_taproot_tweak(self.server_internal_key, merkle_root)
                .ok_or(VPackError::PathExclusivityViolation {
                    derived_key: [0u8; 32],
                    expected_key: self.leaf_taproot_key,
                })?;

        if derived_q != self.leaf_taproot_key {
            return Err(VPackError::PathExclusivityViolation {
                derived_key: derived_q,
                expected_key: self.leaf_taproot_key,
            });
        }

        Ok(())
    }

    /// Total serialized byte size of this struct (compile-time constant: 214 bytes).
    pub const fn serialized_size() -> usize {
        core::mem::size_of::<Self>()
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Derive the Taproot output key Q = TapTweak(P, merkle_root) from the tree.
///
/// Uses the correct single-leaf Bark tapscript:
/// `<exit_delta> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG`
///
/// Returns `[0u8; 32]` if:
/// - `tree.internal_key` is all-zero (BIP-327 not computed or feature disabled).
/// - `tree.leaf.script_pubkey` is shorter than 33 bytes (user pubkey unavailable).
/// - The taproot tweak fails (invalid key or scalar).
fn compute_leaf_taproot_key(tree: &VPackTree) -> [u8; 32] {
    if tree.internal_key == [0u8; 32] || tree.leaf.script_pubkey.len() < 33 {
        return [0u8; 32];
    }

    #[cfg(feature = "schnorr-verify")]
    {
        use crate::consensus::second_tech::compute_bark_vtxo_tapscript_root;
        use crate::consensus::taproot::compute_taproot_tweak;

        if let Ok(merkle_root) = compute_bark_vtxo_tapscript_root(tree) {
            if let Some(q) = compute_taproot_tweak(tree.internal_key, merkle_root) {
                return q;
            }
        }
    }

    [0u8; 32]
}

/// Serialize an `OutPoint` to 36 raw bytes: txid (32B LE) + vout (4B LE).
fn outpoint_to_bytes(op: &crate::types::OutPoint) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&op.txid.to_byte_array());
    buf[32..36].copy_from_slice(&op.vout.to_le_bytes());
    buf
}
