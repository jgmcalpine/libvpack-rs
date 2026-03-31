//! VTXO Dehydration Layer: transforms a raw Bark `Vtxo` into two minimalist structures.
//!
//! # Overview
//!
//! Bark's native VTXO format is 10–50 KB per VTXO ("Bloat Wall"). This module provides a
//! dehydration pass that produces:
//!
//! - **[`VpackSovereigntyEnvelope`]** (~214 bytes): a `Copy`, zero-heap proof for balance
//!   verification and Taproot path-exclusivity checking on a Hardware Wallet.
//! - **[`VpackExitWaterfall`]** (≤ 8 KB, ≤ 75 hops): a compact, fixed-buffer streaming iterator for
//!   L1 emergency exit verification, one hop at a time.
//!
//! # Entry point
//!
//! ```text
//! bark_dehydrate(tree, vtxo_id)
//!   → (VpackSovereigntyEnvelope, VpackExitWaterfall)
//! ```
//!
//! The caller is responsible for building the `VPackTree` via
//! [`crate::adapters::second_tech::bark_to_vpack`] (which now populates `internal_key` and
//! `asp_expiry_script`) and the `VtxoId` via
//! [`crate::consensus::SecondTechV3::compute_vtxo_id`].

pub mod envelope;
pub mod waterfall;

pub use envelope::VpackSovereigntyEnvelope;
pub use waterfall::{HopData, VpackExitWaterfall, MAX_HWW_HOPS, WATERFALL_BUF_CAPACITY};

use crate::consensus::VtxoId;
use crate::error::VPackError;
use crate::payload::tree::VPackTree;

/// Dehydrate a parsed Bark `VPackTree` into a sovereignty envelope and a compact exit waterfall.
///
/// # Arguments
///
/// - `tree`: A `VPackTree` produced by the updated [`crate::adapters::second_tech::bark_to_vpack`].
///   The `internal_key` and `asp_expiry_script` fields must be populated for Taproot exclusivity
///   verification to succeed. When the `schnorr-verify` feature is enabled, `bark_to_vpack`
///   populates both fields automatically.
/// - `vtxo_id`: The VTXO identifier computed by
///   [`crate::consensus::SecondTechV3::compute_vtxo_id`].
///
/// # Returns
///
/// A `(VpackSovereigntyEnvelope, VpackExitWaterfall)` tuple on success, or a `VPackError` if
/// the tree is too deep to fit in the waterfall buffer.
pub fn bark_dehydrate(
    tree: &VPackTree,
    vtxo_id: &VtxoId,
) -> Result<(VpackSovereigntyEnvelope, VpackExitWaterfall), VPackError> {
    let envelope = VpackSovereigntyEnvelope::from_tree(tree, vtxo_id);
    let waterfall = VpackExitWaterfall::from_tree(tree)?;
    Ok((envelope, waterfall))
}
