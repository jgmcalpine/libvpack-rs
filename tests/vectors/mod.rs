//! Cryptographic Test Vectors extracted directly from reference implementations.
//! These vectors provide the mathematical source of truth for BIP-341 Taproot
//! tree construction, hashing, and key tweaking.

pub mod arkd;
pub mod bark;

/// Standardized structure for Taproot tree extraction vectors.
/// All values are represented as hex strings to maintain readability.
pub struct TaprootTestVector {
    pub description: &'static str,
    /// 32-byte X-only public key used as the base for the Taproot tweak.
    pub internal_key: &'static str,
    /// Raw, unhashed Bitcoin script bytes for each leaf.
    pub leaf_scripts: &'static [&'static str],
    /// Expected 32-byte BIP-341 TapLeaf hashes corresponding to the scripts.
    pub tapleaf_hashes: &'static [&'static str],
    /// Expected intermediate 32-byte TapBranch hashes.
    pub tapbranch_hashes: &'static [&'static str],
    /// Final 32-byte Merkle Root of the Taproot tree.
    pub merkle_root: &'static str,
    /// Final 32-byte X-only tweaked public key (Internal Key + Merkle Root).
    pub tweaked_pubkey: &'static str,
}

/// Structure specifically for Bark's explicit left/right branch sorting vectors.
pub struct BarkBranchVector {
    pub description: &'static str,
    pub left_sorted: &'static str,
    pub right_sorted: &'static str,
    pub tap_branch_hash: &'static str,
}
