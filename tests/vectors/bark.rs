//! Second Tech (`bark`) Reference Implementation Test Vectors.
//! Extracted from bark tests during VTXO tree construction.

use super::{BarkBranchVector, TaprootTestVector};

/// A single node internal Taproot representing the Cosign path.
/// Useful for testing tweak math without a complex tree.
#[allow(dead_code)]
pub const BARK_COSIGN_TAPROOT: TaprootTestVector = TaprootTestVector {
    description: "cosign_taproot: guards internal node / root output",
    internal_key: "0710fc677c82cc82912438c88914a1d8ecbb31401360c89059976e4cb826c5bd",
    leaf_scripts: &[
        "03a08601b17520bd20b0bf5e3164ab2d0aeff8805771e9795a04ff92d91eddf07d1d3ce01d474cac",
    ],
    tapleaf_hashes: &["f3b27ea5040a80a696f967971c13f3509d5b0fd633a4c7f6e3bc3a67222796ec"],
    tapbranch_hashes: &[],
    merkle_root: "f3b27ea5040a80a696f967971c13f3509d5b0fd633a4c7f6e3bc3a67222796ec",
    tweaked_pubkey: "ca542aaf6c76c4b4c7822d73d91551ef42482098f3675d915d61782448b2ac5b",
};

/// An explicit test vector proving lexicographical sorting in TapBranch hashing.
/// This guarantees our implementation correctly handles branch ordering.
pub const BARK_LEAF_COSIGN_SORTING: BarkBranchVector = BarkBranchVector {
    description: "Explicit TapBranch sorting from bark leaf_cosign_taproot",
    left_sorted: "83b6ff40459a2a6ccad4066752938a10183a881e35fb17cf1ff4651bae66b5c0",
    right_sorted: "f3b27ea5040a80a696f967971c13f3509d5b0fd633a4c7f6e3bc3a67222796ec",
    tap_branch_hash: "7735c13f616bfa9403220bd1a0db55eddab3d896c6d72927b3c73eab03b452b0",
};
