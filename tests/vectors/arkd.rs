//! Ark Labs (`arkd`) Reference Implementation Test Vectors.
//! Extracted via `go test -v ./script/ -run TestParseVtxoScript` from `pkg/ark-lib/script`.

use super::TaprootTestVector;

/// A standard 2-leaf VTXO script tree (e.g., Condition CSV multisig closure).
/// Perfect for testing basic `TapLeaf` hashing and a single `TapBranch` combination.
pub const ARKD_2_LEAF_TREE: TaprootTestVector = TaprootTestVector {
    description: "vtxoScript with condition CSV multisig closure (2 leaves)",
    internal_key: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",

    // Raw script bytes (before TapLeaf encoding)
    leaf_scripts: &[
        "516920002851fd1c7692e5ab649ce1a88bd8ba59e09401d78c4c8fe6ef93c405c4bbb8ad2008c65c69fb2bb155d81f914de7b0319a01f3ce89eaad8e212efaf835c58010a3ac",
        "516903020040b27520002851fd1c7692e5ab649ce1a88bd8ba59e09401d78c4c8fe6ef93c405c4bbb8ad2008c65c69fb2bb155d81f914de7b0319a01f3ce89eaad8e212efaf835c58010a3ac",
    ],

    // Expected Tagged Hashes for the leaves above
    tapleaf_hashes: &[
        "2999dc24f252d160e1e8f6811395afa6cb02c5c3bc730bf7edb60626c4e4cea0",
        "9e2a25f1999896e98abdacb8239a6e777e7d33963f7fd10ff000e9a146dd5a52",
    ],

    // Expected Tagged Hash when combining leaf 0 and leaf 1
    tapbranch_hashes: &[
        "75dc161a060613a0ac4db73a7239f888a5a3e67395b54ac66af35f962ad474e7",
    ],

    merkle_root: "75dc161a060613a0ac4db73a7239f888a5a3e67395b54ac66af35f962ad474e7",
    tweaked_pubkey: "2e65d02c0d5a6f6a11cbf67692d0fc0c9f115661d945146511d3b6bf80825c1a",
};

/// A complex 6-leaf VTXO script tree.
/// Perfect for testing deep Merkle tree assembly and multi-level branch hashing.
#[allow(dead_code)]
pub const ARKD_6_LEAF_TREE: TaprootTestVector = TaprootTestVector {
    description: "vtxoScript from even number of tapscripts (6 leaves)",
    internal_key: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",

    // Script raw bytes omitted for brevity in this vector, focusing on hash assembly
    leaf_scripts: &[],

    tapleaf_hashes: &[
        "c37142cae91e51a8ab3f78e87cd6d329db349b2927856aeeb778b34569e0b0ef",
        "6e7862aec3e570b4876a0f070eef1bdd5abb208eec5946edc9453eb1ed9bce6a",
        "13f370fd9a3178981263c855767e5adb119232e8bd89a67b208a490530ca3a40",
        "74864ac0cfb7dee462decb11cbf37efb8d7f40d3042437c5ebc4bc96041af9ed",
        "5df82a3e78abc9559497d60a8d73354b78484b8b5f2e505776da4796a1d9c8a3",
        "072c1d858bcb55f7a2a68ab0ba9419ade2d51dcda72cbe5b9a0c73d9a6e9b4b2",
    ],
    tapbranch_hashes: &[
        "c07ef708a9095488036783e17db7a7970c4e58bb8dd333320034e4db689367ec",
        "1d37598fe5d9156105d179c3794973fc8cf0a330b4a8919aa90aac07410e0118",
        "29d2f782a9cb36cd35b9b9314abd66ed8334652f41e2c96ed241e90e8e13fc06",
        "cc75174ce9261de1dddf9b9175fb0297633f33475294a3aed6a944dc8f37081d",
        "14ce41c5f291dd99185bdde6b5859183354ef8eb5fa00d51b2e45f0e84c8f8b9",
    ],
    merkle_root: "c07ef708a9095488036783e17db7a7970c4e58bb8dd333320034e4db689367ec",
    tweaked_pubkey: "5de945bb60e4c8c0cf5096f71f4707018d0a9879c76c9cf7a7996d8a555b812e",
};
