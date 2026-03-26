# libvpack-rs: Verified Capabilities & Audit Spec

> **LIVING DOCUMENT -- UPDATED PER COMMIT**
> This document is strictly generated from the active test suite of `libvpack-rs`. It represents the *mathematically and programmatically verified* capabilities of the library. If a protocol feature or exit path requirement is not listed here, it is not yet covered by our test invariants. This file must be regenerated on every commit.

---

## Quick Reference Index

| # | Category | Key Capabilities | Primary Test Files |
|---|----------|------------------|--------------------|
| 1 | [Cryptographic Primitives (BIP-341)](#1-cryptographic-primitives-bip-341) | TapLeaf hash, TapBranch sorting, Taproot tweak, balanced Merkle root | `tests/taproot_reconstruction.rs` |
| 2 | [Tree Reconstruction & VTXO ID Computation](#2-tree-reconstruction--vtxo-id-computation) | Full tree rebuild, Merkle root derivation, VTXO ID parity for both Ark Labs and Second Tech | `tests/taproot_reconstruction.rs`, `src/consensus/ark_labs.rs`, `src/consensus/second_tech.rs` |
| 3 | [Sabotage Detection & Path Exclusivity](#3-sabotage-detection--path-exclusivity) | Internal key mutation, expiry backdoor, fake P2TR, inflation, sequence tampering, Schnorr forgery, engine Schnorr split-sabotage | `tests/taproot_reconstruction.rs`, `tests/conformance/mod.rs`, `tests/forensic_verification.rs`, `tests/consensus_guard_tests.rs`, `src/consensus/ark_labs.rs`, `src/consensus/second_tech.rs` |
| 3.1 | [Sovereignty & Inclusion Guarantees](#31-sovereignty--inclusion-guarantees) | Shadow key injection, sibling substitution, path truncation/extension, BIP-341 sorting integrity | `tests/taproot_reconstruction.rs` |
| 4 | [JSON Conformance & Cross-Implementation Standardization](#4-json-conformance--cross-implementation-standardization) | Ark Labs and Second Tech JSON vector parsing, public API pipeline, WASM adapter auto-inference | `tests/conformance/mod.rs`, `tests/export_tests/mod.rs`, `src/lib.rs` |
| 5 | [Forensic Hash Verification](#5-forensic-hash-verification) | Naked sha256d parity, version sensitivity (V2 vs V3), virtual tx reconstruction | `tests/forensic_verification.rs`, `tests/conformance/mod.rs` |
| 6 | [Transaction Factory & Wire Format](#6-transaction-factory--wire-format) | Preimage byte parity, SegWit signed layout, legacy unsigned format | `src/consensus/tx_factory.rs` |
| 7 | [Serialization & Identity Roundtrips](#7-serialization--identity-roundtrips) | VtxoId parse/display, VPackTree pack/parse, end-to-end pack-then-verify | `src/consensus/mod.rs`, `src/payload/tests.rs`, `tests/conformance/mod.rs` |
| 8 | [Mutation Testing & Consensus Hardening](#8-mutation-testing--consensus-hardening) | cargo-mutants audit (`audit.yml`), `compute_vtxo_id` output-vector refactor, Schnorr split-sabotage on path steps | `.github/workflows/audit.yml`, `src/consensus/ark_labs.rs`, `src/consensus/second_tech.rs`, `tests/consensus_guard_tests.rs` |

**Error Variant Cross-Reference** (search this document for any of these to find the test that guards it):
`IdMismatch` | `ValueMismatch` | `SequenceMismatch` | `PolicyMismatch` | `InvalidVout` | `InvalidSignature` | `PathExclusivityViolation` | `MissingExclusivityData` | `InvalidArkLabsScript` | `InvalidBarkScript`

**Test Vector Files** used across the suite:

| Vector File | Format | Used By |
|-------------|--------|---------|
| `tests/conformance/vectors/ark_labs/round_leaf_v3.json` | Ark Labs V3 Anchored | Conformance, export, forensic, unit tests |
| `tests/conformance/vectors/ark_labs/round_branch_v3.json` | Ark Labs V3 Anchored | Conformance, export, inflation, deep recursion |
| `tests/conformance/vectors/ark_labs/oor_forfeit_pset.json` | Ark Labs V3 OOR | Conformance, export, tx_factory parity |
| `tests/conformance/vectors/second/round_v3_borsh.json` | Second Tech V3 Plain | Conformance, export, forensic, SHA256 parity |
| `tests/conformance/vectors/second/boarding_v3_borsh.json` | Second Tech V3 Plain | Conformance, export |
| `tests/conformance/vectors/second/oor_v3_borsh.json` | Second Tech V3 Plain | Conformance, export, OOR ingredient parsing |
| `tests/fixtures/second_tech_round1_step0.json` | Second Tech fixture | Unit verification, sabotage, deep recursion, Schnorr sabotage |
| `tests/vectors/arkd.rs` | Rust constants | Taproot primitive tests (2-leaf, 6-leaf trees) |
| `tests/vectors/bark.rs` | Rust constants | Taproot primitive tests (cosign, branch sorting) |

---

## 1. Cryptographic Primitives (BIP-341)

*Every VTXO in the Ark protocol is locked behind a Taproot output. Taproot outputs are derived from an internal key and a Merkle tree of script leaves (BIP-341). If any step in this derivation -- leaf hashing, branch sorting, tree assembly, or key tweaking -- is incorrect, the resulting on-chain output will be unspendable. These tests verify that `libvpack-rs` implements each cryptographic primitive identically to the reference implementations (`arkd` and `bark`), ensuring that exit transactions constructed by this library will be accepted by the Bitcoin network.*

### BIP-341 TapLeaf Hashing

* **Description:** Takes a raw Bitcoin script (the bytes of a spending condition) and computes its BIP-341 "TapLeaf" tagged hash. The tagged hash prepends `SHA256("TapLeaf")` to the data before hashing, which domain-separates leaf hashes from all other Bitcoin hash types. The test asserts that `tap_leaf_hash(script)` produces the exact 32-byte hash that the Ark Labs reference implementation (`arkd`) computes for the same script.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_tapleaf_hash_against_arkd`](tests/taproot_reconstruction.rs#L29)
* **Vectors:** `ARKD_2_LEAF_TREE.leaf_scripts[0]` and `ARKD_2_LEAF_TREE.tapleaf_hashes[0]` from [`tests/vectors/arkd.rs`](tests/vectors/arkd.rs#L8)
* **What this proves:** A wallet or verifier using this library will produce leaf hashes that are byte-identical to those produced by `arkd`. This is the foundational building block: if leaf hashing is wrong, the entire Taproot tree is wrong, and the user's exit script cannot be proven to exist in the on-chain output.

### BIP-341 TapBranch Lexicographic Sorting

* **Description:** BIP-341 requires that when two child hashes are combined into a branch, they are first sorted lexicographically (the numerically smaller hash comes first). This test feeds two known leaf hashes from the `bark` reference implementation in both `(left, right)` and `(right, left)` order and asserts that `tap_branch_hash` produces the identical result regardless of input order.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_tapbranch_sorting_against_bark`](tests/taproot_reconstruction.rs#L41)
* **Vectors:** `BARK_LEAF_COSIGN_SORTING` from [`tests/vectors/bark.rs`](tests/vectors/bark.rs#L23)
* **What this proves:** The branch hash is order-independent, matching BIP-341's specification exactly. Without this guarantee, two implementations given the same tree in different traversal orders would derive different Merkle roots, creating incompatible exit transactions.

### Taproot Tweak Derivation (Multiple Tree Sizes)

* **Description:** The Taproot "tweak" combines a 32-byte x-only internal public key with a 32-byte Merkle root to produce the final output key that appears on-chain. These tests verify `compute_taproot_tweak` against three independent reference vectors: a 2-leaf tree from `arkd`, a 6-leaf tree from `arkd`, and a cosign tree from `bark`. Each test asserts that the derived 32-byte tweaked public key matches the reference byte-for-byte.
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_taptweak_against_arkd`](tests/taproot_reconstruction.rs#L60) -- 2-leaf tree
  * [`tests/taproot_reconstruction.rs::test_taptweak_against_arkd_6_leaf`](tests/taproot_reconstruction.rs#L71) -- 6-leaf tree
  * [`tests/taproot_reconstruction.rs::test_taptweak_against_bark`](tests/taproot_reconstruction.rs#L82) -- Bark cosign tree
* **Vectors:** `ARKD_2_LEAF_TREE`, `ARKD_6_LEAF_TREE`, `BARK_COSIGN_TAPROOT`
* **What this proves:** The final on-chain key derivation is correct across tree topologies and implementations. This is the step that directly determines whether the user's VTXO can be spent on L1. If the tweak is wrong by even a single bit, the resulting P2TR address is unspendable.

### Balanced Merkle Root from Leaf Hashes

* **Description:** Given 6 pre-computed TapLeaf hashes, the test feeds them into `compute_balanced_merkle_root` (which uses a recursive halving topology: split the list in half, compute each sub-root, then combine) and asserts the result matches the `arkd` reference Merkle root.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_balanced_merkle_root_6_leaf`](tests/taproot_reconstruction.rs#L96)
* **Vectors:** `ARKD_6_LEAF_TREE.tapleaf_hashes` (6 hashes) and `ARKD_6_LEAF_TREE.merkle_root`
* **What this proves:** The library correctly assembles a balanced Merkle tree from an arbitrary number of leaves. This is critical for Ark round transactions that contain many VTXO script leaves -- the tree topology must match the ASP's construction exactly, or the user's leaf will not be provable via a control block.

---

## 2. Tree Reconstruction & VTXO ID Computation

*A VTXO's identity (its "VTXO ID") is the sha256d hash of the virtual transaction that created it. To verify a VTXO, the verifier must reconstruct the exact virtual transaction from its component parts (scripts, values, anchors) and confirm the hash matches. This section covers end-to-end reconstruction: from raw scripts all the way to the final VTXO ID, for both Ark Labs (V3Anchored, `TxVariant 0x04`) and Second Tech/Bark (V3Plain, `TxVariant 0x03`) consensus engines.*

### Ark Labs Full Tree Reconstruction (2-Leaf)

* **Description:** Constructs a `VPackTree` from the `ARKD_2_LEAF_TREE` reference vector's internal key and expiry script. Calls `compute_ark_labs_merkle_root` to derive the Merkle root, then `compute_taproot_tweak` to derive the output key. Asserts three things: (1) the Merkle root matches the reference, (2) the tweaked key matches the reference, and (3) the tweaked key equals the x-only pubkey embedded in the `OP_1 <32-byte-key>` P2TR `script_pubkey`.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_ark_labs_full_tree_reconstruction`](tests/taproot_reconstruction.rs#L113)
* **What this proves:** Given an Ark Labs VTXO's component scripts and internal key, this library can reconstruct the exact L1 Taproot output. A user holding these scripts can independently verify that the on-chain UTXO they were promised actually contains their exit path.

### Bark/Second Tech Full Tree Reconstruction

* **Description:** Same structure as the Ark Labs test, but uses the `BARK_COSIGN_TAPROOT` vector. Additionally verifies that re-compiling the expiry script (parse the CLTV value from the raw script, re-encode it, hash it) produces a TapLeaf hash identical to the `bark` reference's `right_sorted` value, confirming the parse-compile roundtrip is lossless.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_bark_full_tree_reconstruction`](tests/taproot_reconstruction.rs#L175)
* **What this proves:** The library's Bark-specific script parsing (CLTV expiry extraction, cosign key extraction) and recompilation produce byte-identical results to the `bark` reference. This ensures that Second Tech VTXOs can be unilaterally exited using only the data in the V-PACK.

### Ark Labs V3 Leaf VTXO ID Computation

* **Description:** Loads the `round_leaf_v3.json` conformance vector (a real leaf-level VTXO from the Ark Labs builder), constructs a `VPackTree` from its `reconstruction_ingredients`, and calls `ArkLabsV3.compute_vtxo_id()`. Asserts the computed 32-byte VTXO ID matches the `expected_vtxo_id` from the vector file.
* **Test Location:** [`src/consensus/ark_labs.rs::test_ark_labs_v3_leaf_verification`](src/consensus/ark_labs.rs#L496)
* **Vectors:** `tests/conformance/vectors/ark_labs/round_leaf_v3.json`
* **What this proves:** For the simplest Ark Labs VTXO type (a direct leaf with no intermediate branch nodes), the library computes the correct sha256d transaction hash. This is the "Gold Standard" parity test: if this passes, the library agrees with `arkd` on what this VTXO's identity is.

### Ark Labs V3 Branch VTXO ID Computation

* **Description:** Loads `round_branch_v3.json` (a branch-level VTXO containing sibling outputs). Constructs siblings with their canonical `hash_sibling_birth_tx` hashes, builds the tree with a 1-step path, and computes the VTXO ID. Asserts the ID matches the expected value and that `Display` formatting (reversed byte order) matches the expected string.
* **Test Location:** [`src/consensus/ark_labs.rs::test_ark_labs_v3_branch_verification`](src/consensus/ark_labs.rs#L663)
* **Vectors:** `tests/conformance/vectors/ark_labs/round_branch_v3.json`
* **What this proves:** The library correctly handles branch-level VTXOs where the virtual transaction has multiple outputs (user output + sibling outputs + fee anchor). The sibling birth-tx hashing and top-down chaining logic produce the correct intermediate transaction IDs.

### Ark Labs V3 Deep Recursion (3-Level Path)

* **Description:** Manually constructs a 3-level tree: an anchor transaction spawns a Level 1 branch (from `round_branch_v3.json` data), which spawns a Level 2 intermediate node, which spawns the final leaf. Each level has its own siblings and fee anchor. Calls `compute_vtxo_id` and asserts the result is a non-zero `VtxoId::Raw` hash.
* **Test Location:** [`src/consensus/ark_labs.rs::test_ark_labs_v3_deep_recursion`](src/consensus/ark_labs.rs#L769)
* **What this proves:** The top-down chaining logic -- where each level's transaction ID becomes the next level's input -- works correctly for multi-level Ark trees. This matters for round transactions where a user's VTXO is several branches deep in the tree; all intermediate virtual transactions must chain correctly for the final VTXO ID to be valid.

### Second Tech V3 Link VTXO ID Computation

* **Description:** Loads the `second_tech_round1_step0.json` fixture (a real Step 0 genesis item from a Second Tech round). Constructs the tree with one path step containing multiple sibling scripts and a grandparent hash as anchor. Calls `SecondTechV3.compute_vtxo_id()` and asserts: (1) the computed ID matches `expected_vtxo_id`, (2) the ID is an `OutPoint` variant (not `Raw`), (3) the TxID hash portion and vout match independently.
* **Test Location:** [`src/consensus/second_tech.rs::test_second_tech_v3_link_verification`](src/consensus/second_tech.rs#L584)
* **Vectors:** `tests/fixtures/second_tech_round1_step0.json`
* **What this proves:** For Second Tech's `OutPoint`-based VTXO identity scheme (where the ID is a `TxID:vout` pair rather than a raw hash), the library computes the correct virtual transaction ID. The `OutPoint` format difference from Ark Labs is correctly handled.

### Second Tech V3 Deep Recursion (5-Step Path)

* **Description:** Constructs a 5-step genesis path (the deepest path tested in the suite). Step 0 uses real fixture data; Steps 1-4 use intermediate scripts with decreasing child amounts (20000, 19000, 18000, 17000). Computes the VTXO ID and asserts: (1) `signed_txs` has exactly 6 entries (5 path steps + 1 leaf), (2) each signed tx starts with version 3 LE bytes in legacy format, (3) the ID is an `OutPoint` with a non-zero TxID, and (4) `vout` matches `leaf.vout`.
* **Test Location:** [`src/consensus/second_tech.rs::test_second_tech_v3_deep_recursion`](src/consensus/second_tech.rs#L815)
* **What this proves:** The library handles deep genesis paths where a VTXO was created through many levels of virtual transaction splitting. Each step in the chain produces a correctly formatted transaction whose ID feeds into the next step's input. The `signed_txs` output provides the full chain of virtual transactions needed for an L1 exit.

### Previous-link outputs in `compute_vtxo_id` (implementation invariant)

* **Description:** During top-down path traversal, each virtual transaction’s outputs are fed into the *next* step as the “previous outputs” used for parent amount/script and (when `schnorr-verify` is enabled) BIP-341 Taproot sighash verification. This state is stored as a single `Vec<ReconstructedOutput>` (`value` + `script_pubkey` per output), not as two parallel vectors. The Schnorr gate uses one bounds check: `idx >= prev_outputs.len()` before indexing.
* **Code:** [`src/consensus/ark_labs.rs`](src/consensus/ark_labs.rs), [`src/consensus/second_tech.rs`](src/consensus/second_tech.rs) — private `ReconstructedOutput` struct and `prev_outputs: Option<Vec<ReconstructedOutput>>` in `ConsensusEngine::compute_vtxo_id`.
* **What this proves:** Values and scripts for the same logical output are always paired; there is no separate invariant that two parallel slices stay the same length. Mutation testing no longer sees an equivalent `replace || with &&` mutant on two redundant `.len()` checks for the same conceptual boundary.

---

## 3. Sabotage Detection & Path Exclusivity

*The security model of Ark depends on users being able to detect tampered data. An ASP (Ark Service Provider) could attempt to serve a user a V-PACK containing subtly wrong data -- a mutated key, an inflated value, a backdoored script -- that would make the VTXO unspendable or redirect funds. Every test in this section proves that a specific class of attack is detected and rejected with a specific error variant. If a sabotage vector is not listed here, it is not yet tested.*

### Path Exclusivity: Valid Trees Pass

* **Description:** Constructs valid Ark Labs and Bark trees from reference vectors and calls `verify_path_exclusivity`. The function reconstructs the Taproot output key from the tree's `internal_key` and `asp_expiry_script`, then checks that the derived key matches the key embedded in the leaf's `script_pubkey`. Both tests assert success (no error).
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_valid_ark_labs`](tests/taproot_reconstruction.rs#L317) -- `TxVariant::V3Anchored`
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_valid_bark`](tests/taproot_reconstruction.rs#L324) -- `TxVariant::V3Plain`
* **What this proves:** The baseline: correctly constructed trees pass path exclusivity verification. This confirms that the check is not overly aggressive -- legitimate VTXOs are accepted.

### Path Exclusivity: Missing Data Rejected

* **Description:** Takes a valid Ark Labs tree and empties the `asp_expiry_script` field. Calls `verify_path_exclusivity` and asserts the result is `Err(VPackError::MissingExclusivityData)`.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_path_exclusivity_missing_data`](tests/taproot_reconstruction.rs#L335)
* **What this proves:** If the ASP omits the expiry script (which would prevent the user from verifying the tree structure), the library explicitly rejects the V-PACK rather than silently accepting incomplete data. The user is never left in a state where they cannot verify their exit path.

### Sabotage: Mutated Internal Key

* **Description:** Takes valid trees (one Ark Labs, one Bark) and flips a single bit (`XOR 0x01`) in `internal_key[0]`. Calls `verify_path_exclusivity` and asserts `Err(VPackError::PathExclusivityViolation)` for both.
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_mutated_internal_key_ark_labs`](tests/taproot_reconstruction.rs#L351)
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_mutated_internal_key_bark`](tests/taproot_reconstruction.rs#L363)
* **What this proves:** A single-bit mutation in the internal key cascades through the Taproot tweak into a completely different output key, which no longer matches the `script_pubkey`. This prevents an ASP from serving a V-PACK with a subtly different internal key (e.g., one that includes a hidden spending path the user doesn't know about).

### Sabotage: Backdoored Expiry Script

* **Description:** Takes valid trees and flips a byte at the midpoint of `asp_expiry_script`. Asserts the result is either `VPackError::PathExclusivityViolation` (the modified script produces a different Merkle root and thus a different output key) or `VPackError::InvalidArkLabsScript` / `VPackError::InvalidBarkScript` (the modified bytes make the script unparseable).
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_backdoored_expiry_ark_labs`](tests/taproot_reconstruction.rs#L379)
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_backdoored_expiry_bark`](tests/taproot_reconstruction.rs#L395)
* **What this proves:** If an ASP modifies the expiry script (e.g., to shorten the timelock so they can sweep funds earlier, or to replace the user's key with their own), the verification detects the tampering. The modified script either fails to parse or produces a key mismatch.

### Sabotage: Fake P2TR Anchor (Wrong Output Key)

* **Description:** Replaces the `script_pubkey` in the leaf with a valid-looking P2TR script (`OP_1 <32-byte-fake-key>`) but using a key that does not correspond to the tree's internal key + Merkle root. Asserts `Err(VPackError::PathExclusivityViolation)` for both Ark Labs and Bark variants.
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_fake_anchor_ark_labs`](tests/taproot_reconstruction.rs#L415)
  * [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_fake_anchor_bark`](tests/taproot_reconstruction.rs#L431)
* **What this proves:** An ASP cannot serve a V-PACK that claims the user's VTXO is at a different on-chain output than the one derivable from the tree's scripts. This prevents fund redirection attacks where the V-PACK data looks valid but points to an output the ASP controls.

### Sabotage: Non-P2TR Script Type

* **Description:** Replaces the leaf's `script_pubkey` with a P2WPKH script (`OP_0 <20-byte-hash>`) instead of P2TR. Asserts `Err(VPackError::PathExclusivityViolation)`.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_path_exclusivity_sabotage_non_p2tr_script`](tests/taproot_reconstruction.rs#L451)
* **What this proves:** The library enforces that VTXO outputs must be Taproot (P2TR). Any attempt to claim a VTXO is locked in a non-Taproot output type is rejected, since non-Taproot outputs cannot contain the script tree required for Ark exit paths.

### Sabotage: Wrong Sibling Script (Ark Labs and Second Tech)

* **Description:** For Ark Labs: constructs a valid tree, computes the expected VTXO ID, then replaces the fee anchor sibling's script with `vec![0x00]` (a single-byte garbage script). Calls `verify` and asserts `Err(VPackError::IdMismatch)`. For Second Tech: same approach, replacing the fee anchor script in a genesis item's siblings. Both test via the `ConsensusEngine::verify` method.
* **Test Locations:**
  * [`src/consensus/ark_labs.rs::test_ark_labs_v3_leaf_sabotage_anchor_mismatch`](src/consensus/ark_labs.rs#L575)
  * [`src/consensus/second_tech.rs::test_second_tech_v3_link_sabotage_anchor_mismatch`](src/consensus/second_tech.rs#L686)
* **What this proves:** The sibling scripts directly affect the virtual transaction's outputs. Changing any sibling's script changes the birth transaction hash, which changes the VTXO ID. An ASP cannot substitute a different fee anchor or sibling output without the verifier detecting `IdMismatch`.

### Sabotage: Inflation (+1 Satoshi)

* **Description:** Loads `round_leaf_v3.json` and increases the first output's value by 1 satoshi. Packs and verifies with the original expected ID and a fixed `anchor_value`. Asserts `Err(VPackError::ValueMismatch)`. Separately loads `round_branch_v3.json` and increases the first sibling's value by 1 satoshi, asserting the same error.
* **Test Location:** [`tests/conformance/mod.rs::test_sabotage_inflation`](tests/conformance/mod.rs#L345)
* **What this proves:** The value conservation check (`anchor_value == sum of all outputs`) catches even a 1-satoshi inflation attempt. The `anchor_value` parameter acts as the on-chain ground truth: the user provides the actual L1 UTXO value, and if the V-PACK's output values don't sum to it, verification fails with `VPackError::ValueMismatch`.

### Sabotage: Amount Corruption (Conformance Vectors)

* **Description:** For every Second Tech conformance vector that has an `amount` field, the test adds 1 satoshi and verifies against the original expected ID. Asserts `Err(VPackError::IdMismatch)` or `Err(VPackError::ValueMismatch)`.
* **Test Location:** [`tests/conformance/mod.rs::run_integrity_sabotage`](tests/conformance/mod.rs#L153) (called by `run_conformance_vectors`)
* **What this proves:** Across all Second Tech vector types (round, boarding, OOR), any amount manipulation is detected. The check works because the amount is baked into the virtual transaction preimage -- changing it produces a different hash.

### Sabotage: Sequence Tampering

* **Description:** For Ark Labs vectors with an `nSequence` field, the test flips the sequence value (from `0xFFFFFFFF` to `0xFFFFFFFE` or vice versa). Asserts `Err(VPackError::IdMismatch)` or `Err(VPackError::SequenceMismatch)`.
* **Test Location:** [`tests/conformance/mod.rs::run_integrity_sabotage`](tests/conformance/mod.rs#L153) (called by `run_conformance_vectors`)
* **What this proves:** The `nSequence` field (which controls relative timelocks in Bitcoin) is part of the transaction preimage. Tampering with it changes the VTXO ID, preventing an ASP from silently modifying timelock parameters.

### Sabotage: Sibling Script Mutation (Conformance Vectors)

* **Description:** For Ark Labs branch vectors with siblings, the test verifies the good tree first, then mutates the first sibling's script (wrapping_add on byte 0). Re-packs via `create_vpack_from_tree` and asserts `Err(VPackError::IdMismatch)`.
* **Test Location:** [`tests/conformance/mod.rs::run_integrity_sabotage`](tests/conformance/mod.rs#L153) (called by `run_conformance_vectors`)
* **What this proves:** The chain-of-spends integrity check catches sibling script mutations at the conformance level, not just the unit level. This is an end-to-end sabotage test through the full public API pipeline.

### Sabotage: Invalid Vout

* **Description:** For Second Tech vectors, sets `vout` to 99 (an output index that does not exist in the virtual transaction). Asserts `Err(VPackError::InvalidVout(99))`.
* **Test Location:** [`tests/conformance/mod.rs::run_integrity_sabotage`](tests/conformance/mod.rs#L153) (called by `run_conformance_vectors`)
* **What this proves:** The library validates that the claimed output index exists in the reconstructed virtual transaction. An ASP cannot claim a VTXO exists at a nonexistent output position.

### Sabotage: Path Sequence Mismatch

* **Description:** For Ark Labs branch vectors, modifies the `sequence` field in the first path step to differ from the leaf's sequence. Asserts `Err(VPackError::PolicyMismatch)`.
* **Test Location:** [`tests/conformance/mod.rs::run_integrity_sabotage`](tests/conformance/mod.rs#L153) (called by `run_conformance_vectors`)
* **What this proves:** All levels of a VTXO tree must use the same sequence/timelock policy. If a path step uses a different sequence than the leaf, it indicates either corruption or an attempt to apply inconsistent spending conditions at different tree levels.

### Sabotage: Invalid Sequence Value (Rejected at Verification)

* **Description:** Loads valid Ark Labs ingredients, sets `n_sequence` to `0x00000005` (an unusual, likely invalid value for Ark protocol purposes), packs, and verifies. Asserts `result.is_err()`.
* **Test Location:** [`tests/conformance/mod.rs::test_reject_invalid_sequence`](tests/conformance/mod.rs#L1304)
* **What this proves:** The verification pipeline rejects VTXOs with non-standard sequence values. This prevents an ASP from injecting arbitrary relative timelock values that could alter the VTXO's spending conditions.

### Sabotage: Tampered Schnorr Signature

* **Description:** Constructs a Second Tech tree with a 2-step path. Sets a 64-byte signature on the second path step with the last byte as `0xFF` (a tampered signature). Packs and verifies. Asserts `Err(VPackError::InvalidSignature)`. *This test requires the `schnorr-verify` feature flag.*
* **Test Location:** [`tests/forensic_verification.rs::test_sabotage_invalid_signature`](tests/forensic_verification.rs#L264)
* **Feature Gate:** `#[cfg(feature = "schnorr-verify")]`
* **What this proves:** When Schnorr signature verification is enabled, the library validates that all signatures in the genesis path are cryptographically valid. A forged or corrupted signature is caught before the VTXO is accepted, preventing an ASP from serving pre-signed exit transactions with invalid signatures.

### Engine Schnorr verification: split sabotage on a path step (`consensus_guard_tests`)

* **Description:** Under `#[cfg(feature = "schnorr-verify")]`, the `engine_schnorr` module builds a **two-step** signed path with a valid BIP-340 signature on `path[1]`, then applies two independent failure modes that both exercise the `i > 0` Schnorr branch inside `ArkLabsV3::compute_vtxo_id` and `SecondTechV3::compute_vtxo_id`: (1) **output commitment mismatch** — replace `path[1].child_script_pubkey` with a P2TR script for a different x-only key than the one used to sign, so the recomputed Taproot sighash no longer matches the stored signature; (2) **signature math mismatch** — keep scripts consistent but flip a byte in `path[1].signature`. Separate tests call each engine so a regression in either engine’s loop is visible. Additional tests cover valid P2TR and 33-byte leaf keys and a shared corrupted-signature case.
* **Test Locations:** [`tests/consensus_guard_tests.rs`](tests/consensus_guard_tests.rs) — `engine_schnorr::test_ark_engine_sabotage_only_key_mismatch`, `test_ark_engine_sabotage_only_sig_math_mismatch`, `test_second_tech_engine_sabotage_only_key_mismatch`, `test_second_tech_engine_sabotage_only_sig_math_mismatch`, plus `test_engine_schnorr_valid_*` and `test_engine_schnorr_corrupted_sig`.
* **Feature Gate:** `#[cfg(feature = "schnorr-verify")]`
* **What this proves:** Schnorr verification is tied to the **path step** under test (intermediate link), not only the leaf. Each failure mode returns `InvalidSignature` (or the same engine error surface as production), so tests distinguish “wrong output script commitment in the virtual tx” from “broken signature bytes” while keeping the rest of the tree valid.

---

## 3.1 Sovereignty & Inclusion Guarantees

*The tests below form the "Merkle Integrity Audit" — a suite of adversarial tests that prove `verify_path_exclusivity` provides a mathematically complete defense against three classes of Taproot tree tampering. Each test constructs a valid tree, applies a precise, structure-preserving mutation, and asserts that the library detects the tampering at the cryptographic key-comparison stage (not at the parsing stage). Together they guarantee that no hidden spend paths, truncated trees, or injected keys can survive verification.*

### Shadow Key Injection Protection

* **Description:** Path exclusivity recomputes the Taproot output key from the tree's scripts and `internal_key`, then compares it against the P2TR `script_pubkey`. A single-bit flip in `internal_key` (at byte 15, bit 7) cascades through the `TapTweak` derivation into a completely different tweaked key, which no longer matches the leaf's P2TR output. This test uses a 5-leaf Bark tree (1 expiry + 4 unlock siblings) to exercise the full balanced Merkle root computation, including odd-node promotion, before the tweak. A separate "Dual-Sabotage" test independently exercises both arms of the P2TR format guard (`length != 34`, `prefix != [0x51, 0x20]`) and the key-equality comparison, killing `|| -> &&` and `!= -> ==` cargo-mutants.
* **Test Locations:**
  * [`tests/taproot_reconstruction.rs::test_internal_key_mutation_fails`](tests/taproot_reconstruction.rs)
  * [`tests/taproot_reconstruction.rs::test_dual_sabotage_script_validation_gate`](tests/taproot_reconstruction.rs)
* **What this proves:** An ASP cannot inject a "shadow" internal key — one that would add a hidden key-path spend — without the library detecting the resulting output key mismatch. Even a single-bit change in the key is caught.

### Sibling Substitution Protection

* **Description:** Takes a valid 5-leaf Bark tree and mutates one byte of a sibling's `musig_key` (the last 32 bytes of the unlock script). The mutation preserves all opcodes and push-length prefixes, so the script parser (`parse_bark_unlock_script`) still succeeds — ensuring the failure propagates through the Merkle math, not through a parse rejection. The modified script produces a different `TapLeaf` hash, which changes the balanced Merkle root, which changes the tweaked output key.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_merkle_sibling_substitution_fails`](tests/taproot_reconstruction.rs)
* **What this proves:** An ASP cannot substitute a different spend path for an existing sibling without detection. Even a single-bit change in a sibling's cryptographic key material cascades through the Merkle tree to an output key mismatch.

### Path Truncation & Extension Protection

* **Description:** Tests two attacks against the Taproot tree structure: (1) *Truncation* — removing the last `leaf_sibling`, dropping from 5 leaves (odd count, triggering BIP-341 odd-node promotion) to 4 leaves (even count, all paired). (2) *Extension* — appending a duplicate sibling, growing from 5 leaves to 6. Both mutations change the balanced Merkle root because the tree topology (number of leaves, pairing, and promotion) is different.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_path_truncation_and_extension_fails`](tests/taproot_reconstruction.rs)
* **What this proves:** An ASP cannot hide a spend path by truncating the tree (removing a leaf the user does not know about) or extend it by adding a leaf (inserting an additional exit path). Both attacks change the Merkle root and are caught by the output key comparison. The 5-leaf baseline specifically exercises BIP-341's odd-node promotion logic, ensuring the library's `compute_balanced_merkle_root` handles the even/odd boundary correctly.

### BIP-341 Lexicographic Sorting Integrity

* **Description:** Constructs two deterministic 32-byte hashes where `A > B` lexicographically and verifies that `tap_branch_hash(A, B)` produces an identical result to `tap_branch_hash(B, A)`. Additionally verifies the result equals the manually computed `tagged_hash("TapBranch", B || A)`, confirming the smaller hash is placed first per BIP-341.
* **Test Location:** [`tests/taproot_reconstruction.rs::test_taproot_lexicographical_sorting_integrity`](tests/taproot_reconstruction.rs)
* **What this proves:** The BIP-341 branch sorting rule is enforced internally by the library, not assumed by callers. Two implementations traversing the same tree in different orders will produce identical Merkle roots, ensuring exit transactions are interoperable.

### Control Block Parity Enforcement

* **Description:** Two adversarial tests target the parity bit and leaf version encoded in the control block's first byte. The parity test reconstructs a valid control block, flips only bit 0 (the Y-coordinate parity), and asserts that `verify_control_block` rejects it — the derived tweaked key's parity no longer matches the control byte. The leaf version test replaces `0xc0` (BIP-341 Tapscript) with the unknown version `0xc2` while preserving the original parity bit; the altered version changes the `TapLeaf` tagged hash, which cascades through the Merkle root into a tweaked key mismatch. Together these tests prove that malformed witness stacks — whether from a buggy wallet or a malicious ASP — are rejected before reaching L1.
* **Test Locations:**
  * [`tests/control_block_tests.rs::test_control_block_internal_key_parity_mismatch`](tests/control_block_tests.rs)
  * [`tests/control_block_tests.rs::test_control_block_invalid_leaf_version_fails`](tests/control_block_tests.rs)
* **What this proves:** The library enforces both the parity bit and the BIP-341 leaf version as first-class security properties. A witness stack with a flipped parity or unknown leaf version cannot pass `verify_control_block`, preventing malformed spends from being accepted off-chain that would be rejected by L1 consensus.

### Internal Key Commitment (Control Block Sovereignty)

* **Description:** Two tests verify that the internal key embedded in the control block is cryptographically bound to the on-chain P2TR output key. The "Shadow Key" test reconstructs a valid Bark control block, XOR-flips byte 16 (the middle of the 32-byte internal key segment) with `0xFF`, and asserts rejection — a single-byte mutation in the key cascades through `TapTweak` into a completely different tweaked key. The "Output Key Mismatch" test provides a valid control block and correct leaf script but supplies the tweaked key from a *different* VTXO (`BARK_COSIGN_TAPROOT` vs `ARKD_2_LEAF_TREE`), asserting that cross-VTXO key confusion is caught. The key comparison in `verify_control_block` uses a constant-time XOR-fold (`ct_eq_32`) to prevent timing side-channels and ensure a `!= → ==` cargo-mutant on the comparison is killed by every positive test.
* **Test Locations:**
  * [`tests/control_block_tests.rs::test_control_block_shadow_key_fails`](tests/control_block_tests.rs)
  * [`tests/control_block_tests.rs::test_control_block_output_key_mismatch`](tests/control_block_tests.rs)
* **What this proves:** The equation `internal_key + merkle_root = on-chain address` is enforced end-to-end. An ASP cannot inject a "shadow" internal key (one that would add a hidden key-path spend) or confuse the verifier with a different VTXO's output key. The constant-time comparison hardens the check against both timing side-channels and mutation testing.

---

## 4. JSON Conformance & Cross-Implementation Standardization

*The V-PACK format must work identically regardless of which Ark implementation produced the data. These tests verify that JSON-serialized `reconstruction_ingredients` from both the Ark Labs (`arkd`) and Second Tech (`bark`) reference implementations can be parsed, packed into V-PACKs, and verified against the expected VTXO IDs. This is the interoperability guarantee: a VTXO created by `arkd` and a VTXO created by `bark` can both be verified by the same `vpack::verify()` function.*

### Universal Conformance Pipeline (All Vectors)

* **Description:** Iterates every JSON file under `tests/conformance/vectors/ark_labs/` and `tests/conformance/vectors/second/`. For each: (1) parses the JSON into `reconstruction_ingredients`, (2) calls the appropriate `create_vpack_*` function (Ark Labs or Second Tech based on `meta.variant`), (3) calls `vpack::verify()` with the expected VTXO ID and the correct anchor value. Additionally runs `run_integrity_sabotage` on each vector (see Section 3). All 6 JSON vectors must pass.
* **Test Location:** [`tests/conformance/mod.rs::run_conformance_vectors`](tests/conformance/mod.rs#L69)
* **Vectors tested:**
  * `ark_labs/round_leaf_v3.json` (anchor: 1100 sats)
  * `ark_labs/round_branch_v3.json` (anchor: 1700 sats)
  * `ark_labs/oor_forfeit_pset.json` (anchor: 1000 sats)
  * `second/round_v3_borsh.json` (anchor: 13000 sats)
  * `second/boarding_v3_borsh.json` (anchor: 10000 sats)
  * `second/oor_v3_borsh.json` (anchor: 10000 sats)
* **What this proves:** The full pipeline -- JSON parsing, tree construction, binary packing, verification -- produces correct results for every supported VTXO type across both implementations. This is the most comprehensive single test in the suite.

### OOR Ingredients Parsing

* **Description:** Loads `oor_v3_borsh.json`, extracts the `anchor_outpoint` field, parses it as a `VtxoId`, and then parses the full `reconstruction_ingredients` via `second_tech_ingredients_from_json`. Asserts both operations succeed.
* **Test Location:** [`tests/conformance/mod.rs::oor_ingredients_parse`](tests/conformance/mod.rs#L320)
* **What this proves:** Out-of-round (OOR) VTXOs from Second Tech -- which have a different structure than in-round VTXOs -- can be successfully parsed. The `anchor_outpoint` format (which may be a raw hash rather than a `TxID:vout` pair) is handled correctly.

### Export API Parity (Ark Labs)

* **Description:** For every Ark Labs JSON vector with a real `expected_vtxo_id`, calls the public API: `ark_labs_ingredients_from_json` then `create_vpack_ark_labs` then `vpack::verify`. Uses vector-specific anchor values (1100, 1700, or 1000 sats). Asserts verification succeeds.
* **Test Location:** [`tests/export_tests/mod.rs::export_ark_labs_parity`](tests/export_tests/mod.rs#L11)
* **What this proves:** The public export API (`create_vpack_ark_labs`) produces byte-identical V-PACKs to the internal pipeline. External consumers (wallets, verifiers) using the public API will get correct results.

### Export API Parity (Second Tech)

* **Description:** Same structure as the Ark Labs export test, but using `second_tech_ingredients_from_json` and `create_vpack_second_tech`. Uses 13000 sats for `round_v3_borsh.json` and 10000 sats for other vectors.
* **Test Location:** [`tests/export_tests/mod.rs::export_second_tech_parity`](tests/export_tests/mod.rs#L51)
* **What this proves:** The public export API for Second Tech VTXOs produces correct, verifiable V-PACKs. This confirms parity between the internal and external API surfaces.

### WASM Adapter Auto-Inference

* **Description:** Two tests load JSON conformance vectors (one Ark Labs, one Second Tech) and pass them through the `LogicAdapter` auto-inference pipeline. The pipeline tries `ArkLabsAdapter::map_ingredients` first, then `SecondTechAdapter::map_ingredients`. For each, it asserts: (1) `verify()` succeeds, (2) the inferred variant string is correct (`"0x04"` for Ark Labs, `"0x03"` for Second Tech). *These tests require the `adapter` feature flag plus `bitcoin` or `wasm`.*
* **Test Locations:**
  * [`src/lib.rs::wasm_verify_auto_inference_ark_labs_round_leaf_v3`](src/lib.rs#L193) -- asserts variant `"0x04"`
  * [`src/lib.rs::wasm_verify_auto_inference_second_round_v3_borsh`](src/lib.rs#L201) -- asserts variant `"0x03"`
* **Feature Gate:** `#[cfg(all(test, feature = "adapter", any(feature = "bitcoin", feature = "wasm")))]`
* **What this proves:** A WASM-based verifier (e.g., a browser wallet) can accept raw JSON without knowing the VTXO type in advance. The adapter layer correctly infers which consensus engine to use and verifies the VTXO, enabling implementation-agnostic verification UIs.

---

## 5. Forensic Hash Verification

*These tests operate at the lowest level: raw bytes in, hash out. They verify that `libvpack-rs` computes VTXO IDs using the same hash function and preimage layout as the reference implementations. This is the "naked hash" layer -- no tree construction, no parsing, just `sha256d(bytes) == expected_id`. These tests exist to catch subtle preimage encoding bugs (byte order, version fields, serialization format) that would silently produce wrong VTXO IDs.*

### Naked Hash: Ark Labs Leaf (V3 Preimage)

* **Description:** Takes a hardcoded hex string representing the V3 transaction preimage for a round leaf VTXO. Computes `sha256d` (double-SHA256 in Bitcoin display order: bytes reversed for human readability). Asserts the result equals the gold-standard `expected_vtxo_id` string.
* **Test Location:** [`tests/forensic_verification.rs::naked_hash_ark_labs_leaf_version_2_vs_3`](tests/forensic_verification.rs#L39)
* **What this proves:** The raw preimage bytes, when double-SHA256'd, produce the correct VTXO ID. This is the most fundamental correctness check: it bypasses all library code and directly validates the preimage encoding.

### Naked Hash: Ark Labs Branch (V3 vs V2 Version Sensitivity)

* **Description:** Takes the V3 branch preimage hex, computes sha256d, and asserts it matches the expected branch ID. Then flips byte 0 from `0x03` to `0x02` (simulating a V2 preimage) and asserts the hash does *not* match.
* **Test Location:** [`tests/forensic_verification.rs::naked_hash_ark_labs_branch_version_2_vs_3`](tests/forensic_verification.rs#L56)
* **What this proves:** The version byte is part of the preimage and affects the hash. V2 and V3 preimages for the same transaction produce different VTXO IDs. This confirms that version-3 virtual transactions (which Ark uses) are distinct from hypothetical version-2 transactions.

### Naked Hash: Ark Labs OOR Forfeit (V3 vs compute_txid)

* **Description:** Decodes the OOR forfeit preimage hex as a `bitcoin::Transaction` using the `bitcoin` crate's consensus decoder, calls `compute_txid()`, and asserts the result matches the sha256d of the raw bytes. Also verifies that flipping to V2 breaks the match.
* **Test Location:** [`tests/forensic_verification.rs::naked_hash_ark_labs_oor_version_2_vs_3`](tests/forensic_verification.rs#L80)
* **What this proves:** The library's preimage layout for OOR forfeit transactions is identical to Bitcoin's consensus transaction serialization. The `bitcoin` crate's `compute_txid` and a manual sha256d of the raw bytes agree, confirming there are no hidden encoding differences.

### Second Tech SHA256 vs SHA256d Discrimination

* **Description:** Loads `round_v3_borsh.json`, extracts the `borsh_hex` (the raw Borsh-serialized VTXO tree bytes from Second Tech's storage format), and hashes it with both single-SHA256 and double-SHA256 (sha256d). Compares both results against `expected_vtxo_id`. Asserts that at most one can match, and that if single-SHA256 matches, it panics (contradicting the audit finding that Second Tech uses sha256d). Skips if `borsh_hex` is absent.
* **Test Location:** [`tests/conformance/mod.rs::second_round_v3_borsh_hash_single_vs_double_sha256`](tests/conformance/mod.rs#L832)
* **What this proves:** This test documents and enforces the hash function choice: Second Tech uses double-SHA256 (sha256d), not single-SHA256, for VTXO ID computation. If a future implementation change switches hash functions, this test will catch it.

### Second Tech Reconstructed Virtual Transaction

* **Description:** Loads `round_v3_borsh.json` and attempts to reconstruct a Bitcoin virtual transaction (Version 3, 1 input, 1 output, locktime 0) from the Borsh payload. Tries multiple strategies to extract the output script and anchor from the payload bytes. If reconstruction succeeds, asserts that `compute_txid()` of the reconstructed transaction matches the expected VTXO ID hash and that `vout` is 0. Skips if `borsh_hex` is absent.
* **Test Location:** [`tests/conformance/mod.rs::second_round_v3_reconstructed_tx_sha256d_matches_expected_vtxo_id`](tests/conformance/mod.rs#L901)
* **What this proves:** The VTXO ID for Second Tech is the TxID of a virtual Bitcoin transaction. By reconstructing that transaction from raw Borsh data and computing its TxID, this test validates the exact preimage layout that `bark` uses. This is the forensic alignment test: it proves the library agrees with `bark` on the byte-level structure of virtual transactions.

### Master Universal Verification

* **Description:** Loads one Ark Labs vector (`round_leaf_v3.json`) and one Second Tech vector (`round_v3_borsh.json`). For each, manually constructs a `VPackTree`, packs it into bytes, and calls `vpack::verify()`. Asserts both verifications succeed and that the returned tree has non-empty data (script_pubkey or amount > 0). This is the single test that proves both consensus engines work through the same `verify()` entrypoint.
* **Test Location:** [`tests/forensic_verification.rs::master_universal_verification`](tests/forensic_verification.rs#L131)
* **What this proves:** The `vpack::verify()` function is truly universal: the same function accepts V-PACKs from both Ark Labs and Second Tech, dispatches to the correct consensus engine based on the header's `TxVariant`, and returns a verified tree. A wallet or verifier does not need to know which implementation created the VTXO.

---

## 6. Transaction Factory & Wire Format

*The transaction factory (`tx_factory`) is responsible for producing the exact byte sequence of virtual Bitcoin transactions. These transactions are never broadcast to the Bitcoin network -- they are virtual -- but their serialization must be byte-for-byte identical to what `arkd` or `bark` produces, because the sha256d of these bytes *is* the VTXO ID. A single extra byte, wrong byte order, or missing field produces a different hash and a different (invalid) VTXO ID.*

### Preimage Byte Parity (OOR Forfeit)

* **Description:** Loads the `oor_forfeit_pset.json` vector, extracts the `unsigned_tx_hex` (the reference transaction bytes from the Ark Labs builder), and reconstructs the same transaction using `tx_preimage()` with the anchor's TxID/vout, output scripts, and values. Asserts the output is byte-for-byte identical to the reference.
* **Test Location:** [`src/consensus/tx_factory.rs::test_factory_parity_v3_oor`](src/consensus/tx_factory.rs#L233)
* **Vectors:** `tests/conformance/vectors/ark_labs/oor_forfeit_pset.json` field `raw_evidence.unsigned_tx_hex`
* **What this proves:** The transaction factory produces output identical to `arkd`'s builder. This is the byte-level parity guarantee: the library does not add, remove, or reorder any bytes compared to the reference implementation.

### Signed Transaction Layout (SegWit)

* **Description:** Uses the same OOR forfeit vector data but calls `tx_signed_hex()` with a dummy 64-byte signature. Asserts: (1) the output starts with version 3 LE + SegWit marker `0x00` + flag `0x01`, (2) it ends with 4-byte locktime `0x00000000`, (3) the signature bytes appear at the expected position (last 68 bytes = 64-byte sig + 4-byte locktime), and (4) total length equals `preimage_len + 2 (marker/flag) + 66 (witness: 1 item-count + 1 length + 64 sig)`.
* **Test Location:** [`src/consensus/tx_factory.rs::test_factory_signed_v3_parity`](src/consensus/tx_factory.rs#L279)
* **What this proves:** Signed virtual transactions use correct SegWit serialization with the witness data in the right position. This matters for Second Tech's genesis path, where each step's signed transaction must be correctly formatted for the next step to reference it.

### Unsigned Transaction Legacy Format

* **Description:** Calls `tx_signed_hex()` with all signatures set to `None`. Asserts: (1) version is 3 LE, (2) bytes 4-5 are *not* `0x00 0x01` (no SegWit marker/flag), and (3) the output is byte-identical to `tx_preimage()`. This confirms that unsigned transactions use legacy (non-SegWit) serialization.
* **Test Location:** [`src/consensus/tx_factory.rs::test_factory_unsigned_uses_legacy_format`](src/consensus/tx_factory.rs#L347)
* **What this proves:** When no signatures are present, the transaction factory produces legacy-format transactions that are identical to the preimage. This is critical because the VTXO ID is computed from the unsigned preimage -- if the unsigned format differed from the preimage, the computed ID would be wrong.

---

## 7. Serialization & Identity Roundtrips

*These tests verify that data survives a full encode-decode cycle without loss or corruption. A V-PACK is a binary format: a tree is serialized into bytes (packed), then those bytes are deserialized back into a tree (parsed). If any field is lost, reordered, or truncated during this process, the VTXO becomes unverifiable. Additionally, VTXO IDs must round-trip correctly through their string representation (human-readable hex) and back.*

### VtxoId Parse/Display Roundtrip (Ark Labs Raw Hash)

* **Description:** Parses a 64-character hex string as a `VtxoId`. Asserts it produces the `Raw` variant with bytes in internal (reversed) order -- following Bitcoin's TxID convention where the display string is the byte-reversed hash. Then asserts `format!("{}", id)` reproduces the original string.
* **Test Location:** [`src/consensus/mod.rs::vtxo_id_parse_ark_labs_raw_hex`](src/consensus/mod.rs#L243)
* **What this proves:** Ark Labs VTXO IDs (which are raw 32-byte hashes without a vout) parse and display correctly using Bitcoin's byte-reversal convention. A VTXO ID copied from a block explorer or `arkd` log can be pasted into the verifier and will be interpreted correctly.

### VtxoId Parse/Display Roundtrip (Second Tech OutPoint)

* **Description:** Parses a `"Hash:Index"` string (e.g., `"c806...d662:0"`) as a `VtxoId`. Asserts it produces the `OutPoint` variant with `vout == 0`. Asserts `format!("{}", id)` reproduces the original string.
* **Test Location:** [`src/consensus/mod.rs::vtxo_id_parse_second_tech_outpoint`](src/consensus/mod.rs#L269)
* **What this proves:** Second Tech VTXO IDs (which include a vout index after the hash) parse and display correctly. The colon-separated format is handled, and the vout is preserved through the roundtrip.

### VPackTree Serialization Roundtrip

* **Description:** Constructs a minimal `VPackTree` with known field values (`internal_key = [0xAA; 32]`, `asp_expiry_script = [0x51, 0x02]`, specific anchor and leaf values). Packs it via `pack()`, then parses the header and payload back via `BoundedReader::parse()`. Asserts the reconstructed tree equals the original (via `PartialEq`), and independently checks that `internal_key` and `asp_expiry_script` survived.
* **Test Location:** [`src/payload/tests.rs::test_vpack_tree_serialization_roundtrip`](src/payload/tests.rs#L21)
* **Feature Gate:** `#[cfg(any(feature = "bitcoin", feature = "wasm"))]`
* **What this proves:** The binary serialization format preserves every field in the tree structure. No data is lost during packing, and the parser correctly reconstructs all fields including the internal key and expiry script (which were added later in the format and could be regression-prone).

### End-to-End Pack-then-Verify Consistency (Both Engines)

* **Description:** Constructs full trees for both Ark Labs (from `round_leaf_v3.json` ingredients) and Second Tech (manually constructed 5-step path with real scripts). For each: packs into bytes, calls `vpack::verify()`, and asserts the returned tree's fields match the original: `leaf.amount`, `leaf.script_pubkey`, `anchor`, `fee_anchor_script`, and `path.len()`.
* **Test Location:** [`tests/conformance/mod.rs::test_vpack_internal_consistency_roundtrip`](tests/conformance/mod.rs#L1041)
* **What this proves:** The complete lifecycle -- construct tree, pack into binary, verify (which internally unpacks, recomputes the VTXO ID, and checks it), return the verified tree -- preserves all user-visible fields for both consensus engines. This is the most comprehensive roundtrip test: it exercises packing, parsing, ID computation, and field extraction in a single pipeline.

---

## 8. Mutation testing & consensus hardening

*Beyond unit and integration tests, the project runs [**cargo-mutants**](https://mutants.rs/) to search for “surviving” code changes: if a syntactic mutant (e.g. flipping an operator or eliding a check) still passes the full test suite, that mutant is a **miss** — a sign that tests or structure should be tightened. This section documents how that audit is run and how recent consensus refactors relate to it.*

### CI workflow

* **Workflow:** [`.github/workflows/audit.yml`](.github/workflows/audit.yml) — **Audit (Mutation Testing)**.
* **Triggers:** `workflow_dispatch` and a **daily** `schedule` (`cron: "0 0 * * *"`).
* **Command (high level):** `cargo mutants --package vpack --all-features --file "src/consensus/*"` with a **function-name filter** (`-F`) limiting mutations to `validate_.*`, `verify_.*`, `compute_vtxo_id`, `reconstruct_.*`, and `audit_.*` — i.e. consensus validation and reconstruction surfaces, not unrelated crates.
* **`--all-features`:** Builds **all** optional `vpack` features in the mutants run, including **`schnorr-verify`**. That way BIP-340 Schnorr checks inside `compute_vtxo_id` are compiled and exercised under mutation, reducing **false survivors** that appear only when gated code is left out of the build.
* **`--baseline skip` / `--jobs 4`:** Skips unchanged baseline bookkeeping where configured; uses parallel workers for throughput on CI.

### Equivalent mutants and the `prev_outputs` refactor

* Previously, `compute_vtxo_id` kept **two** optional vectors (`prev_output_values` and `prev_output_scripts`) and guarded indexing with `idx >= a.len() || idx >= b.len()`. When both vectors are always populated in lockstep from the same reconstructed outputs, `cargo-mutants` could introduce **`replace || with &&`** mutants that were **semantically equivalent** (no test could distinguish them), producing noisy **MISSED** results.
* The implementation now uses a **single** `Vec<ReconstructedOutput>` (`value` + `script_pubkey`) and a **single** check `idx >= prev.len()`. The redundant `||` gate is gone, so that class of equivalent mutant **no longer exists** in the source.

### Local verification vs. mutants temp dirs

* **Ground truth:** `cargo test -p vpack --all-features` (from a normal checkout) is the authoritative check that consensus, guards, and conformance still pass after changes.
* **Caveat:** `cargo-mutants` copies the package into a **temporary build tree**. Tests that read files only via paths relative to the **real** repository (e.g. JSON next to `tests/`) may not see those files in the temp tree unless the project configures mutants to copy extra data or uses paths anchored consistently. If an unmutated baseline fails inside mutants but passes in CI/unit tests, investigate fixture visibility rather than consensus logic.

### Related integration tests

* **[`tests/consensus_guard_tests.rs`](tests/consensus_guard_tests.rs)** — variant confusion, `InvalidVout` / `FeeAnchorMissing` / `ValueMismatch`, hand-off `parent_index`, and the **`engine_schnorr`** split-sabotage cases (Section 3) that specifically stress the Schnorr branch on **`path[1]`** for both engines.

---

## Appendix: Test Coverage Summary

| Category | Tests | Positive | Negative/Sabotage |
|----------|-------|----------|-------------------|
| 1. Cryptographic Primitives | 6 | 6 | 0 |
| 2. Tree Reconstruction & VTXO ID | 7 + structural note | 7 + 0 | 0 |
| 3. Sabotage Detection & Path Exclusivity | ~20 | 2 (valid baseline) | ~18 |
| 3.1 Sovereignty & Inclusion Guarantees | 6 | 2 (valid baseline + sorting) | 4 |
| 4. JSON Conformance & Standardization | 6 | 6 | 0 |
| 5. Forensic Hash Verification | 6 | 6 | 0 |
| 6. Transaction Factory & Wire Format | 3 | 3 | 0 |
| 7. Serialization & Identity Roundtrips | 4 | 4 | 0 |
| 8. Mutation testing | process (cargo-mutants) | — | — |
| **Total** | **~58+** | **~36** | **~22** |

*Note: `run_conformance_vectors` and `run_integrity_sabotage` iterate over all 6 JSON vectors, so their effective test count is higher than the single `#[test]` function suggests. Diagnostic/print-only tests (e.g., `print_computed_vtxo_id`, `vpack_byte_size_summary`) and `#[ignore]`-tagged one-off generators are excluded from this count as they contain no assertions.*

### Features Required for Full Test Coverage

| Feature Flag | Tests Gated |
|-------------|-------------|
| `bitcoin` or `wasm` | All tests in categories 2-7 (consensus, payload, export) |
| `adapter` + (`bitcoin` or `wasm`) | WASM auto-inference tests in category 4 |
| `schnorr-verify` | `test_sabotage_invalid_signature` in category 3; `engine_schnorr` tests in [`tests/consensus_guard_tests.rs`](tests/consensus_guard_tests.rs); all tests in category 3.1 (Sovereignty & Inclusion Guarantees) |

### Not Yet Covered (Known Gaps)

The following protocol features are *not* exercised by the current test suite. 

- **[HIGH] Tweak parity bit enforcement (BIP-341)**: No test asserts that `compute_taproot_tweak` preserves the correct even/odd Y-coordinate parity. A wrong parity bit produces a valid-looking P2TR address whose Schnorr signatures fail on-chain -- an "unspendable VTXO" the user believes they own.
- **[HIGH] Resource exhaustion / denial of service (hardware security)**: No test feeds pathological inputs (depth-bomb V-PACKs, near-`MAX_PAYLOAD_SIZE` payloads, deeply nested nodes) to the `no_std` parser. A malicious ASP could crash or brick a hardware wallet via stack overflow or heap exhaustion.
- **[HIGH] Sighash flag conformance**: No test asserts that reconstructed virtual transactions produce the correct sighash preimage for the flag (`SIGHASH_DEFAULT` / `SIGHASH_ALL`) the user's signature was generated against. A structurally valid exit transaction with a mismatched sighash commitment is unsignable.
- **[HIGH] `exit_delta` and `expiry` fields**: Set to 0 in all test trees; no test verifies non-zero values affect ID computation or exit logic.
- **Liquid/Elements asset types**: `asset_id` is always `None` in all test vectors.
- **`Full` sibling variant**: All sibling nodes in tests use `SiblingNode::Compact`; the `SiblingNode::Full(TxOut)` variant is not tested.
- **Maximum depth/arity limits**: `MAX_TREE_DEPTH` (32) and `MAX_TREE_ARITY` (16) are referenced in headers but no test pushes these boundaries.
- **Error paths for malformed binary input**: No test feeds truncated, oversized, or garbage bytes to the parser.
- **Checksum validation**: The `checksum` field is always 0 in test headers; no test verifies CRC32 rejection.