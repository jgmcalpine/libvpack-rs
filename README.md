# `libvpack-rs`

**The Universal Life Raft for VTXOs. A `no_std` Rust reference library for sovereign Virtual UTXO verification and emergency recovery.**

[![CI](https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml)
[![Cargo](https://img.shields.io/badge/cargo-v1.0.0--RC.2-green)](https://crates.io/crates/vpack)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: V-BIP-01](https://img.shields.io/badge/Standard-V--PACK-blue)](docs/specs/01-vbip.md)

## The VTXO: The Fundamental Unit of Bitcoin Scaling
As Bitcoin Layer 2 protocols evolve and diverge, the **Virtual UTXO (VTXO)** remains the shared technical primitive. Whether a protocol uses fanned-out connector trees, sequential chains, or hash-locks for atomicity, the user's proof-of-ownership is ultimately a VTXO.

## The Problem: Implementation Lock-in
In the current ecosystem, implementations use incompatible mathematical identities and divergent transaction templates. This creates data silos where a user's balance is "invisible" to any software other than the one that issued it. If a provider goes offline, the user is locked out of their funds—even with their 12-word seed—because they lack the "Map" to the off-chain state.

## The Solution: V-PACK
`libvpack-rs` implements the **V-PACK** standard—a universal, implementation-agnostic digital envelope for VTXO state-trees. It acts as the **Universal Life Raft**, providing a standardized format for backups and verification that works across different scaling topologies.

### Key Features
*   **Passive Audit Logic:** Zero-assumption verification. The engine reconstructs transactions using only provided data, ensuring it never "fixes" or ignores malformed provider data.
*   **Agnostic Verification:** Supports multiple VTXO topologies, including **Binary Trees** (Ark Labs) and **Recursive Transaction Chains** (Second Tech).
*   **Hardware-Native (`no_std`):** Zero-dependency core logic designed to run on resource-constrained devices like Coldcard, BitBox, or mobile Secure Enclaves.
*   **BIP-431 (TRUC) Ready:** Enforces deterministic Transaction Version 3 templates to ensure safe, transparent signing.
*   **Ultra-Compact:** Standard proofs are compressed to **~132 bytes**, fitting into a single QR code or Nostr note.

---

## The Identity Mismatch: Bridging the Gap
Ark Labs and Second Technologies use incompatible mathematical identities for the same Bitcoin assets. `libvpack-rs` is the only tool that bridges this gap at the data layer:

| Model | ID Format | Logic | Byte Size |
|:--- |:--- |:--- |:--- |
| **Transaction-Native** | **Raw Hash** | `sha256d(Bitcoin_V3_Tx)` | 32 Bytes |
| **Object-Native** | **OutPoint** | `sha256d(Tx):Index` | 36 Bytes |

---

## Quick Start (Rust)

Add `vpack` to your `Cargo.toml`:
```toml
[dependencies]
vpack = { version = "1.0.0-rc.2", default-features = false }
```

### 1. Verify a VTXO Independently
```rust
use vpack::{verify, VtxoId};

// Raw bytes from a V-PACK file, QR code, or Nostr note
let raw_vpack: &[u8] = get_bytes_from_backup(); 
let expected_id = VtxoId::from_str("47ea55bc...:0").unwrap();

// Mathematically reconstructs the path to the L1 anchor
match vpack::verify(raw_vpack, &expected_id) {
    Ok(tree) => println!("VTXO Verified! Amount: {:?}", tree.leaf.amount),
    Err(e) => eprintln!("Verification Failed: {:?}", e),
}
```

### 2. Universal Export (The De-Siloer)
```rust
use vpack::export::{create_vpack_ark_labs, ArkLabsIngredients};

// Take raw ingredients (Amounts, Scripts, Sequences) from an existing 
// implementation and save them as a universal .vpk file.
let ingredients = ArkLabsIngredients { /* ... */ };
let universal_vpack = create_vpack_ark_labs(ingredients)?;
```

---

## WASM Support
The **wasm-vpack** workspace crate provides headless verification with auto-inference for web browsers.
```bash
cd wasm-vpack && wasm-pack build --target web
```
See the [Web Verifier Demo](https://vtxopack.org) for a live implementation.

## Project Roadmap
- [x] **Phase 1-5: Forensic Audit & Core Logic.** Byte-level reconciliation of $nSequence$, Fee Anchors, and Identity Models.
- [ ] **Phase 6 (Current): The VTXO-Inspector.** A WASM-powered "Sovereignty Path" visualizer at `vtxopack.org`. Enabling users to verify balances locally.
- [ ] **Phase 7: The Fire Escape (Sovereign Recovery).** Transition from verifying IDs to generating and broadcasting fully-signed L1 transaction chains. Includes fee-rate awareness and Mempool.space API integration.
- [ ] **Phase 8: The Sentinel (Weather Station).** Implementing automated "drift detection" in CI. Monitoring the Ark Labs and Second Tech codebases daily to ensure the V-PACK standard stays synchronized with divergent implementation changes.
- [ ] **Phase 9: Universal Connect (Mobile Bindings).** Implementing UniFFI support to provide native Swift (iOS) and Kotlin (Android) bindings, allowing mobile wallets to integrate V-PACK verification as a standard feature.
- [ ] **Phase 10: V-Nostr State Recovery.** Defining a standardized NIP for encrypted V-PACK backups on Nostr. This ensures that even if a user loses their device and the ASP is offline, their "Map" remains retrievable via their sovereign keys.