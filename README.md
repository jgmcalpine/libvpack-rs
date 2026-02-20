# `libvpack-rs`

**A lightweight, `no_std` Rust reference library for universal VTXO (Virtual UTXO) parsing, verification, and standardization.**(https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml)(https://img.shields.io/badge/cargo-v1.0.0--RC.2-green)](https://crates.io/crates/vpack)(https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[!(https://img.shields.io/badge/Standard-V--PACK-blue)](docs/specs/01-vbip.md)

⚠️ **CURRENT LIMITATION (See Phase 7):** `libvpack-rs` currently verifies **Path Existence** (that an exit path is structurally valid and signatures match) but does not yet verify **Path Exclusivity** (full Taproot tree reconstruction to prove the non-existence of alternative ASP spend paths). This is our current Priority 0.

## The VTXO: The Fundamental Unit of Layer 2 Scaling
As Bitcoin Layer 2 protocols evolve, the **Virtual UTXO (VTXO)** has emerged as the shared technical primitive. While protocols are exploring different throughput optimizations, the user's proof-of-ownership is ultimately an off-chain VTXO residing within a pre-signed transaction tree.

## The Problem: Client-Stack Dependency in Constrained Environments
As the VTXO ecosystem matures, implementations like **Arkade (by Ark Labs)** and **Bark (by Second)** are diverging into specific technical "dialects" optimized for different use cases. They handle outpoint indexing, relative timelocks, and mempool policies (such as CPFP and P2A package relay) differently. 

While both protocols are fully open-source and their off-chain state is entirely cryptographically verifiable, parsing this state natively currently requires importing a heavy, implementation-specific software stack. For highly constrained, high-security environments like `no_std` hardware wallets, importing these large dependency trees just to verify a signature and an outpoint is a major point of friction. 

## The Solution: V-PACK
`libvpack-rs` implements the **V-PACK** standard, a neutral, implementation-agnostic translation layer and verification engine. It allows hardware wallets and mobile clients to ingest, verify, and display VTXO state without needing to load an implementation's entire codebase.

### Key Features
*   **Implementation-Agnostic Parsing:** Seamlessly handles the structural and dialect differences between Arkade and Bark (e.g., 32-byte ID hashes vs. 36-byte OutPoint indexing).
*   **Hardware-Native (`no_std`):** Zero-dependency core logic designed strictly for resource-constrained devices like Coldcard, BitBox, or mobile Secure Enclaves.
*   **BIP-431 (TRUC) Ready:** Currently enforces deterministic Transaction Version 3 templates. The schema is actively being expanded to deeply parse and validate advanced mempool policies, specifically including Bark's Pay-to-Anchor (P2A) and 1p1c CPFP package relay topologies.
*   **Ultra-Compact:** Standard proofs are compressed to **~132 bytes**, allowing exit data to fit into a single QR code or Nostr note.

---

## Bridging the Dialect Gap
Arkade and Bark utilize distinct mathematical identities and sequencing logic for the same Bitcoin primitives. `libvpack-rs` bridges this gap at the data layer:

| Implementation | ID Format | Logic | Byte Size | nSequence Signal |
|:--- |:--- |:--- |:--- |:--- |
| **Arkade (Ark Labs)** | **Transaction-Native** | `sha256d(Bitcoin_V3_Tx)` | 32 Bytes | `0xFFFFFFFE` (TRUC RBF) |
| **Bark (Second)** | **Object-Native** | `sha256d(Tx):Index` | 36 Bytes | `0x00000000` (BIP-68 Timelocks) |

---

## Quick Start (Rust)

Add `vpack` to your `Cargo.toml`:
```toml
vpack = { version = "1.0.0-rc.2", default-features = false }
```

### 1. Verify a VTXO Independently
```rust
use vpack::{verify, VtxoId};

// Raw bytes from a V-PACK file, QR code, or Nostr note
let raw_vpack: & = get_bytes_from_backup(); 
let expected_id = VtxoId::from_str("47ea55bc...:0").unwrap();

// Mathematically reconstructs the path to the L1 anchor
match vpack::verify(raw_vpack, &expected_id) {
    Ok(tree) => println!("VTXO Verified! Amount: {:?}", tree.leaf.amount),
    Err(e) => eprintln!("Verification Failed: {:?}", e),
}
```

### 2. Universal Export (Standardization)
```rust
use vpack::export::{create_vpack_ark_labs, ArkLabsIngredients};

// Take raw ingredients (Amounts, Scripts, Sequences) from a specific 
// implementation and serialize them into the lightweight V-PACK standard.
let ingredients = ArkLabsIngredients { /* ... */ };
let universal_vpack = create_vpack_ark_labs(ingredients)?;
```

---

## WASM Support
The **wasm-vpack** workspace crate provides headless verification with auto-inference for web browsers.
```bash
cd wasm-vpack && wasm-pack build --target web
```
See the(https://vtxopack.org) for a live implementation of the VTXO-Inspector.

## Project Roadmap
- [x] **Phase 1-5: Forensic Audit & Core Logic.** Byte-level reconciliation of $nSequence$, Fee Anchors, and Identity Models across implementations.
- [x] **Phase 6: The VTXO-Inspector.** A WASM-powered visualizer at `vtxopack.org`, enabling users to parse and verify balances locally in the browser.
- [ ] **Phase 7 (CURRENT PRIORITY): Path Exclusivity (Sovereignty Pillar 2).** Moving beyond structural existence to guarantee path exclusivity. Implementing full Taproot tree reconstruction to mathematically prove that the *only* existing paths in the Taptree are the user's key-spend and the server's expiry path, verifying the non-existence of ASP backdoors.
- [ ] **Phase 8: The Sentinel (Weather Station).** Implementing automated "drift detection" in CI. Monitoring the Arkade and Bark codebases daily to ensure the V-PACK standard stays synchronized with divergent implementation changes.
- [ ] **Phase 9: The Fire Escape (Sovereign Recovery).** Transition from verifying IDs to generating and broadcasting fully-signed L1 transaction chains. Includes fee-rate awareness and Mempool.space API integration.
- [ ] **Phase 10: Universal Connect (Mobile Bindings).** Implementing UniFFI support to provide native Swift (iOS) and Kotlin (Android) bindings, allowing mobile wallets to integrate V-PACK verification as a standard feature.
- [ ] **Phase 11: V-Nostr State Recovery.** Defining a standardized NIP for encrypted V-PACK backups on Nostr. 
