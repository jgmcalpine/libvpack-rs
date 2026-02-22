# `libvpack-rs`: Independent VTXO Verification

**A pure-Rust, no_std clean-room engine for the independent auditing, visualization, and universal verification of Ark Layer 2 VTXOs.**

[![CI](https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jgmcalpine/libvpack-rs/actions/workflows/ci.yml) [![Crates.io](https://img.shields.io/badge/cargo-v1.0.0--RC.2-green)](https://crates.io/crates/vpack) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![V-PACK Standard](https://img.shields.io/badge/Standard-V--PACK-blue)](docs/specs/01-vbip.md)

⚠️ **CURRENT LIMITATION (See Phase 7):** `libvpack-rs` currently verifies **Path Existence** (that an exit path is structurally valid and signatures match) but does not yet verify **Path Exclusivity** (full Taproot tree reconstruction to prove the non-existence of alternative ASP spend paths). This is our current Priority 0.

## The VTXO: The Fundamental Unit of Layer 2 Scaling
As Bitcoin Layer 2 protocols evolve, the **Virtual UTXO (VTXO)** has emerged as the shared technical primitive. While protocols are exploring different throughput optimizations, a user's proof-of-ownership is ultimately an off-chain VTXO residing within a pre-signed transaction tree.

## The Need for Independent Verification
As the Ark ecosystem matures, implementations like **Arkade (by Ark Labs)** and **Bark (by Second)** are naturally diverging into specific technical "dialects" optimized for different use cases. While this rapid innovation is incredibly healthy for Bitcoin, it introduces three challenges for the broader ecosystem:

1. **Implementation-Coupled Verification:** Currently, core teams build both the ASP server and the client SDKs used to verify its operations. In complex cryptographic systems, shared assumptions between a server and its companion SDK can sometimes obscure edge cases. As noted by protocol developers, the ecosystem benefits heavily from an independent, "clean-room" verifier to provide thorough, external review of VTXO exits.
2. **Covenant Complexity:** Ark's underlying covenant math is brilliantly designed but highly complex. Even though the protocols are fully open-source, the raw Taproot tree structures can be difficult for newcomers and developers to visualize and fully grasp without dedicated educational tools.
3. **The Hardware Bottleneck:** Feature-rich client SDKs are excellent for hot wallets, but they inherently carry larger dependency footprints. For highly constrained, high-security environments like `no_std` hardware wallets, importing a full protocol stack just to verify an exit path is prohibitive.

## The Solution: V-PACK
`libvpack-rs` implements the **V-PACK** standard: a neutral, implementation-agnostic verification engine. It acts as the ecosystem's independent auditor and educational bridge.

### Core Pillars
*   **Independent Security Audit [In Progress]:** Moving towards a clean-room implementation of BIP-341 Taproot reconstruction. The goal is to independently verify "Path Exclusivity"—mathematically proving the strict absence of ASP backdoors. *(Note: `libvpack-rs` currently verifies structural existence; strict exclusivity auditing is the immediate next phase).*
*   **Transparency & Education [Current & Expanding]:** Powers local WASM visualizers (like `vtxopack.org`) that parse V-PACK payloads so developers and users can inspect the underlying components. Upcoming phases will upgrade this to graphically map the full Taproot tree and script execution logic.
*   **Hardware-Native (`no_std`) Baseline [Current]:** A zero-dependency core logic designed strictly for resource-constrained devices, establishing the foundational open-source plumbing that hardware wallets can eventually use to verify Ark natively without vendor lock-in.

---

## Bridging the Dialect Gap
Arkade and Bark utilize distinct mathematical identities and sequencing logic for the same Bitcoin primitives. `libvpack-rs` bridges this gap at the data layer to provide a unified verification standard:

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

### 1. Independently Audit a VTXO
```rust
use vpack::{verify, VtxoId};

// Raw bytes from an ASP, a V-PACK file, or local state
let raw_vpack: &[u8] = get_bytes_from_backup(); 
let expected_id = VtxoId::from_str("47ea55bc...:0").unwrap();

// Clean-room verification: mathematically reconstructs the path to the L1 anchor
match vpack::verify(raw_vpack, &expected_id) {
    Ok(tree) => println!("VTXO Verified! Independent Audit Passed. Amount: {:?}", tree.leaf.amount),
    Err(e) => eprintln!("Audit Failed - Invalid State: {:?}", e),
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

## WASM Support & "The Glass VTXO"
The **wasm-vpack** workspace crate provides headless verification with auto-inference for web browsers. This enables transparent educational tools.
```bash
cd wasm-vpack && wasm-pack build --target web
```
See [vtxopack.org](https://vtxopack.org) for a live implementation of the VTXO-Inspector.

---

## Project Roadmap

- [x] **Phase 1-5: Forensic Audit & Core Logic.** Byte-level reconciliation of nSequence, Fee Anchors, and Identity Models across divergent Ark implementations.
- [x] **Phase 6: The VTXO-Inspector.** A WASM-powered visualizer at `vtxopack.org`, enabling users to parse and verify L2 balances locally in the browser.
- [ ] **Phase 7 (CURRENT PRIORITY): Path Exclusivity Engine (Security & Cryptographic Audit).** Implementing pure-Rust BIP-341 Taproot reconstruction. Building the engine to audit the entire VTXO Taptree, mathematically proving the strict non-existence of ASP backdoors or hidden sweep scripts.
- [ ] **Phase 8: "The Glass VTXO" (Transparency & Education).** Upgrading the visualizer to parse and graphically display the full Taproot tree and underlying Bitcoin scripts, creating an interactive UX where developers can visually learn how Ark covenants execute.
- [ ] **Phase 9: "The Sentinel" (Automated Drift Detection & Code Review).** Implementing daily automated CI monitoring against upstream Arkade and Bark codebases to catch silent covenant changes, alerting the community and acting as an automated early-warning system.
- [ ] **Phase 10: The Fire Escape (Sovereign Recovery Generation).** Transitioning the library from verifying state to trustlessly generating fully-signed L1 exit transactions, complete with fee-rate awareness, allowing users to broadcast their sovereign exit independently of the ASP's proprietary software.
- [ ] **Phase 11: Standardized Specifications & Educational Deep-Dives.** Writing the formal V-PACK open-source specification and publishing technical deep-dives to educate newcomers on L2 Taproot engineering.

