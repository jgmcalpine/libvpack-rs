# `libvpack-rs`

**The Universal Life Raft for VTXOs. A `no_std` Rust reference library for sovereign Virtual UTXO verification and emergency recovery.**

[![Cargo](https://img.shields.io/badge/cargo-v1.0.0--RC.1-green)](https://github.com/jgmcalpine/libvpack-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: V-BIP-01](https://img.shields.io/badge/Standard-V--PACK-blue)](docs/specs/01-vbip.md)

## The VTXO: The Fundamental Unit of Bitcoin Scaling
As Bitcoin Layer 2 protocols evolve and diverge, the **Virtual UTXO (VTXO)** remains the shared technical primitive. Whether a protocol uses fanned-out connector trees, sequential chains, or hash-locks for atomicity, the user's proof-of-ownership is ultimately a VTXO.

## The Problem: Implementation Lock-in
In the current ecosystem, different implementations use incompatible mathematical identities and divergent transaction templates for their VTXOs. This creates data silos where a user's balance is "invisible" to any software other than the one that issued it. If a service provider goes offline and the local "map" to the money is lost, the user is locked out of their funds—even if they possess their 12-word seed phrase.

## The Solution: V-PACK
`libvpack-rs` implements the **V-PACK** standard—a universal, implementation-agnostic digital envelope for VTXO state-trees. It acts as the **Universal Life Raft**, providing a standardized format for backups and verification that works across different scaling topologies.

### Key Features
*   **Agnostic Verification:** Supports multiple VTXO topologies, including **Binary Trees** and **Recursive Transaction Chains**.
*   **Sovereign Auditing:** Verify that VTXO ingredients are mathematically anchored to the Bitcoin blockchain without trusting a server-side UI.
*   **Hardware-Native (`no_std`):** Zero-dependency core logic designed to run on resource-constrained devices like hardware wallets or mobile Secure Enclaves.
*   **BIP-431 (TRUC) Ready:** Enforces deterministic Transaction Version 3 templates to ensure safe, transparent signing on external devices.
*   **Ultra-Compact:** Standard proofs are compressed to **~132 bytes**, fitting easily into a single QR code or Nostr note.

---

## The Identity Mismatch: Bridging the Gap
Different implementations use incompatible identities for the same Bitcoin assets. `libvpack-rs` bridges these divergences at the data layer:

| Model | ID Format | Logic | Byte Size |
|:--- |:--- |:--- |:--- |
| **Transaction-Native** | **Raw Hash** | `sha256d(Bitcoin_V3_Tx)` | 32 Bytes |
| **Object-Native** | **OutPoint** | `sha256d(Tx):Index` | 36 Bytes |

V-PACK standardizes the underlying "Ingredients" (Amount, Script, Sequence, ExitDelta) so the correct identity can be calculated for any compliant tool.

---

## Technical Specifications
`libvpack-rs` handles the specific "Dialect" divergences identified in our [Forensic Audit](research/audit_data/AUDIT_SUMMARY.md):

| Feature | Variant 0x03 (V3-Chain) | Variant 0x04 (V3-Tree) |
|:---|:---|:---|
| **Topology** | Sequential Connector Chain | Fanned-out Merkle Tree |
| **nSequence** | `0x00000000` (Zero) | `0xFFFFFFFF` / `0xFFFFFFFE` |
| **Fee Anchor** | Mandatory | Mandatory |

---

## Quick Start (Rust)

Add `vpack` to your `Cargo.toml`:
```toml
[dependencies]
vpack = { version = "1.0.0-rc.1", default-features = false }
```

**Verify a VTXO Independently:**
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

---

## WASM (Milestone 6.1)
The **wasm-vpack** workspace crate exposes headless verification with auto-inference (Ark Labs vs Second Tech). Install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) and the target (`cargo install wasm-pack` and `rustup target add wasm32-unknown-unknown`), then build and run the demo:
```bash
cd wasm-vpack && wasm-pack build --target web && npx serve .
```
Then open the printed URL and go to `/demo/`. See [wasm-vpack/README.md](wasm-vpack/README.md).

## Project Roadmap
- [x] **Phase 1-5:** Forensic Audit & Core VTXO Logic Implementation.
- [ ] **Phase 6 (Current):** **The VTXO-Inspector** — A WASM web tool for browser-side auditing and visualization.
- [ ] **Phase 7:** **Sovereign Recovery** — Tools to reconstruct and broadcast L1 exit chains.
- [ ] **Phase 8:** **Language Bindings** — UniFFI support for mobile wallet integration.
```
