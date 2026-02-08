# `libvpack-rs`

**The Universal Life Raft for the Ark Ecosystem. A `no_std` Rust reference library for sovereign VTXO verification and emergency recovery.**

[![Cargo](https://img.shields.io/badge/cargo-v1.0.0--RC-green)](https://github.com/your-org/libvpack-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standard: V-BIP-01](https://img.shields.io/badge/Standard-V--BIP--01-blue)](docs/specs/01-vbip.md)

## The Problem: The "Half-Key" Trap
In standard Bitcoin, your 12-word seed is a complete backup. In the Ark Protocol, your seed is only half a key. Because a Virtual UTXO (VTXO) exists off-chain, you also need the **Transaction Tree (The Map)** to prove your ownership to the Bitcoin network.

The current Ark landscape is a series of isolated **"Liquidity Islands"** (Ark Labs, Second Technologies, etc.). While these islands are self-custodial, they speak divergent dialects. If your ASP disappears and you have lost your local data, your "fire escape" (unilateral exit) is effectively locked because no other software speaks the proprietary language required to reconstruct your exit path.

## The Solution: V-PACK
`libvpack-rs` implements the **V-BIP-01** standard—a universal, implementation-agnostic digital envelope for Ark state-trees. It acts as the **Universal Life Raft**, providing a standardized format for backups and verification that works across all Ark implementations.

### Key Features
*   **Sovereign Recovery:** Reconstruct your exit transactions independently of the ASP that issued them.
*   **Independent Auditing:** Verify that your funds are mathematically anchored to the Bitcoin blockchain without trusting your provider's UI.
*   **Hardware-Native (`no_std`):** Optimized to run on resource-constrained devices like hardware wallets or mobile Secure Enclaves.
*   **BIP-431 (TRUC) Ready:** Enforces the latest Version 3 transaction templates to ensure safe, deterministic signing.
*   **Ultra-Compact:** Standard proofs are compressed to **~132 bytes**, fitting easily into a single QR code or Nostr note.

---

## The Identity Mismatch: Why a Standard is Mandatory
Our [Forensic Audit](research/audit_data/AUDIT_SUMMARY.md) identified that the two leading Ark implementations use incompatible mathematical identities for the same Bitcoin assets. `libvpack-rs` is the only tool that bridges this 4-byte gap:

| Implementation | ID Format | Representation | Byte Size |
|:--- |:--- |:--- |:--- |
| **Ark Labs** | **Hash-Native** | `[32-byte TxID]` | 32 Bytes |
| **Second Tech** | **OutPoint-Native** | `[32-byte TxID] + [4-byte Index]` | 36 Bytes |

**The Result:** Without V-PACK, an Ark Labs proof is "gibberish" to a Second Tech wallet. V-PACK standardizes the underlying "Ingredients" (Amount, Script, Sequence) so that the correct ID can be calculated for **any** tool.

---

## Technical Specifications: The Silo Map
`libvpack-rs` handles the specific "Dialect" divergences required for emergency exits:

| Feature | Variant 0x03 (V3-Chain) | Variant 0x04 (V3-Tree) |
|:---|:---|:---|
| **Primary Topology** | Recursive Transaction Chain | Fanned-out Merkle Tree |
| **nSequence Policy** | `0x00000000` (Zero) | `0xFFFFFFFF` / `0xFFFFFFFE` |
| **Fee Anchor** | Mandatory | Mandatory |
| **Verification Math** | Sequential Reconstruction | Recursive Tree Hashing |

---

## Quick Start (Rust)

Add `vpack` to your `Cargo.toml`:
```toml
[dependencies]
vpack = { git = "https://github.com/your-org/libvpack-rs", default-features = false }
```

**Verify a VTXO Independently:**
```rust
use vpack::{verify, VtxoId};

// Raw bytes from a V-PACK file or QR code
let raw_vpack: &[u8] = get_bytes_from_backup(); 
let expected_id = VtxoId::from_str("47ea55bc...:0").unwrap();

// Mathematically reconstructs the path to the L1 anchor
match vpack::verify(raw_vpack, &expected_id) {
    Ok(tree) => println!("Verification Success! Amount: {:?}", tree.leaf.amount),
    Err(e) => eprintln!("Verification Failed: {:?}", e),
}
```

**Universal Export (The De-Siloer):**
```rust
use vpack::export::{create_vpack_ark_labs, ArkLabsIngredients};

// Take raw ingredients from any ASP and save them as a universal .vpk file
let ingredients = ArkLabsIngredients { /* ... */ };
let universal_vpack = create_vpack_ark_labs(ingredients)?;
```

---

## Project Roadmap

- [x] **Phase 1-5:** Forensic Audit & Core Logic Implementation (V3/TRUC).
- [ ] **Phase 6 (Current):** **The Ark-Inspector** — A WASM web tool for browser-side V-PACK auditing and visualization.
- [ ] **Phase 7:** **The Emergency Broadcaster** — Reconstructing and pushing exit chains to L1 via Mempool.space/Esplora.
- [ ] **Phase 8:** **Language Bindings** — UniFFI support for Swift (iOS) and Kotlin (Android).
- [ ] **Phase 9:** **V-Nostr** — Standardizing encrypted state-backups over the Nostr relay network.

## Grant Support & Referrals
This project is an independent effort to increase Bitcoin sovereignty. We are currently seeking support from **OpenSats** and other Bitcoin-native donors to maintain this library as a neutral safety net for the Ark ecosystem.
