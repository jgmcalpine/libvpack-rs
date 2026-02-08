# BIP: V-PACK Universal Container for Virtual UTXOs (VTXOs)

**Title:** V-PACK: A Deterministic Binary Format for Off-Chain VTXO Verification  
**Author:** [Your Name] <[Your Email]>  
**Status:** Draft  
**Type:** Standards Track  
**Layer:** Presentation & Transport  
**Created:** 2026-02-01  
**License:** MIT  

## 1. Abstract

This proposal defines **V-PACK**, a deterministic binary container designed for the storage, transport, and independent verification of **Virtual UTXOs (VTXOs)**. V-PACK standardizes the "Map" (off-chain transaction tree) required to prove ownership of Bitcoin Layer 2 assets. The format is designed to be **Compact** (~132 bytes for typical leaves), **Hardware-Native** (4-byte aligned, `no_std` compatible), and **Implementation-Agnostic**, bridging the structural divergences between various Ark-style service providers.

## 2. Motivation

In standard Bitcoin, a 12-word seed phrase constitutes a complete backup of funds. In off-chain protocols utilizing VTXOs, the seed phrase is only "half a key." Because VTXOs exist as leaves on a private transaction tree, a user requires the specific **Transaction Path** leading from an on-chain anchor to their leaf to prove ownership or perform a unilateral exit.

Currently, the VTXO ecosystem is fragmented. Lead implementations (e.g., Ark Labs and Second Technologies) utilize divergent transaction templates, identity models, and sequence policies. This has created implementation-specific silos where:
1.  **Data Lock-in:** User backups are unreadable across different wallet implementations.
2.  **Sovereignty Risk:** If a specific service provider (ASP) fails, users lacking implementation-specific recovery tools cannot reconstruct their exit paths.
3.  **Hardware Blindness:** Hardware wallets cannot independently verify or sign VTXO spending without a standardized, deterministic template.

V-PACK resolves these issues by providing a universal "Grammar" to encapsulate the ingredients required to reconstruct and verify VTXOs regardless of the issuing silo.

## 3. Rationale

### 3.1 V3/TRUC Standard
V-PACK adopts **BIP-431 (Topologically Restricted Unexpected Clusters)** as its baseline. By enforcing Version 3 transaction rules, V-PACK ensures that all virtual transactions are immune to pinning attacks in the mempool during a unilateral exit.

### 3.2 Script-Path vs. Hash-Path
Early L2 designs assumed "Hash-Paths" (paying to a child's TxID). Forensic audit reveals that implementations use unique "Connector Scripts." V-PACK standardizes the inclusion of the literal **scriptPubKey** in the proof, ensuring the verifier does not have to guess implementation-specific key derivation logic.

### 3.3 Hardware Alignment
The 24-byte header is strictly 4-byte aligned. This ensures that low-resource microcontrollers (ARM Cortex-M) can parse V-PACKs without memory alignment faults or expensive padding.

## 4. Specification

### 4.1 Header (24 Bytes)

All integers are Little-Endian. The header enables "Fail-Fast" validation before cryptographic math is executed.

| Offset | Size | Name | Type | Description |
|:-------|:-----|:---------------|:-----|:------------|
| 0 | 3 | Magic | [u8; 3] | ASCII "VPK" (0x56 0x50 0x4B) |
| 3 | 1 | Flags | u8 | [0]: LZ4, [2]: Compact, [3]: AssetID |
| 4 | 1 | Version | u8 | V-PACK Format Version (0x01) |
| 5 | 1 | Tx Variant | u8 | 0x03=V3-Chain, 0x04=V3-Tree |
| 6 | 2 | Tree Arity | u16 | Max children per node |
| 8 | 2 | Tree Depth | u16 | Max levels (Parser Hard Limit) |
| 10 | 2 | Node Count | u16 | Total siblings in the proof path |
| 12 | 4 | Asset Type | u32 | 0=BTC, 1=Taproot Asset, 2=RGB |
| 16 | 4 | Payload Len | u32 | Size of the payload following the header |
| 20 | 4 | Checksum | u32 | CRC32 of bytes 0..19 + Payload |

**Checksum Rule:** To prevent circular dependency, bytes 20..23 are excluded from the hash.

### 4.2 Consensus Variants

Implementations MUST handle identity derivation based on the `Tx Variant` field:

*   **Variant 0x03 (V3-Chain):** Reconstructs a sequential chain of transactions. The VTXO identity is an **OutPoint** (`TxID:Index`). Input `nSequence` is enforced as `0x00000000`.
*   **Variant 0x04 (V3-Tree):** Reconstructs a fanned-out Merkle tree. The VTXO identity is a **32-byte Hash** (`TxID`). Input `nSequence` is enforced as `0xFFFFFFFF` (Rounds) or `0xFFFFFFFE` (OOR).

### 4.3 Payload Structure

The payload follows a strict linear layout to optimize battery life on mobile devices.

#### 4.3.1 Prefix Section (Fail-Fast)
1.  **Asset ID** (Optional, 32B): Present if `Flags & 0x08`.
2.  **Anchor OutPoint** (36B): The L1 TxID (32B) + Vout (4B).
3.  **Fee Anchor Script** (Borsh `Vec<u8>`): Mandatory for V3 variants.

#### 4.3.2 Tree Section (Borsh Encoded)
The tree is serialized top-down from the on-chain root to the leaf.

```rust
struct VPackTree {
    leaf: VtxoLeaf,
    path: Vec<GenesisItem>, 
}

struct VtxoLeaf {
    amount: u64,
    vout: u32,           // Required for OutPoint identities
    sequence: u32,       // nSequence policy
    expiry: u32,         // BIP-113 compliant timelock
    exit_delta: u16,     // Unilateral exit delay
    script_pubkey: Vec<u8>,
}

struct GenesisItem {
    siblings: Vec<SiblingNode>,
    parent_index: u32,
    sequence: u32,
    child_amount: u64,
    child_script_pubkey: Vec<u8>,
    signature: Option<[u8; 64]>, // For cosigned transitions
}
```

## 5. Backward Compatibility

V-PACK is a new standard and does not break existing Bitcoin consensus rules. Existing Ark implementations can support V-PACK by implementing a logic-mapping adapter that exports their internal "Receipts" into the V-PACK "Recipe" format.

## 6. Reference Implementation

A reference implementation in Rust (`no_std`) is available at:  
[https://github.com/jgmcalpine/libvpack-rs](https://github.com/jgmcalpine/libvpack-rs)
