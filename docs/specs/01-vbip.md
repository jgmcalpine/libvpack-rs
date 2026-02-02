# V-BIP-01: The V-PACK Container Format
**Version:** 1.1.0 (Audit-Corrected)
**Layer:** Presentation & Transport

## 1. Abstract
V-PACK is a deterministic binary container for off-chain Bitcoin transaction trees. It standardizes the storage and transport of Virtual UTXOs (vUTXOs) across different Ark Service Provider (ASP) implementations. It prioritizes **Compactness** (via Hybrid Proofs), **Fail-Fast Verification**, and **Hardware Alignment**.

## 2. Security & Validation Rules
1.  **Bounded Reader:** Parsers MUST NOT read more `path` items than specified in the `Tree Depth` header.
2.  **Consensus Variants:**
    *   **Variant 0x03 (V3-Plain):** Derived from Second Tech logic. Hashing is applied to a serialized object. 
    *   **Variant 0x04 (V3-Anchored):** Derived from Ark Labs logic. Hashing is applied to a reconstructed BIP-431 (TRUC) transaction including a mandatory Fee Anchor.
3.  **Expiry & Delta:** The `expiry` and `exit_delta` fields MUST be interpreted as absolute block heights or relative durations per BIP-113.
4.  **Checksum Exclusion:** Calculated over Bytes 0-19 of the Header + the Payload.

## 3. The Header (24 Bytes)
**Alignment:** 4-byte aligned. **Endianness:** Little-Endian.

| Offset | Size | Name | Type | Description |
|:-------|:-----|:---------------|:-----|:------------|
| 0 | 3 | Magic | [u8] | "VPK" (0x56 0x50 0x4B) |
| 3 | 1 | Flags | u8 | Bit 0: LZ4, Bit 2: Compact, Bit 3: AssetID |
| 4 | 1 | Version | u8 | V-PACK Version (0x01) |
| 5 | 1 | **Tx Variant** | u8 | **0x03=V3-Plain, 0x04=V3-Anchored** |
| 6 | 2 | Tree Arity | u16 | Children per node |
| 8 | 2 | Tree Depth | u16 | Max levels (Parser Limit) |
| 10 | 2 | Node Count | u16 | Total siblings (Complexity est.) |
| 12 | 4 | Asset Type | u32 | 0=BTC, 1=Taproot, 2=RGB |
| 16 | 4 | Payload Len | u32 | Size of data following header |
| 20 | 4 | Checksum | u32 | CRC32 (Bytes 0..19 + Payload) |

## 4. The Payload Structure

### 4.1 The Prefix Section (Fail-Fast)
1.  **Asset ID (Optional, 32 Bytes):** Present if `Flags & 0x08`.
2.  **Anchor OutPoint (36 Bytes):** `TxID` (32B) + `Vout` (4B).
3. **fee_anchor_script:** Vec<u8>

### 4.2 The Tree Section (Borsh Encoded)
```rust
struct VPackTree {
    leaf: VtxoLeaf,
    path: Vec<GenesisItem>, 
}

struct VtxoLeaf {
    amount: u64,
    script_pubkey: Vec<u8>, 
    vout: u32,           // Mandatory for OutPoint-based IDs (Variant 0x03)
    sequence: u32,       // 0xFFFFFFFF (Round) or 0xFFFFFFFE (OOR)
    expiry: u32,         // Timelock
    exit_delta: u16,     // Required for Second Tech security model
}

struct GenesisItem {
    siblings: Vec<SiblingNode>, 
    parent_index: u32,
    sequence: u32,
    child_amount: u64,       // Needed to reconstruct the Parent's Output Value
    child_script_pubkey: Vec<u8>, // Needed to reconstruct the Parent's Output Script
}