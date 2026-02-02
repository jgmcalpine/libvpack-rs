# Forensic Audit Report: Ark Protocol Implementation Divergence
**Date:** February 2, 2026
**Status:** Concluded (Sniffing Window Closed)
**Targets:**
*   **Ark Labs:** `arkade-os/arkd`
*   **Second Technologies:** `ark-bitcoin/bark`

## 1. Executive Summary
The forensic audit confirms that while both major Ark implementations have adopted **Bitcoin Transaction Version 3 (TRUC)**, they remain **Binary Incompatible**. The divergence is not merely in formatting but in the "Preimage Philosophy" used to generate the VTXO ID.

## 2. Core Divergence Findings

### A. Transaction-Native vs. Object-Native
*   **Ark Labs (`arkd`):** Follows a **Transaction-Native** model. The VTXO ID is the `TxID` of a reconstructed virtual transaction.
*   **Second Tech (`bark`):** Follows an **Object-Native** model. The VTXO ID is an `OutPoint` where the hash is derived from the Borsh-serialization of the Rust struct itself, not a Bitcoin transaction.

### B. The Fee Anchor Requirement
The audit of `ark_labs/round_branch_v3.json` proves that Ark Labs enforces a mandatory **Fee Anchor** output (`51024e73`) on *every* level of the tree. Reconstructing an Ark Labs ID without this 4-byte script results in a total hash mismatch. Second Tech does not currently utilize this anchor in its virtual state.

### C. The nSequence Toggle
Sniffed data from `ark_labs/oor_forfeit_pset.json` revealed a critical consensus rule:
*   **Round Transactions:** Use `0xFFFFFFFF` (Sequence::MAX).
*   **OOR Transactions:** Use `0xFFFFFFFE`.
Standardizing this sequence in the V-PACK payload is necessary to support Out-of-Round payments.

## 3. Final Preimage Map

| Component | Field | Ark Labs (Variant 0x04) | Second Tech (Variant 0x03) |
| :--- | :--- | :--- | :--- |
| **Logic** | Hashing | Reconstructed Bitcoin V3 Tx | Borsh-serialized Struct |
| **Identity** | Format | 32-byte Hash (TxID) | 36-byte OutPoint (Hash:Index) |
| **Input** | Sequence | Context-dependent (MAX or MAX-1) | Usually Zero or MAX |
| **Output N** | Fee Anchor | **Mandatory** (`51024e73`) | **Absent** |
| **Math** | Algorithm | Double-SHA256 | Double-SHA256 (on Struct) |

## 4. Technical Conclusion
Project V-PACK serves as the **Rosetta Stone**. By encapsulating the raw ingredients (Amount, Script, Sequence, ExitDelta) into a single container, `libvpack-rs` allows a user to "translate" their Bitcoin state between these two incompatible siloes without an on-chain transaction.