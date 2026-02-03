# Forensic Audit Report: Ark Protocol Implementation Divergence
**Date:** February 2, 2026
**Status:** Concluded (Sniffing Window Closed)

## 1. Executive Summary
The forensic audit confirms that both major Ark implementations have adopted **Bitcoin Transaction Version 3 (TRUC)**. However, they are binary incompatible due to conflicting **Topologies** and **Identity Models**. Both implementations use **Double-SHA256** for hashing, but the data being hashed (the preimage) is structured differently.

## 2. Core Divergence Findings

### A. Tree Topology vs. Chain Topology
*   **Ark Labs (`arkd`):** Follows a **Tree Model**. Every VTXO is a leaf in a Merkle-style transaction tree. Reconstructing an ID requires knowledge of the branching factor (Arity).
*   **Second Tech (`bark`):** Follows a **Chain Model**. A VTXO is the end-point of a recursive chain of transactions. Reconstructing an ID requires iterating through the `genesis` vector, where each transaction spends the previous one.

### B. nSequence Policies
A critical "hidden" divergence was found in the input sequence numbers:
*   **Ark Labs (Round):** `0xFFFFFFFF` (MAX).
*   **Ark Labs (OOR):** `0xFFFFFFFE` (MAX-1).
*   **Second Tech (Standard):** `0x00000000` (ZERO).

### C. Identity Model (Hash vs. OutPoint)
*   **Ark Labs:** The ID is a 32-byte **TxID** (the hash of the virtual transaction).
*   **Second Tech:** The ID is a 36-byte **OutPoint** (`TxID:Index`). The index identifies which output in the round transaction belongs to the user.

## 3. Final Preimage Map

| Component | Field | Ark Labs (Variant 0x04) | Second Tech (Variant 0x03) |
| :--- | :--- | :--- | :--- |
| **Topology** | Layout | Flat Merkle Tree | Recursive Tx Chain |
| **Identity** | Format | 32-byte Hash (TxID) | 36-byte OutPoint (TxID:Index) |
| **Input** | Sequence | MAX (`0xFFFFFFFF`) | ZERO (`0x00000000`) |
| **Output N** | Fee Anchor | Mandatory (`51024e73`) | Mandatory (`fee::fee_anchor`) |
