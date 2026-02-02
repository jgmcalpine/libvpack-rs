**Date:** February 1, 2026
**Subject:** Forensic Analysis of Ark Protocol Silos

Our forensic audit confirms that both major Ark implementations—**Ark Labs (arkd)** and **Second Technologies (bark)**—have converged on **Bitcoin Transaction Version 3 (TRUC)**. Despite this common versioning, the implementations are binary incompatible at the identity level.

#### Key Divergence Findings:

1.  **Identity Model (Hash vs. OutPoint):**
    *   **Ark Labs:** A VTXO ID is a raw 32-byte hash (the `TxID` of the virtual transaction).
    *   **Second Tech:** A VTXO ID is an **OutPoint** (`Hash:Index`). The hash is derived from a serialized object, and the index identifies the specific output within that object.

2.  **Hashing Preimage (Transaction vs. Struct):**
    *   **Ark Labs:** Utilizes **"Transaction-Native ID."** The ID is the `sha256d` of a reconstructed Bitcoin V3 transaction.
    *   **Second Tech:** Utilizes **"Object-Native ID."** The ID is the `sha256d` of a **Borsh-serialized Rust struct**. It does not follow Bitcoin transaction serialization rules.

3.  **Mandatory Topology (Fee Anchors):**
    *   **Ark Labs:** Enforces a mandatory **Fee Anchor output** (`51024e73`) on *every* node of the transaction tree (Leaves and Branches). Reconstructing a hash without this specific output results in an invalid ID.
    *   **Second Tech:** Employs a **"Plain" V3 model** without mandatory anchors in the virtual state.

4.  **The "Silent" Sequence Rule:**
    *   Ark Labs exhibits a context-dependent `nSequence` change. **Rounds** utilize `0xFFFFFFFF`, while **OOR (Forfeit)** transactions utilize **`0xFFFFFFFE`**. 

#### Resolution via V-PACK:
To bridge this gap, V-PACK establishes two primary Consensus Variants:
*   **Variant 0x03 (V3-Plain):** Targets the Second Tech "Object-Native" model.
*   **Variant 0x04 (V3-Anchored):** Targets the Ark Labs "Transaction-Native" model.
