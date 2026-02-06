**Date:** February 1, 2026  
**Subject:** Forensic Analysis of Ark Protocol Silos

Our forensic audit confirms that both major Ark implementations—**Ark Labs (arkd)** and **Second Technologies (bark)**—have converged on **Bitcoin Transaction Version 3 (TRUC)**. Despite this common versioning, the implementations are binary incompatible at the identity level. This structural divergence justifies the V-PACK standard’s dual consensus variants.

---

#### 1. Identity Model: OutPoint vs. Flat Hash (vout finding)

- **Second Tech** uses an **OutPoint Identity Model (Hash:Index)**. The VTXO ID is an OutPoint: the hash is the TxID of the final link in the recursive transaction chain, and the **index (vout)** identifies the specific output within that transaction. The vout is essential to the identity.
- **Ark Labs** uses a **Flat Hash Identity Model**. The VTXO ID is a raw 32-byte hash (the TxID of the virtual transaction) with **no index**. There is no vout in the identity.

This contrast—OutPoint (Hash:Index) vs. flat 32-byte hash—is a major structural finding that motivates V-PACK’s separate handling of Variant 0x03 and 0x04.

---

#### 2. Topology: Tree vs. Recursive Transaction Chain

- **Ark Labs** uses a **tree**: branch and leaf nodes, with a mandatory **Fee Anchor output** (`51024e73`) on *every* node. Reconstructing the ID requires building this tree of V3 transactions (user output + siblings + fee anchor) and taking its TxID.
- **Second Tech** uses a **Recursive Transaction Chain**: a linear chain of V3 transactions from anchor to leaf. Each link has outputs (next link + fee anchor); the verified math is the **chain of V3 transaction hashes**. Borsh is used for **storage only**; the identity is not a “struct hash” but the TxID (and vout) of the final transaction in that chain. The phrase **Recursive Transaction Chain** should be used for Second Tech to avoid reviving the incorrect “struct-hash” or “Borsh struct” identity description.

---

#### 3. Hashing Preimage

- **Ark Labs (Transaction-Native):** The ID is the `sha256d` of a reconstructed Bitcoin V3 transaction (inputs, outputs, locktime per Bitcoin consensus).
- **Second Tech (Recursive Transaction Chain):** The ID is the `sha256d` of a **Bitcoin V3 transaction** at each link; the final ID is the OutPoint (TxID:vout) of the leaf transaction. Borsh serialization is used only for on-disk/wire storage of the chain data, not as the hash preimage.

---

#### 4. The “Silent” nSequence Rule (Ark Labs)

Ark Labs uses a context-dependent `nSequence` in the virtual transaction inputs:

- **Rounds:** `nSequence` = **`0xFFFFFFFF`**.
- **OOR (Forfeit):** `nSequence` = **`0xFFFFFFFE`**.

Implementers must use the correct value for the context (Round vs. OOR) when reconstructing the transaction for verification.

---

#### Resolution via V-PACK

V-PACK bridges the two silos with two consensus variants:

- **Variant 0x03 (V3-Plain):** Second Tech — Recursive Transaction Chain; **OutPoint Identity (Hash:Index)**.
- **Variant 0x04 (V3-Anchored):** Ark Labs — Transaction tree with mandatory Fee Anchor; **Flat Hash Identity** (raw 32-byte TxID).
