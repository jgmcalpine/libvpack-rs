# VTXO Inspector — Web Portal

**The public gateway to the VTXO-PACK standard. An interactive, local-first auditor for Bitcoin Layer 2 sovereignty.**

Live at: [vtxopack.org](https://vtxopack.org)

## 1. Our Mission: Sovereignty & Education

The VTXO Inspector is built with two primary goals:

1.  **Sovereign Tooling:** We provide the "Life Raft" for the Ark ecosystem. By allowing users to independently verify their Virtual UTXOs (VTXOs) and visualize their exit paths, we ensure that self-custody is a technical reality, not just a marketing promise. Even if your service provider (ASP) disappears, the data provided here gives you the blueprint to reclaim your funds on the Bitcoin mainnet.
2.  **Visual Education:** For those new to Ark-style scaling, the protocol can feel like a "black box." Our **Sovereignty Path** visualizer uses a biological tree metaphor to demystify the hierarchy of off-chain transactions. By interacting with the "Roots" (L1), "Branches" (Intermediate links), and "Fruit" (your VTXO), users learn exactly how their money is secured by the blockchain.

## 2. Privacy First: The WASM Win

The VTXO Inspector is a **Static Web Application**. This means there is no "backend" server processing your data.

### Local-First Auditing
Traditional financial tools require you to upload your data to a server for analysis. In the Bitcoin ecosystem, this is a massive privacy risk. 
*   **The WASM Solution:** We compile our core Rust library (`libvpack-rs`) into **WebAssembly (WASM)**. 
*   **Zero-Knowledge Verification:** When you paste your VTXO ingredients into this site, the cryptographic math—reconstructing transactions, verifying Schnorr signatures, and auditing value conservation—happens **entirely inside your browser**. 
*   **Your data never leaves your computer.** 

### What about Blockchain Queries?
To provide a complete audit, the site checks the status of your "Anchor" on the Bitcoin blockchain. 
*   **What we send:** We only send the **Anchor Transaction ID** (a piece of public on-chain data) to `mempool.space`.
*   **What we keep private:** The sensitive **Off-chain Tree** (your specific balance, your scripts, and your transaction history) is never sent to any external API. We cross-reference the ASP's private claims against the blockchain's public reality locally.

## 3. Powered by `libvpack-rs`

The "Brain" of this website is [libvpack-rs](../README.md), our open-source, `no_std` Rust reference library. 

The web app utilizes this library to:
*   **Map Silo Data:** Use logic-mapping adapters to translate Ark Labs and Second Tech dialects into a unified format.
*   **Passive Reconstruction:** Rebuild every virtual transaction in your path from scratch to ensure the ASP hasn't altered the rules.
*   **Signature Auditing:** Perform pure-Rust Schnorr verification to prove every step of your path is authorized and spendable.

## 4. Developer Setup

If you want to run the VTXO Inspector locally:

### Prerequisites
*   [Node.js](https://nodejs.org/) (v18+)
*   [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (to recompile the Rust engine)

### Installation
```bash
# From the verifier-web directory
npm install
```

### Syncing the WASM Engine
If you make changes to the core Rust library, you must sync the build:
```bash
# From the project root
cd wasm-vpack && wasm-pack build --target web
cd ../verifier-web && npm run wasm:sync
```

### Development
```bash
npm run dev
```

## 5. Roadmap
*   [x] **Stage 1:** Manual JSON Audit & Auto-Inference.
*   [x] **Stage 2:** Vertical "Sovereignty Path" Visualization.
*   [x] **Stage 3:** Universal `.vpk` binary export/import.
*   [ ] **Stage 4:** Emergency L1 Broadcaster (The Fire Escape).
*   [ ] **Stage 5:** Nostr-based state recovery integration.

---

**Built for the Bitcoin Community. No trackers. No servers. Just math.**