# wasm-vpack

WASM wrapper for libvpack-rs: headless verification with auto-inference over Ark Labs and Second Tech silo formats.

**No C compiler required.** The library uses a type shim for wasm builds: only `bitcoin_hashes` (pure Rust) is used, so `secp256k1-sys` is not built and the resulting WASM is smaller.

## Prerequisites

Install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) and the `wasm32-unknown-unknown` target:

```bash
cargo install wasm-pack
rustup target add wasm32-unknown-unknown
```

## Build

From this directory:

```bash
wasm-pack build --target web
```

## Run the demo

Serve the crate root so both `pkg/` and `demo/` are available:

```bash
cd wasm-vpack
wasm-pack build --target web
npx serve .
```

Then open `http://localhost:5000/demo/` (or the URL printed by `serve`). The page runs `wasm_verify` on `ark_labs/round_leaf_v3.json` and `second/round_v3_borsh.json` and shows variant and status for each.
