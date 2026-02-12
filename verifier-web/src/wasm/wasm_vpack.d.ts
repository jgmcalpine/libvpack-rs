/* tslint:disable */
/* eslint-disable */

/**
 * Set the panic hook so Rust panics show up as readable errors in the browser console.
 */
export function init(): void;

/**
 * Computes the VTXO ID from reconstruction_ingredients only (no anchor_value).
 * Use for path verification before fetching L1. Tries ArkLabs then SecondTech.
 * Returns { variant, reconstructed_tx_id } or throws.
 */
export function wasm_compute_vtxo_id(json_input: string): any;

/**
 * Exports reconstruction_ingredients JSON to standard-compliant V-PACK binary.
 * Uses the same LogicAdapter mapping as verification (ArkLabs/SecondTech) for byte-perfect output.
 * JSON must include reconstruction_ingredients; anchor_value is not required for packing.
 * Returns raw bytes as Uint8Array, or throws on parse/encoding error.
 */
export function wasm_export_to_vpack(json_input: string): Uint8Array;

/**
 * Parses the V-PACK header and minimal payload prefix to extract anchor outpoint.
 * Validates magic bytes first. Returns { anchor_txid, anchor_vout, tx_variant, is_testnet }.
 * Use anchor_txid (display hex) with mempool.space for L1 fetch.
 */
export function wasm_parse_vpack_header(vpack_bytes: Uint8Array): any;

/**
 * Unpacks a binary V-PACK to JSON ingredients (reconstruction_ingredients + raw_evidence).
 * Allows the user to "see inside" any .vpk file. Does not verify—parse only.
 */
export function wasm_unpack_to_json(vpack_bytes: Uint8Array): string;

/**
 * Verifies reconstruction_ingredients JSON against expected_vtxo_id.
 * JSON must include anchor_value (L1 UTXO value in sats) as string or number.
 * Use string for full 64-bit range (e.g. "anchor_value": "1100").
 * Tries ArkLabs then SecondTech adapters; returns the first that parses and verifies.
 * Response: { variant, status: "Success"|"Failure", reconstructed_tx_id }.
 */
export function wasm_verify(json_input: string): any;

/**
 * Verifies a binary V-PACK directly (bypasses Logic Adapters).
 * Calls core vpack::verify() with bytes already in standard format.
 * anchor_value: Some(sats) for L1 verification; None for Test Mode (uses output sum).
 */
export function wasm_verify_binary(vpack_bytes: Uint8Array, anchor_value?: bigint | null): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wasm_compute_vtxo_id: (a: number, b: number) => [number, number, number];
    readonly wasm_export_to_vpack: (a: number, b: number) => [number, number, number, number];
    readonly wasm_parse_vpack_header: (a: number, b: number) => [number, number, number];
    readonly wasm_unpack_to_json: (a: number, b: number) => [number, number, number, number];
    readonly wasm_verify: (a: number, b: number) => [number, number, number];
    readonly wasm_verify_binary: (a: number, b: number, c: number, d: bigint) => [number, number, number];
    readonly init: () => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
