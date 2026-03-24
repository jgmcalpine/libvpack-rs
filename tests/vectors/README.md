# JSON testing standard for `vpack` (libvpack-rs)

This document specifies how JSON fixtures relate to the crate’s typed reconstruction data.

## Universal contract: `VpackState`

`libvpack-rs` defines a versioned JSON envelope, [`VpackState`](../../src/state.rs), as the portable contract for passing Ark Labs (V3 anchored) or Second Tech (V3 plain) **reconstruction ingredients** between tools, tests, and integrations.

The envelope is strict by design:

- **`schema_version`** (string): must be `"1.0"` for the current release line. Other values are rejected at deserialization time.
- **`implementation`** (string): `"ark_labs"` or `"second_tech"`, describing which silo produced the payload.
- **`ingredients`** (object): a **flat** object whose fields are exactly those of [`ArkLabsIngredients`](../../src/export.rs) or [`SecondTechIngredients`](../../src/export.rs), with no extra wrapper key. The field `implementation` selects which struct shape to deserialize; duplicate tags like `"ark_labs": { ... }` inside `ingredients` are not used.

The root object uses Serde’s `deny_unknown_fields`: extra keys at the envelope level are errors, which catches schema drift and accidental or malicious fields early.

Ingredient objects reuse the same field names and hex encoding conventions as the historical `reconstruction_ingredients` blobs inside audit vectors (e.g. `nSequence`, `parent_outpoint` as an alias for anchor outpoint, scripts as lowercase hex strings). Existing helpers that parse raw audit JSON without the envelope remain valid for conformance tests.

## Conformance vectors (core set)

The six primary conformance JSON files live under `tests/conformance/vectors/`. Relative to that directory:

| File | Description |
|------|-------------|
| `ark_labs/round_leaf_v3.json` | Ark Labs V3-anchored **round** case with a single leaf output and no branch path—typical end-user VTXO after a cooperative round. |
| `ark_labs/round_branch_v3.json` | Ark Labs V3-anchored **branch** step: intermediate tree node with siblings and child output linking toward the leaf. |
| `ark_labs/oor_forfeit_pset.json` | Ark Labs **out-of-round (OOR) / forfeit** style scenario tied to PSBT-style evidence—non-cooperative path with distinct `nSequence` semantics. |
| `second/round_v3_borsh.json` | Second Tech V3-plain **round** VTXO reconstructed from (or aligned with) borsh-backed silo data and a multi-step genesis path where applicable. |
| `second/boarding_v3_borsh.json` | Second Tech **boarding** VTXO: depth-zero chain position when funds first enter the virtual layer under Second Tech rules. |
| `second/oor_v3_borsh.json` | Second Tech **OOR** V3-plain case: exit / out-of-round positioning with path and expiry aligned to the bark-style representation. |

These files use the broader **audit vector** layout (`meta`, `raw_evidence`, `reconstruction_ingredients`, optional `legacy_evidence`). Wrapping only the `reconstruction_ingredients` object inside `VpackState` yields a standalone `VpackState` document suitable for new tooling while preserving the same inner ingredient semantics.
