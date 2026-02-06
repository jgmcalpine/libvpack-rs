# Release Candidate — Final File Tree

**Gate status:** `cargo test` GREEN (internal round-trips + conformance). `cargo check` zero warnings.

## File tree (cleaned repository)

```
vpack/
├── Cargo.toml
├── README.md
├── rust-toolchain.toml
├── docs/
│   ├── audits/
│   │   └── 01-audit-vtxo.md
│   ├── plans/
│   │   └── milestone-4.3.5-branch-reconstruction-revised.md
│   ├── release_candidate_file_tree.md   (this file)
│   └── specs/
│       └── 01-vbip.md
├── research/
│   └── audit_data/
│       ├── AUDIT_SUMMARY.md
│       ├── message.md
│       ├── ark_labs/
│       │   ├── oor_forfeit_pset.json
│       │   ├── round_branch_v3.json
│       │   └── round_leaf_v3.json
│       └── second/
│           ├── boarding_v3_borsh.json
│           ├── oor_v3_borsh.json
│           └── round_v3_borsh.json
├── src/
│   ├── lib.rs
│   ├── compact_size.rs
│   ├── error.rs
│   ├── header.rs
│   ├── pack.rs
│   ├── adapters/
│   │   ├── mod.rs
│   │   └── second_tech.rs
│   ├── consensus/
│   │   ├── mod.rs
│   │   ├── ark_labs.rs
│   │   ├── second_tech.rs
│   │   └── tx_factory.rs
│   └── payload/
│       ├── mod.rs
│       ├── reader.rs
│       └── tree.rs
└── tests/
    ├── test_main.rs
    ├── forensic_verification.rs
    ├── common/
    │   ├── mod.rs
    │   └── logic_adapters.rs
    ├── conformance/
    │   ├── mod.rs
    │   └── vectors/
    │       ├── ark_labs/
    │       │   ├── oor_forfeit_pset.json
    │       │   ├── round_branch_v3.json
    │       │   └── round_leaf_v3.json
    │       └── second/
    │           ├── boarding_v3_borsh.json
    │           ├── oor_v3_borsh.json
    │           └── round_v3_borsh.json
    └── fixtures/
        ├── ark_labs_round_leaf_preimage_hex.txt
        └── second_tech_round1_step0.json
```
