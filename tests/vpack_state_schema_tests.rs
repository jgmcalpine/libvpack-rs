//! `VpackState` JSON envelope: schema version, strict fields, flat `ingredients` by `implementation`.

use vpack::export::create_vpack_ark_labs;
use vpack::{VpackImplementation, VpackIngredients, VpackState};

const VALID_ARK_LABS_ENVELOPE: &str = r#"{
  "schema_version": "1.0",
  "implementation": "ark_labs",
  "ingredients": {
    "parent_outpoint": "ecdeb06aa5a707d7d91177fd56dae8119d4e1b7505d197a765890ff346e6e3a4:0",
    "fee_anchor_script": "51024e73",
    "nSequence": 4294967295,
    "outputs": [
      {
        "value": 1100,
        "script": "51202e65d02c0d5a6f6a11cbf67692d0fc0c9f115661d945146511d3b6bf80825c1a"
      },
      {
        "value": 0,
        "script": "51024e73"
      }
    ],
    "internal_key": "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    "asp_expiry_script": "516903020040b27520002851fd1c7692e5ab649ce1a88bd8ba59e09401d78c4c8fe6ef93c405c4bbb8ad2008c65c69fb2bb155d81f914de7b0319a01f3ce89eaad8e212efaf835c58010a3ac"
  }
}"#;

#[test]
fn vpack_state_deserializes_schema_1_0_ark_labs() {
    let state: VpackState = serde_json::from_str(VALID_ARK_LABS_ENVELOPE).expect("valid envelope");
    assert_eq!(state.schema_version, VpackState::SCHEMA_VERSION);
    assert_eq!(state.implementation, VpackImplementation::ArkLabs);
    let VpackIngredients::ArkLabs(ingredients) = state.ingredients else {
        panic!("expected ArkLabs ingredients");
    };
    let bytes = create_vpack_ark_labs(ingredients).expect("pack from deserialized ingredients");
    assert!(!bytes.is_empty());
}

#[test]
fn vpack_state_json_round_trip_via_constructor() {
    let state: VpackState = serde_json::from_str(VALID_ARK_LABS_ENVELOPE).expect("parse");
    let VpackIngredients::ArkLabs(ingredients) = state.ingredients else {
        panic!("expected ArkLabs");
    };
    let again = VpackState::new_ark_labs(ingredients);
    let json = serde_json::to_string(&again).expect("serialize");
    let back: VpackState = serde_json::from_str(&json).expect("round-trip deserialize");
    assert_eq!(back.schema_version, VpackState::SCHEMA_VERSION);
    assert_eq!(back.implementation, VpackImplementation::ArkLabs);
}

#[test]
fn vpack_state_serialize_always_emits_schema_1_0() {
    let state: VpackState = serde_json::from_str(VALID_ARK_LABS_ENVELOPE).expect("parse");
    let VpackIngredients::ArkLabs(ingredients) = state.ingredients else {
        panic!("expected ArkLabs");
    };
    let tampered = VpackState {
        schema_version: "2.0".to_string(),
        implementation: VpackImplementation::ArkLabs,
        ingredients: VpackIngredients::ArkLabs(ingredients),
    };
    let json = serde_json::to_string(&tampered).expect("serialize");
    assert!(
        json.contains("\"schema_version\":\"1.0\""),
        "serialized JSON must always use canonical schema version, got: {json}"
    );
    let parsed: VpackState = serde_json::from_str(&json).expect("library parses its own output");
    assert_eq!(parsed.schema_version, VpackState::SCHEMA_VERSION);
}

#[test]
fn vpack_state_rejects_unknown_top_level_field() {
    let json = r#"{
        "schema_version": "1.0",
        "implementation": "ark_labs",
        "ingredients": { "parent_outpoint": "aa:0", "nSequence": 4294967295, "outputs": [{"value":1,"script":"51"}] },
        "malicious_flag": true
    }"#;
    let err = serde_json::from_str::<VpackState>(json).expect_err("unknown field must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("malicious_flag"),
        "expected unknown field error for malicious_flag, got: {msg}"
    );
}

#[test]
fn vpack_state_rejects_missing_implementation() {
    let json = r#"{
        "schema_version": "1.0",
        "ingredients": { "parent_outpoint": "aa:0", "nSequence": 4294967295, "outputs": [{"value":1,"script":"51"}] }
    }"#;
    let err = serde_json::from_str::<VpackState>(json).expect_err("missing implementation");
    let msg = err.to_string();
    assert!(
        msg.contains("implementation"),
        "expected missing field implementation, got: {msg}"
    );
}

#[test]
fn vpack_state_rejects_unsupported_schema_version() {
    let json = r#"{
        "schema_version": "2.0",
        "implementation": "ark_labs",
        "ingredients": { "parent_outpoint": "aa:0", "nSequence": 4294967295, "outputs": [{"value":1,"script":"51"}] }
    }"#;
    let err = serde_json::from_str::<VpackState>(json).expect_err("schema 2.0 must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("schema_version") || msg.contains("unsupported"),
        "expected unsupported schema_version error, got: {msg}"
    );
}
