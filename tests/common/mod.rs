//! Shared test helpers: logic-mapping adapters and ingredient builders for export/conformance.

mod ingredients_from_json;
mod logic_adapters;

#[allow(unused_imports)]
pub use ingredients_from_json::{
    ark_labs_ingredients_from_json, second_tech_ingredients_from_json,
};
#[allow(unused_imports)]
pub use logic_adapters::{
    second_path_from_tree, tree_from_ingredients, ArkLabsAdapter, LogicAdapter, SecondTechAdapter,
};
