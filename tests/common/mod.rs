//! Shared test helpers: logic-mapping adapters that build VPackTree from reconstruction_ingredients.

mod logic_adapters;

pub use logic_adapters::{
    second_path_from_tree, tree_from_ingredients, ArkLabsAdapter, LogicAdapter, SecondTechAdapter,
};
