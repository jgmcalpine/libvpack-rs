//! Versioned JSON envelope for Ark Labs and Second Tech reconstruction ingredients.

use alloc::string::{String, ToString};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::export::{ArkLabsIngredients, SecondTechIngredients};

/// Supported L2 implementation for a [`VpackState`] payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpackImplementation {
    ArkLabs,
    SecondTech,
}

/// Ingredient payload; variant must match [`VpackState::implementation`].
#[derive(Debug, Clone)]
pub enum VpackIngredients {
    ArkLabs(ArkLabsIngredients),
    SecondTech(SecondTechIngredients),
}

/// Universal JSON contract: schema version, implementation tag, and typed ingredients.
///
/// JSON shape: `ingredients` is a **flat** object (either [`ArkLabsIngredients`] or
/// [`SecondTechIngredients`] fields), not wrapped in an `ark_labs` / `second_tech` key.
/// [`VpackImplementation`] selects which struct to deserialize.
#[derive(Debug, Clone)]
pub struct VpackState {
    /// Always [`Self::SCHEMA_VERSION`] when constructed via [`Self::new_ark_labs`] /
    /// [`Self::new_second_tech`]. Serialized JSON always emits this version regardless of this field.
    pub schema_version: String,
    pub implementation: VpackImplementation,
    pub ingredients: VpackIngredients,
}

impl Serialize for VpackState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("VpackState", 3)?;
        st.serialize_field("schema_version", Self::SCHEMA_VERSION)?;
        st.serialize_field("implementation", &self.implementation)?;
        match &self.ingredients {
            VpackIngredients::ArkLabs(i) => st.serialize_field("ingredients", i)?,
            VpackIngredients::SecondTech(i) => st.serialize_field("ingredients", i)?,
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for VpackState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VpackStateRaw {
            schema_version: String,
            implementation: VpackImplementation,
            ingredients: serde_json::Value,
        }

        let raw = VpackStateRaw::deserialize(deserializer)?;
        if raw.schema_version != Self::SCHEMA_VERSION {
            return Err(DeError::custom(
                "unsupported schema_version (expected \"1.0\")",
            ));
        }

        let ingredients = match raw.implementation {
            VpackImplementation::ArkLabs => {
                let i = serde_json::from_value::<ArkLabsIngredients>(raw.ingredients)
                    .map_err(|e| DeError::custom(e.to_string()))?;
                VpackIngredients::ArkLabs(i)
            }
            VpackImplementation::SecondTech => {
                let i = serde_json::from_value::<SecondTechIngredients>(raw.ingredients)
                    .map_err(|e| DeError::custom(e.to_string()))?;
                VpackIngredients::SecondTech(i)
            }
        };

        Ok(VpackState {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            implementation: raw.implementation,
            ingredients,
        })
    }
}

impl VpackState {
    /// Current schema version accepted by [`VpackState::deserialize`] and always written by [`Serialize`].
    pub const SCHEMA_VERSION: &'static str = "1.0";

    /// Builds envelope with [`VpackImplementation::ArkLabs`] and canonical schema version.
    pub fn new_ark_labs(ingredients: ArkLabsIngredients) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            implementation: VpackImplementation::ArkLabs,
            ingredients: VpackIngredients::ArkLabs(ingredients),
        }
    }

    /// Builds envelope with [`VpackImplementation::SecondTech`] and canonical schema version.
    pub fn new_second_tech(ingredients: SecondTechIngredients) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            implementation: VpackImplementation::SecondTech,
            ingredients: VpackIngredients::SecondTech(ingredients),
        }
    }
}
