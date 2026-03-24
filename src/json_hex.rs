//! Hex (de)serialization helpers for `export-json` ingredient fields.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Deserializer, Serializer};

/// `serde(with = "crate::json_hex::vec")` for `Vec<u8>` hex strings.
pub mod vec {
    use alloc::vec::Vec;

    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize_vec(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_vec(deserializer)
    }
}

/// `serde(with = "crate::json_hex::bytes32")` for `[u8; 32]` hex strings.
pub mod bytes32 {
    use alloc::string::String;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex string"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

pub fn serialize_vec<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(s.trim()).map_err(serde::de::Error::custom)
}

pub fn deserialize_vec_default_empty<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        None => Ok(Vec::new()),
        Some(s) if s.trim().is_empty() => Ok(Vec::new()),
        Some(s) => hex::decode(s.trim()).map_err(serde::de::Error::custom),
    }
}

pub fn deserialize_bytes32_default_zero<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    let s = match opt {
        None => return Ok([0u8; 32]),
        Some(ref t) if t.trim().is_empty() => return Ok([0u8; 32]),
        Some(t) => t,
    };
    let v = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
    if v.len() != 32 {
        return Err(serde::de::Error::custom("expected 32-byte hex string"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
