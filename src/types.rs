//! Type shim: bitcoin types for native builds, minimal types for wasm (bitcoin_hashes only).
//! Allows wasm32 builds without the bitcoin crate (and thus without secp256k1-sys C build).

#[cfg(feature = "bitcoin")]
mod bitcoin_shim {
    use crate::error::VPackError;

    pub use bitcoin::consensus::Decodable;
    pub use bitcoin::hashes;
    pub use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    /// Decode OutPoint from Bitcoin consensus (36 bytes: 32 txid + 4 vout LE).
    pub fn decode_outpoint(data: &mut &[u8]) -> Result<OutPoint, VPackError> {
        OutPoint::consensus_decode(data).map_err(|_| VPackError::EncodingError)
    }

    /// Decode TxOut from Bitcoin consensus (8 value + VarInt script len + script).
    pub fn decode_txout(data: &mut &[u8]) -> Result<TxOut, VPackError> {
        TxOut::consensus_decode(data).map_err(|_| VPackError::EncodingError)
    }
}

#[cfg(feature = "wasm")]
mod wasm_shim {
    use alloc::vec::Vec;

    use bitcoin_hashes::Hash;
    use byteorder::{ByteOrder, LittleEndian};

    use crate::compact_size::read_compact_size;
    use crate::error::VPackError;

    /// Re-export so `crate::types::hashes::Hash` and `sha256d` match the bitcoin crate API.
    pub mod hashes {
        pub use bitcoin_hashes::sha256d;
        pub use bitcoin_hashes::Hash;
    }

    pub use bitcoin_hashes::sha256d;

    /// 32-byte hash (e.g. txid). Uses bitcoin_hashes::sha256d::Hash for API compatibility.
    pub type Txid = bitcoin_hashes::sha256d::Hash;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OutPoint {
        pub txid: Txid,
        pub vout: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ScriptBuf(pub Vec<u8>);

    impl ScriptBuf {
        pub fn from_bytes(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Amount(pub u64);

    impl Amount {
        pub fn from_sat(sat: u64) -> Self {
            Self(sat)
        }
        pub fn to_sat(self) -> u64 {
            self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TxOut {
        pub value: Amount,
        pub script_pubkey: ScriptBuf,
    }

    impl TxOut {
        pub fn value(&self) -> Amount {
            self.value
        }
    }

    /// Decode OutPoint from Bitcoin consensus (36 bytes: 32 txid + 4 vout LE).
    pub fn decode_outpoint(data: &mut &[u8]) -> Result<OutPoint, VPackError> {
        if data.len() < 36 {
            return Err(VPackError::IncompleteData);
        }
        let mut txid_arr = [0u8; 32];
        txid_arr.copy_from_slice(&data[..32]);
        let txid = Txid::from_byte_array(txid_arr);
        let vout = LittleEndian::read_u32(&data[32..36]);
        *data = &data[36..];
        Ok(OutPoint { txid, vout })
    }

    /// Decode TxOut from Bitcoin consensus (8 value + VarInt script len + script).
    pub fn decode_txout(data: &mut &[u8]) -> Result<TxOut, VPackError> {
        if data.len() < 8 {
            return Err(VPackError::IncompleteData);
        }
        let value = LittleEndian::read_u64(&data[..8]);
        *data = &data[8..];
        let (script_len, varint_len) =
            read_compact_size(*data).ok_or(VPackError::EncodingError)?;
        let script_len = script_len as usize;
        *data = &data[varint_len..];
        if data.len() < script_len {
            return Err(VPackError::IncompleteData);
        }
        let script_pubkey = ScriptBuf::from_bytes(data[..script_len].to_vec());
        *data = &data[script_len..];
        Ok(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        })
    }

}

// When both features are enabled (e.g. workspace build from wasm-vpack), prefer wasm so only one shim is active.
#[cfg(feature = "wasm")]
pub use wasm_shim::*;

#[cfg(all(feature = "bitcoin", not(feature = "wasm")))]
pub use bitcoin_shim::*;
