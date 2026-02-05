//! Deterministic serialization of a Bitcoin V3 transaction preimage (BIP-431 / TRUC).
//! Topology-agnostic: supports 2-output tree nodes or 100-output batch transactions.
//! no_std; manual consensus encoding only.

use alloc::vec::Vec;

use byteorder::ByteOrder;
use byteorder::LittleEndian;

use crate::compact_size::write_compact_size;

// -----------------------------------------------------------------------------
// Preimage types
// -----------------------------------------------------------------------------

/// One input for the transaction preimage. scriptSig is always empty for virtual txs.
#[derive(Debug, Clone)]
pub struct TxInPreimage {
    /// Previous output txid in wire (internal) order.
    pub prev_out_txid: [u8; 32],
    /// Previous output index.
    pub prev_out_vout: u32,
    /// nSequence (e.g. 0xFFFFFFFE for OOR, 0xFFFFFFFF for round).
    pub sequence: u32,
}

/// One output for the transaction preimage.
#[derive(Debug, Clone)]
pub struct TxOutPreimage<'a> {
    /// Value in satoshis.
    pub value: u64,
    /// scriptPubKey as opaque bytes (wire format: VarInt length + these bytes).
    pub script_pubkey: &'a [u8],
}

// -----------------------------------------------------------------------------
// Preimage serialization
// -----------------------------------------------------------------------------

/// Builds the raw transaction preimage bytes (ready for hashing) in strict BIP consensus order.
/// No std::io::Write; uses Vec::with_capacity and extend_from_slice only.
pub fn tx_preimage(
    version: u32,
    inputs: &[TxInPreimage],
    outputs: &[TxOutPreimage<'_>],
    locktime: u32,
) -> Vec<u8> {
    let cap = estimate_capacity(inputs, outputs);
    let mut out = Vec::with_capacity(cap);

    // nVersion (4 bytes LE)
    let mut ver_buf = [0u8; 4];
    LittleEndian::write_u32(&mut ver_buf, version);
    out.extend_from_slice(&ver_buf);

    // vin count
    write_compact_size(&mut out, inputs.len() as u64);

    // Each input: PrevOut (32 + 4) + scriptSig length (VarInt) + scriptSig (none) + nSequence (4)
    for inp in inputs {
        out.extend_from_slice(&inp.prev_out_txid);
        let mut vout_buf = [0u8; 4];
        LittleEndian::write_u32(&mut vout_buf, inp.prev_out_vout);
        out.extend_from_slice(&vout_buf);
        write_compact_size(&mut out, 0);
        let mut seq_buf = [0u8; 4];
        LittleEndian::write_u32(&mut seq_buf, inp.sequence);
        out.extend_from_slice(&seq_buf);
    }

    // vout count
    write_compact_size(&mut out, outputs.len() as u64);

    // Each output: value (8 LE) + scriptPubKey length (VarInt) + scriptPubKey bytes
    for out_pre in outputs {
        let mut val_buf = [0u8; 8];
        LittleEndian::write_u64(&mut val_buf, out_pre.value);
        out.extend_from_slice(&val_buf);
        write_compact_size(&mut out, out_pre.script_pubkey.len() as u64);
        out.extend_from_slice(out_pre.script_pubkey);
    }

    // nLockTime (4 bytes LE)
    let mut lt_buf = [0u8; 4];
    LittleEndian::write_u32(&mut lt_buf, locktime);
    out.extend_from_slice(&lt_buf);

    out
}

fn estimate_capacity(inputs: &[TxInPreimage], outputs: &[TxOutPreimage<'_>]) -> usize {
    let mut cap = 4 + 1 + (inputs.len() * (32 + 4 + 1 + 4)) + 1;
    for o in outputs {
        let script_len = o.script_pubkey.len();
        cap += 8;
        cap += if script_len < 253 {
            1
        } else if script_len < 0x1_0000 {
            3
        } else if script_len < 0x1_0000_0000 {
            5
        } else {
            9
        };
        cap += script_len;
    }
    cap += 4;
    cap
}

// -----------------------------------------------------------------------------
// Verification gate: parity with ark_labs/oor_forfeit_pset.json
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hashes::Hash;

    use super::{TxInPreimage, TxOutPreimage, tx_preimage};
    use crate::consensus::VtxoId;

    /// From raw_evidence.unsigned_tx_hex in oor_forfeit_pset.json.
    const UNSIGNED_TX_HEX: &str = "0300000001411d0d848ab79c0f7ae5a73742c4addd4e5b5646c2bc4bea854d287107825c750000000000feffffff02e803000000000000150014a1b2c3d4e5f6789012345678901234567890ab00000000000000000451024e7300000000";

    /// Anchor in display order (reconstruction_ingredients); parse to get wire-order PrevOut.
    const ANCHOR_STR: &str = "755c820771284d85ea4bbcc246565b4eddadc44237a7e57a0f9cb78a840d1d41:0";

    /// Fee anchor script hex from reconstruction_ingredients.
    const FEE_ANCHOR_SCRIPT_HEX: &str = "51024e73";

    #[test]
    fn test_factory_parity_v3_oor() {
        let expected = hex::decode(UNSIGNED_TX_HEX).expect("decode unsigned_tx_hex");
        let id = VtxoId::from_str(ANCHOR_STR).expect("parse anchor");
        let (prev_out_txid, prev_out_vout) = match id {
            VtxoId::OutPoint(op) => (op.txid.to_byte_array(), op.vout),
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };

        let input = TxInPreimage {
            prev_out_txid,
            prev_out_vout,
            sequence: 0xFFFFFFFE,
        };

        let first_output_script = extract_first_output_script(&expected);
        let fee_anchor_script = hex::decode(FEE_ANCHOR_SCRIPT_HEX).expect("decode fee_anchor_script");

        let out1 = TxOutPreimage {
            value: 1000,
            script_pubkey: first_output_script.as_slice(),
        };
        let out2 = TxOutPreimage {
            value: 0,
            script_pubkey: fee_anchor_script.as_slice(),
        };

        let result = tx_preimage(3, &[input], &[out1, out2], 0);
        assert_eq!(result, expected, "factory output must match unsigned_tx_hex byte-for-byte");
    }

    /// Parses the preimage buffer to return the first output's scriptPubKey bytes.
    fn extract_first_output_script(preimage: &[u8]) -> alloc::vec::Vec<u8> {
        let mut i = 0usize;
        i += 4; // version
        let vin_count = read_compact_size(preimage, &mut i);
        for _ in 0..vin_count {
            i += 32 + 4; // prevout
            let script_len = read_compact_size(preimage, &mut i) as usize;
            i += script_len;
            i += 4; // sequence
        }
        let vout_count = read_compact_size(preimage, &mut i);
        assert!(vout_count >= 1, "expected at least one output");
        i += 8; // value
        let script_len = read_compact_size(preimage, &mut i) as usize;
        preimage[i..i + script_len].to_vec()
    }

    fn read_compact_size(buf: &[u8], i: &mut usize) -> u64 {
        let b = buf[*i];
        *i += 1;
        if b < 253 {
            b as u64
        } else if b == 0xfd {
            let n = u16::from_le_bytes([buf[*i], buf[*i + 1]]);
            *i += 2;
            n as u64
        } else if b == 0xfe {
            let n = u32::from_le_bytes(buf[*i..*i + 4].try_into().unwrap());
            *i += 4;
            n as u64
        } else {
            let n = u64::from_le_bytes(buf[*i..*i + 8].try_into().unwrap());
            *i += 8;
            n
        }
    }
}
