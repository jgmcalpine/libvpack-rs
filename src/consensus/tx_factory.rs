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

// -----------------------------------------------------------------------------
// SegWit signed transaction serialization (BIP-141)
// -----------------------------------------------------------------------------

/// Builds the full SegWit wire-format signed transaction bytes.
/// Layout: nVersion | Marker (0x00) | Flag (0x01) | vin | vout | witness | nLockTime.
/// Requires `signatures.len() == inputs.len()`; each input gets one witness stack (empty if None).
pub fn tx_signed_hex(
    version: u32,
    inputs: &[TxInPreimage],
    outputs: &[TxOutPreimage<'_>],
    signatures: &[Option<[u8; 64]>],
    locktime: u32,
) -> Vec<u8> {
    assert_eq!(
        signatures.len(),
        inputs.len(),
        "signatures.len() must equal inputs.len()"
    );
    let cap = estimate_signed_capacity(inputs, outputs, signatures);
    let mut out = Vec::with_capacity(cap);

    // nVersion (4 bytes LE)
    let mut ver_buf = [0u8; 4];
    LittleEndian::write_u32(&mut ver_buf, version);
    out.extend_from_slice(&ver_buf);

    // Marker + Flag
    out.push(0x00);
    out.push(0x01);

    // vin count
    write_compact_size(&mut out, inputs.len() as u64);

    // vin details (same as preimage)
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

    // vout details (same as preimage)
    for out_pre in outputs {
        let mut val_buf = [0u8; 8];
        LittleEndian::write_u64(&mut val_buf, out_pre.value);
        out.extend_from_slice(&val_buf);
        write_compact_size(&mut out, out_pre.script_pubkey.len() as u64);
        out.extend_from_slice(out_pre.script_pubkey);
    }

    // Witness stack: per input, VarInt item count; for each item, VarInt length + bytes
    for sig in signatures {
        match sig {
            None => write_compact_size(&mut out, 0),
            Some(s) => {
                write_compact_size(&mut out, 1);
                write_compact_size(&mut out, 64);
                out.extend_from_slice(s);
            }
        }
    }

    // nLockTime (4 bytes LE)
    let mut lt_buf = [0u8; 4];
    LittleEndian::write_u32(&mut lt_buf, locktime);
    out.extend_from_slice(&lt_buf);

    out
}

fn estimate_signed_capacity(
    inputs: &[TxInPreimage],
    outputs: &[TxOutPreimage<'_>],
    signatures: &[Option<[u8; 64]>],
) -> usize {
    let base = estimate_capacity(inputs, outputs);
    // Preimage has no marker/flag; signed adds 2 bytes.
    let mut cap = base + 2;
    for sig in signatures {
        cap += 1; // witness item count
        if sig.is_some() {
            cap += 1 + 64; // length VarInt + 64 bytes
        }
    }
    cap
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
        } else if (script_len as u64) < 0x1_0000_0000 {
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

    use std::path::PathBuf;

    use crate::types::hashes::Hash;

    use super::{tx_preimage, tx_signed_hex, TxInPreimage, TxOutPreimage};
    use crate::consensus::VtxoId;

    /// Fee anchor script hex from reconstruction_ingredients.
    const FEE_ANCHOR_SCRIPT_HEX: &str = "51024e73";

    #[test]
    fn test_factory_parity_v3_oor() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/oor_forfeit_pset.json");
        let contents = std::fs::read_to_string(&path).expect("read oor_forfeit_pset.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");
        let unsigned_tx_hex = json["raw_evidence"]["unsigned_tx_hex"]
            .as_str()
            .expect("unsigned_tx_hex present");
        let anchor_str = json["reconstruction_ingredients"]["parent_outpoint"]
            .as_str()
            .expect("parent_outpoint present");

        let expected = hex::decode(unsigned_tx_hex).expect("decode unsigned_tx_hex");
        let id = VtxoId::from_str(anchor_str).expect("parse anchor");
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
        let fee_anchor_script =
            hex::decode(FEE_ANCHOR_SCRIPT_HEX).expect("decode fee_anchor_script");

        let out1 = TxOutPreimage {
            value: 1000,
            script_pubkey: first_output_script.as_slice(),
        };
        let out2 = TxOutPreimage {
            value: 0,
            script_pubkey: fee_anchor_script.as_slice(),
        };

        let result = tx_preimage(3, &[input], &[out1, out2], 0);
        assert_eq!(
            result, expected,
            "factory output must match unsigned_tx_hex byte-for-byte"
        );
    }

    #[test]
    fn test_factory_signed_v3_parity() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("tests/conformance/vectors/ark_labs/oor_forfeit_pset.json");
        let contents = std::fs::read_to_string(&path).expect("read oor_forfeit_pset.json");
        let json: serde_json::Value = serde_json::from_str(&contents).expect("parse JSON");
        let unsigned_tx_hex = json["raw_evidence"]["unsigned_tx_hex"]
            .as_str()
            .expect("unsigned_tx_hex present");
        let anchor_str = json["reconstruction_ingredients"]["parent_outpoint"]
            .as_str()
            .expect("parent_outpoint present");

        let preimage = hex::decode(unsigned_tx_hex).expect("decode unsigned_tx_hex");
        let id = VtxoId::from_str(anchor_str).expect("parse anchor");
        let (prev_out_txid, prev_out_vout) = match id {
            VtxoId::OutPoint(op) => (op.txid.to_byte_array(), op.vout),
            VtxoId::Raw(_) => panic!("expected OutPoint for anchor"),
        };

        let input = TxInPreimage {
            prev_out_txid,
            prev_out_vout,
            sequence: 0xFFFFFFFE,
        };

        let first_output_script = extract_first_output_script(&preimage);
        let fee_anchor_script =
            hex::decode(FEE_ANCHOR_SCRIPT_HEX).expect("decode fee_anchor_script");

        let out1 = TxOutPreimage {
            value: 1000,
            script_pubkey: first_output_script.as_slice(),
        };
        let out2 = TxOutPreimage {
            value: 0,
            script_pubkey: fee_anchor_script.as_slice(),
        };

        let dummy_sig = [0u8; 64];
        let result =
            tx_signed_hex(3, &[input], &[out1, out2], &[Some(dummy_sig)], 0);

        assert!(
            result.starts_with(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "output must start with version 3 LE + marker + flag (030000000001)"
        );
        assert!(
            result.ends_with(&[0u8; 4]),
            "output must end with locktime 00000000"
        );
        let sig_start = result.len() - 4 - 64;
        assert_eq!(
            &result[sig_start..sig_start + 64],
            &dummy_sig[..],
            "last 68 bytes must be 64-byte signature + 4-byte locktime"
        );

        let witness_len = 66; // 1 (item count) + 1 (length) + 64 (sig)
        let expected_len = preimage.len() + 2 + witness_len;
        assert_eq!(
            result.len(),
            expected_len,
            "total length must equal preimage + 2 (marker/flag) + witness"
        );
    }

    /// Verification gate: empty witness (None) must emit exactly 0x00 (CompactSize for 0 items).
    /// Bitcoin nodes expect a witness stack for every input in a SegWit transaction, even if empty.
    #[test]
    fn test_factory_empty_witness_emits_0x00() {
        let input = TxInPreimage {
            prev_out_txid: [0u8; 32],
            prev_out_vout: 0,
            sequence: 0,
        };
        let output = TxOutPreimage {
            value: 1000,
            script_pubkey: &[0x51], // OP_1
        };
        let result = tx_signed_hex(3, &[input], &[output], &[None], 0);

        assert!(
            result.starts_with(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "output must start with V3-Segwit pattern"
        );

        // Witness section: for 1 input with None, we write CompactSize(0) = 0x00
        // Structure: version(4) + marker(1) + flag(1) + vin(1+41) + vout(1+8+1+1) + witness(1) + locktime(4)
        // Witness is 1 byte (0x00) for empty stack. Last 5 bytes = witness(0x00) + locktime(0).
        assert!(
            result.len() >= 5,
            "signed tx must have at least 5 bytes"
        );
        assert_eq!(
            result[result.len() - 5],
            0x00,
            "empty witness must serialize as single 0x00 byte (CompactSize for 0 items)"
        );
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
