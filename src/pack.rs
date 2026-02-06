//! V-PACK serialization (pack). Builds a byte buffer from header + tree.
//! Symmetric to payload::reader; used by conformance tests and ASPs.

use alloc::vec::Vec;

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use borsh::BorshSerialize;
use bitcoin::TxOut;

#[cfg(test)]
extern crate std;

#[cfg(test)]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        std::eprintln!($($arg)*);
        // Force flush to ensure output is visible
        let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
    };
}

#[cfg(not(test))]
macro_rules! debug_print {
    ($($arg:tt)*) => {};
}

use crate::compact_size::write_compact_size;
use crate::error::VPackError;
use crate::header::{Header, HEADER_SIZE, MAGIC_BYTES};
use crate::payload::tree::{SiblingNode, VPackTree};

/// Packs a pre-built payload (prefix + tree section) with the given header into a complete V-PACK.
/// Used by conformance tests that supply raw tree bytes (e.g. from audit borsh_hex).
pub fn pack_from_payload(header: &Header, payload: &[u8]) -> Result<Vec<u8>, VPackError> {
    let payload_len = payload.len();
    if payload_len > crate::header::MAX_PAYLOAD_SIZE as usize {
        return Err(VPackError::PayloadTooLarge(payload_len as u32));
    }
    let mut header_buf = [0u8; HEADER_SIZE];
    header_buf[0..3].copy_from_slice(&MAGIC_BYTES);
    header_buf[3] = header.flags;
    header_buf[4] = header.version;
    header_buf[5] = header.tx_variant.as_u8();
    LittleEndian::write_u16(&mut header_buf[6..8], header.tree_arity);
    LittleEndian::write_u16(&mut header_buf[8..10], header.tree_depth);
    LittleEndian::write_u16(&mut header_buf[10..12], header.node_count);
    LittleEndian::write_u32(&mut header_buf[12..16], header.asset_type);
    LittleEndian::write_u32(&mut header_buf[16..20], payload_len as u32);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&header_buf[0..20]);
    hasher.update(payload);
    LittleEndian::write_u32(&mut header_buf[20..24], hasher.finalize());
    let mut out = Vec::with_capacity(HEADER_SIZE + payload_len);
    out.extend_from_slice(&header_buf);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Packs a header and tree into a complete V-PACK byte buffer.
/// Checksum is computed over bytes 0..20 of header + payload per V-BIP-01.
pub fn pack(header: &Header, tree: &VPackTree) -> Result<Vec<u8>, VPackError> {
    let payload = serialize_payload(header, tree)?;
    let payload_len = payload.len();
    if payload_len > crate::header::MAX_PAYLOAD_SIZE as usize {
        return Err(VPackError::PayloadTooLarge(payload_len as u32));
    }

    let mut header_buf = [0u8; HEADER_SIZE];
    header_buf[0..3].copy_from_slice(&MAGIC_BYTES);
    header_buf[3] = header.flags;
    header_buf[4] = header.version;
    header_buf[5] = header.tx_variant.as_u8();
    LittleEndian::write_u16(&mut header_buf[6..8], header.tree_arity);
    LittleEndian::write_u16(&mut header_buf[8..10], header.tree_depth);
    LittleEndian::write_u16(&mut header_buf[10..12], header.node_count);
    LittleEndian::write_u32(&mut header_buf[12..16], header.asset_type);
    LittleEndian::write_u32(&mut header_buf[16..20], payload_len as u32);
    // bytes 20..24: checksum (filled below)

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&header_buf[0..20]);
    hasher.update(&payload);
    let checksum = hasher.finalize();
    LittleEndian::write_u32(&mut header_buf[20..24], checksum);

    let mut out = alloc::vec::Vec::with_capacity(HEADER_SIZE + payload_len);
    out.extend_from_slice(&header_buf);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn serialize_payload(header: &Header, tree: &VPackTree) -> Result<Vec<u8>, VPackError> {
    let mut out = Vec::new();

    // Prefix: Asset ID (optional)
    if header.has_asset_id() {
        let id = tree.asset_id.unwrap_or([0u8; 32]);
        out.extend_from_slice(&id);
    }

    // Prefix: Anchor OutPoint (36 bytes: 32 txid + 4 vout LE)
    out.extend_from_slice(tree.anchor.txid.as_ref());
    let mut vout_buf = [0u8; 4];
    LittleEndian::write_u32(&mut vout_buf, tree.anchor.vout);
    out.extend_from_slice(&vout_buf);

    // Prefix: fee_anchor_script (Borsh Vec<u8>)
    tree.fee_anchor_script
        .serialize(&mut out)
        .map_err(|_| VPackError::EncodingError)?;

    // Tree: leaf (Borsh)
    tree.leaf.serialize(&mut out).map_err(|_| VPackError::EncodingError)?;

    // Tree: path_len (Borsh u32)
    let path_len = tree.path.len() as u32;
    path_len.serialize(&mut out).map_err(|_| VPackError::EncodingError)?;
    debug_print!("DEBUG WRITER: Wrote path_len={}. Output size: {}", path_len, out.len());

    for (item_idx, item) in tree.path.iter().enumerate() {
        debug_print!("DEBUG WRITER: Starting GenesisItem[{}] serialize. Output size: {}", item_idx, out.len());
        // siblings_len (Borsh u32)
        let siblings_len = item.siblings.len() as u32;
        siblings_len.serialize(&mut out).map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote siblings_len={}. Output size: {}", siblings_len, out.len());

        for (sibling_idx, sibling) in item.siblings.iter().enumerate() {
            debug_print!("DEBUG WRITER: Serializing sibling[{}]. Output size: {}", sibling_idx, out.len());
            match sibling {
                SiblingNode::Compact { hash, value, script } => {
                    out.extend_from_slice(hash);
                    let mut val_buf = [0u8; 8];
                    LittleEndian::write_u64(&mut val_buf, *value);
                    out.extend_from_slice(&val_buf);
                    script
                        .serialize(&mut out)
                        .map_err(|_| VPackError::EncodingError)?;
                    debug_print!("DEBUG WRITER: Wrote Compact sibling: hash[..4]={:?}, value={}, script_len={}. Output size: {}", 
                        &hash[..4], value, script.len(), out.len());
                }
                SiblingNode::Full(txout) => {
                    encode_txout(txout, &mut out)?;
                }
            }
        }

        item.parent_index
            .serialize(&mut out)
            .map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote parent_index={}. Output size: {}", item.parent_index, out.len());
        item.sequence
            .serialize(&mut out)
            .map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote sequence={}. Output size: {}", item.sequence, out.len());
        item.child_amount
            .serialize(&mut out)
            .map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote child_amount={}. Output size: {}", item.child_amount, out.len());
        item.child_script_pubkey
            .serialize(&mut out)
            .map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote child_script_pubkey (len={}). Output size: {}", item.child_script_pubkey.len(), out.len());
        item.signature
            .serialize(&mut out)
            .map_err(|_| VPackError::EncodingError)?;
        debug_print!("DEBUG WRITER: Wrote signature. Output size: {}", out.len());
    }

    Ok(out)
}

/// Bitcoin consensus encoding for TxOut: value (8 LE) + compact size (script len) + script.
/// 
/// SYMMETRY NOTE: This uses `write_compact_size` for script length, which matches
/// `TxOut::consensus_decode` in the reader. Both use Bitcoin VarInt format:
/// - Writer: `write_compact_size(out, script.len())` → VarInt
/// - Reader: `TxOut::consensus_decode(&mut data)` → reads VarInt script_len
/// This ensures perfect symmetry for SiblingNode::Full.
fn encode_txout(txout: &TxOut, out: &mut Vec<u8>) -> Result<(), VPackError> {
    let value = txout.value.to_sat();
    let mut val_buf = [0u8; 8];
    LittleEndian::write_u64(&mut val_buf, value);
    out.extend_from_slice(&val_buf);
    let script = txout.script_pubkey.as_bytes();
    write_compact_size(out, script.len() as u64);
    out.extend_from_slice(script);
    Ok(())
}
