//! Second Tech (bark) dialect adapter: deserializes "Silo Dialect" into V-PACK standard grammar.
//!
//! Bark's Borsh layout differs from V-PACK: different field order, CompactSize for genesis
//! vector length, Bitcoin consensus OutPoints, and a policy enum. This module parses the
//! shadow layout and maps to VPackTree.

use crate::types::{decode_outpoint, OutPoint};
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};

use crate::compact_size::read_compact_size;
use crate::error::VPackError;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};

// -----------------------------------------------------------------------------
// Policy shadow: only variant 0x00 (Pubkey) supported for current vectors.
// -----------------------------------------------------------------------------

/// Bark policy enum. Borsh: 1-byte tag then variant payload.
#[derive(Debug)]
enum BarkPolicyShadow {
    /// Variant 0x00: Pubkey (no payload for our use).
    Pubkey,
    /// Other variants (e.g. 0x05): consume tag only so cursor stays aligned for following point.
    Unknown(()),
}

fn parse_policy(data: &[u8]) -> Result<(BarkPolicyShadow, usize), VPackError> {
    if data.is_empty() {
        return Err(VPackError::IncompleteData);
    }
    let tag = data[0];
    match tag {
        0x00 => Ok((BarkPolicyShadow::Pubkey, 1)),
        _ => Ok((BarkPolicyShadow::Unknown(()), 1)),
    }
}

// -----------------------------------------------------------------------------
// OutPoint: Bitcoin consensus (32B hash + 4B vout LE).
// -----------------------------------------------------------------------------

fn parse_outpoint_consensus(data: &[u8]) -> Result<(OutPoint, usize), VPackError> {
    const OUTPOINT_LEN: usize = 36;
    if data.len() < OUTPOINT_LEN {
        return Err(VPackError::IncompleteData);
    }
    let mut slice = &data[..OUTPOINT_LEN];
    let op = decode_outpoint(&mut slice)?;
    Ok((op, OUTPOINT_LEN))
}

// -----------------------------------------------------------------------------
// Genesis item shadow: siblings (Borsh u32 len + compact siblings), then
// parent_index, sequence, child_amount, child_script_pubkey, signature.
// -----------------------------------------------------------------------------

fn parse_borsh_u32(data: &[u8]) -> Result<(u32, usize), VPackError> {
    if data.len() < 4 {
        return Err(VPackError::IncompleteData);
    }
    let n = LittleEndian::read_u32(&data[0..4]);
    Ok((n, 4))
}

/// Bark may use u16 for counts in genesis transitions (e.g. siblings_len).
fn parse_borsh_u16(data: &[u8]) -> Result<(u16, usize), VPackError> {
    if data.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let n = LittleEndian::read_u16(&data[0..2]);
    Ok((n, 2))
}

fn parse_borsh_vec_u8(data: &[u8]) -> Result<(Vec<u8>, usize), VPackError> {
    let (len, n) = parse_borsh_u32(data)?;
    let len = len as usize;
    let rest = &data[n..];
    if rest.len() < len {
        return Err(VPackError::IncompleteData);
    }
    let bytes = rest[..len].to_vec();
    Ok((bytes, n + len))
}

/// One compact sibling: 32B hash + 8B value LE + Borsh Vec<u8> script.
fn parse_sibling(data: &[u8]) -> Result<(SiblingNode, usize), VPackError> {
    if data.len() < 32 + 8 + 4 {
        return Err(VPackError::IncompleteData);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let value = LittleEndian::read_u64(&data[32..40]);
    let (script, script_consumed) = parse_borsh_vec_u8(&data[40..])?;
    let consumed = 40 + script_consumed;
    Ok((
        SiblingNode::Compact {
            hash,
            value,
            script,
        },
        consumed,
    ))
}

/// One genesis step. Bark uses u16 for siblings_len here; we consume it and map to standard GenesisItem (u32 lengths in V-PACK).
fn parse_genesis_item(mut rest: &[u8]) -> Result<(GenesisItem, usize), VPackError> {
    let start_len = rest.len();
    let (siblings_len, n) = parse_borsh_u16(rest)?;
    rest = &rest[n..];
    let mut siblings = Vec::with_capacity(siblings_len as usize);
    for _ in 0..siblings_len {
        let (sib, consumed) = parse_sibling(rest)?;
        siblings.push(sib);
        rest = &rest[consumed..];
    }
    // Bark: nb_outputs (u8), output_idx (u8) after transition, before other_outputs.
    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let _nb_outputs = rest[0];
    let output_idx = rest[1];
    rest = &rest[2..];
    let parent_index = output_idx as u32;

    if rest.len() < 4 + 8 + 4 {
        return Err(VPackError::IncompleteData);
    }
    let sequence = LittleEndian::read_u32(&rest[0..4]);
    let child_amount = LittleEndian::read_u64(&rest[4..12]);
    let (child_script_pubkey, script_consumed) = parse_borsh_vec_u8(&rest[12..])?;
    rest = &rest[12 + script_consumed..];
    if rest.is_empty() {
        return Err(VPackError::IncompleteData);
    }
    let sig_tag = rest[0];
    let sig_consumed = if sig_tag == 0 {
        1
    } else if sig_tag == 1 {
        if rest.len() < 1 + 64 {
            return Err(VPackError::IncompleteData);
        }
        65
    } else {
        return Err(VPackError::EncodingError);
    };
    let signature = if sig_tag == 0 {
        None
    } else {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&rest[1..65]);
        Some(arr)
    };
    rest = &rest[sig_consumed..];
    let total_consumed = start_len - rest.len();
    Ok((
        GenesisItem {
            siblings,
            parent_index,
            sequence,
            child_amount,
            child_script_pubkey,
            signature,
        },
        total_consumed,
    ))
}

// -----------------------------------------------------------------------------
// Bark top-level: version, amount, expiry_height, server_pubkey, exit_delta,
// anchor_point (36), genesis (CompactSize count + items), policy, point (36).
// -----------------------------------------------------------------------------

/// Deserializes bark (Second Tech) raw Borsh bytes into V-PACK standard grammar.
/// Uses CompactSize for genesis vector length and Bitcoin consensus for OutPoints.
/// nSequence is set to 0x00000000 per Second Tech.
pub fn bark_to_vpack(raw_bytes: &[u8], fee_anchor_script: &[u8]) -> Result<VPackTree, VPackError> {
    let mut rest = raw_bytes;

    // VTXO_ENCODING_VERSION in bark is u16 (2 bytes), not u8.
    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let _version = LittleEndian::read_u16(&rest[0..2]);
    rest = &rest[2..];

    if rest.len() < 8 {
        return Err(VPackError::IncompleteData);
    }
    let amount = LittleEndian::read_u64(&rest[0..8]);
    rest = &rest[8..];

    if rest.len() < 4 {
        return Err(VPackError::IncompleteData);
    }
    let expiry_height = LittleEndian::read_u32(&rest[0..4]);
    rest = &rest[4..];

    // Fixed-length Bitcoin compressed pubkey (33 bytes), not Borsh Vec<u8>.
    const PUBKEY_LEN: usize = 33;
    if rest.len() < PUBKEY_LEN {
        return Err(VPackError::IncompleteData);
    }
    let (pk_bytes, rest_after_pk) = rest.split_at(PUBKEY_LEN);
    let server_pubkey = pk_bytes.to_vec();
    rest = rest_after_pk;

    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let exit_delta = LittleEndian::read_u16(&rest[0..2]);
    rest = &rest[2..];

    let (anchor_point, op_consumed) = parse_outpoint_consensus(rest)?;
    rest = &rest[op_consumed..];

    let (genesis_count, compact_consumed) =
        read_compact_size(rest).ok_or(VPackError::IncompleteData)?;
    rest = &rest[compact_consumed..];

    let fee_anchor_script_vec = fee_anchor_script.to_vec();
    let fee_anchor_sibling = SiblingNode::Compact {
        hash: [0u8; 32],
        value: 0,
        script: fee_anchor_script_vec.clone(),
    };

    let mut path = Vec::with_capacity(genesis_count as usize);
    for _ in 0..genesis_count {
        let (mut item, item_consumed) = parse_genesis_item(rest)?;
        item.siblings.push(fee_anchor_sibling.clone());
        path.push(item);
        rest = &rest[item_consumed..];
    }

    let (_, policy_consumed) = parse_policy(rest)?;
    rest = &rest[policy_consumed..];

    let (point, point_consumed) = parse_outpoint_consensus(rest)?;
    rest = &rest[point_consumed..];

    if !rest.is_empty() {
        return Err(VPackError::TrailingData(rest.len()));
    }

    let leaf = VtxoLeaf {
        amount,
        vout: point.vout,
        sequence: 0x0000_0000,
        expiry: expiry_height,
        exit_delta,
        script_pubkey: server_pubkey,
    };

    let mut leaf_siblings = Vec::new();
    leaf_siblings.push(fee_anchor_sibling);

    Ok(VPackTree {
        leaf,
        leaf_siblings,
        path,
        anchor: anchor_point,
        asset_id: None,
        fee_anchor_script: fee_anchor_script_vec,
    })
}
