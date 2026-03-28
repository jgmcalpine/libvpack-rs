//! Second Tech (bark) dialect adapter: deserializes Bark `ProtocolEncoding` into V-PACK standard
//! grammar.
//!
//! Bark's serialization is: version(u16) + amount(u64) + expiry_height(u32) +
//! server_pubkey(33B) + exit_delta(u16) + anchor_point(36B) + genesis chain(CompactSize count +
//! items) + policy + point(36B). Each genesis item is a `GenesisTransition` (tag + variant data)
//! followed by `nb_outputs`(u8), `output_idx`(u8), `other_outputs`(TxOut[]), `fee_amount`(u64).

use crate::types::{decode_outpoint, OutPoint};
use alloc::vec::Vec;
use byteorder::{ByteOrder, LittleEndian};

use crate::compact_size::read_compact_size;
use crate::error::VPackError;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};

const GENESIS_TRANSITION_COSIGNED: u8 = 1;
const GENESIS_TRANSITION_ARKOOR: u8 = 2;
const GENESIS_TRANSITION_HASH_LOCKED: u8 = 3;

fn parse_outpoint_consensus(data: &[u8]) -> Result<(OutPoint, usize), VPackError> {
    const OUTPOINT_LEN: usize = 36;
    if data.len() < OUTPOINT_LEN {
        return Err(VPackError::IncompleteData);
    }
    let mut slice = &data[..OUTPOINT_LEN];
    let op = decode_outpoint(&mut slice)?;
    Ok((op, OUTPOINT_LEN))
}

fn skip_pubkey(data: &[u8]) -> Result<usize, VPackError> {
    if data.len() < 33 {
        return Err(VPackError::IncompleteData);
    }
    Ok(33)
}

fn skip_optional_sig(data: &[u8]) -> Result<(Option<[u8; 64]>, usize), VPackError> {
    if data.len() < 64 {
        return Err(VPackError::IncompleteData);
    }
    let all_zero = data[..64].iter().all(|b| *b == 0);
    if all_zero {
        Ok((None, 64))
    } else {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&data[..64]);
        Ok((Some(arr), 64))
    }
}

fn read_cs(data: &[u8]) -> Result<(u64, usize), VPackError> {
    read_compact_size(data).ok_or(VPackError::IncompleteData)
}

/// Parse a Bitcoin consensus-encoded TxOut: u64 LE amount + CompactSize script_len + script.
fn parse_txout(data: &[u8]) -> Result<(u64, Vec<u8>, usize), VPackError> {
    if data.len() < 8 {
        return Err(VPackError::IncompleteData);
    }
    let amount = LittleEndian::read_u64(&data[0..8]);
    let (script_len, cs_len) = read_cs(&data[8..])?;
    let start = 8 + cs_len;
    let end = start + script_len as usize;
    if data.len() < end {
        return Err(VPackError::IncompleteData);
    }
    let script = data[start..end].to_vec();
    Ok((amount, script, end))
}

/// Parse one genesis item in Bark ProtocolEncoding format.
fn parse_genesis_item(mut rest: &[u8]) -> Result<(GenesisItem, Vec<Vec<u8>>, usize), VPackError> {
    let start_len = rest.len();

    // GenesisTransition tag
    if rest.is_empty() {
        return Err(VPackError::IncompleteData);
    }
    let transition_tag = rest[0];
    rest = &rest[1..];

    let mut cosign_pubkeys: Vec<Vec<u8>> = Vec::new();
    let signature: Option<[u8; 64]>;

    match transition_tag {
        GENESIS_TRANSITION_COSIGNED => {
            let (key_count, cs_len) = read_cs(rest)?;
            rest = &rest[cs_len..];
            for _ in 0..key_count {
                if rest.len() < 33 {
                    return Err(VPackError::IncompleteData);
                }
                cosign_pubkeys.push(rest[..33].to_vec());
                rest = &rest[33..];
            }
            let (sig, sig_consumed) = skip_optional_sig(rest)?;
            signature = sig;
            rest = &rest[sig_consumed..];
        }
        GENESIS_TRANSITION_HASH_LOCKED => {
            let consumed = skip_pubkey(rest)?;
            rest = &rest[consumed..];
            let (sig, sig_consumed) = skip_optional_sig(rest)?;
            signature = sig;
            rest = &rest[sig_consumed..];
            // MaybePreimage: u8 tag + 32 bytes
            if rest.len() < 33 {
                return Err(VPackError::IncompleteData);
            }
            rest = &rest[33..];
        }
        GENESIS_TRANSITION_ARKOOR => {
            let (key_count, cs_len) = read_cs(rest)?;
            rest = &rest[cs_len..];
            for _ in 0..key_count {
                if rest.len() < 33 {
                    return Err(VPackError::IncompleteData);
                }
                cosign_pubkeys.push(rest[..33].to_vec());
                rest = &rest[33..];
            }
            // TapTweakHash (32 bytes)
            if rest.len() < 32 {
                return Err(VPackError::IncompleteData);
            }
            rest = &rest[32..];
            let (sig, sig_consumed) = skip_optional_sig(rest)?;
            signature = sig;
            rest = &rest[sig_consumed..];
        }
        _ => return Err(VPackError::EncodingError),
    }

    // nb_outputs (u8), output_idx (u8)
    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let nb_outputs = rest[0] as usize;
    let output_idx = rest[1];
    rest = &rest[2..];

    let nb_other = nb_outputs.checked_sub(1).ok_or(VPackError::EncodingError)?;

    let mut other_outputs: Vec<(u64, Vec<u8>)> = Vec::with_capacity(nb_other);
    for _ in 0..nb_other {
        let (amt, script, consumed) = parse_txout(rest)?;
        other_outputs.push((amt, script));
        rest = &rest[consumed..];
    }

    // fee_amount (u64)
    if rest.len() < 8 {
        return Err(VPackError::IncompleteData);
    }
    let _fee_amount = LittleEndian::read_u64(&rest[0..8]);
    rest = &rest[8..];

    let siblings: Vec<SiblingNode> = other_outputs
        .iter()
        .map(|(v, s)| SiblingNode::Compact {
            hash: [0u8; 32],
            value: *v,
            script: s.clone(),
        })
        .collect();

    let total_consumed = start_len - rest.len();

    Ok((
        GenesisItem {
            siblings,
            parent_index: output_idx as u32,
            sequence: 0x0000_0000, // Bark V3 uses Sequence::ZERO
            child_amount: 0,
            child_script_pubkey: Vec::new(),
            signature,
            sighash_flag: 0x00,
        },
        cosign_pubkeys,
        total_consumed,
    ))
}

/// Parse a Bark VtxoPolicy. Returns (user_pubkey_33B, consumed).
fn parse_policy(data: &[u8]) -> Result<(Vec<u8>, usize), VPackError> {
    if data.is_empty() {
        return Err(VPackError::IncompleteData);
    }
    let tag = data[0];
    let mut consumed = 1usize;
    match tag {
        // VTXO_POLICY_PUBKEY = 0x00
        0x00 => {
            if data.len() < consumed + 33 {
                return Err(VPackError::IncompleteData);
            }
            let user_pubkey = data[consumed..consumed + 33].to_vec();
            consumed += 33;
            Ok((user_pubkey, consumed))
        }
        // VTXO_POLICY_SERVER_HTLC_SEND = 0x01
        0x01 => {
            consumed += 33 + 32 + 4; // user_pubkey + payment_hash + htlc_expiry
            if data.len() < consumed {
                return Err(VPackError::IncompleteData);
            }
            let user_pubkey = data[1..34].to_vec();
            Ok((user_pubkey, consumed))
        }
        // VTXO_POLICY_SERVER_HTLC_RECV = 0x02
        0x02 => {
            consumed += 33 + 32 + 4 + 2; // user_pubkey + payment_hash + htlc_expiry + htlc_expiry_delta
            if data.len() < consumed {
                return Err(VPackError::IncompleteData);
            }
            let user_pubkey = data[1..34].to_vec();
            Ok((user_pubkey, consumed))
        }
        _ => {
            // Unknown policy — skip tag only
            Ok((Vec::new(), 1))
        }
    }
}

/// Deserializes bark (Second Tech) raw ProtocolEncoding bytes into V-PACK standard grammar.
pub fn bark_to_vpack(raw_bytes: &[u8], fee_anchor_script: &[u8]) -> Result<VPackTree, VPackError> {
    let mut rest = raw_bytes;

    // Version (u16)
    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let _version = LittleEndian::read_u16(&rest[0..2]);
    rest = &rest[2..];

    // Amount (u64)
    if rest.len() < 8 {
        return Err(VPackError::IncompleteData);
    }
    let amount = LittleEndian::read_u64(&rest[0..8]);
    rest = &rest[8..];

    // Expiry height (u32)
    if rest.len() < 4 {
        return Err(VPackError::IncompleteData);
    }
    let expiry_height = LittleEndian::read_u32(&rest[0..4]);
    rest = &rest[4..];

    // Server pubkey (33 bytes compressed)
    if rest.len() < 33 {
        return Err(VPackError::IncompleteData);
    }
    let server_pubkey = rest[..33].to_vec();
    rest = &rest[33..];

    // Exit delta (u16)
    if rest.len() < 2 {
        return Err(VPackError::IncompleteData);
    }
    let exit_delta = LittleEndian::read_u16(&rest[0..2]);
    rest = &rest[2..];

    // Anchor OutPoint (36 bytes: 32B txid + 4B vout LE)
    let (anchor_point, op_consumed) = parse_outpoint_consensus(rest)?;
    rest = &rest[op_consumed..];

    // Genesis chain: CompactSize(nb_items) + items
    let (genesis_count, cs_consumed) = read_cs(rest)?;
    rest = &rest[cs_consumed..];

    let fee_anchor_script_vec = fee_anchor_script.to_vec();
    let fee_anchor_sibling = SiblingNode::Compact {
        hash: [0u8; 32],
        value: 0,
        script: fee_anchor_script_vec.clone(),
    };

    let mut path: Vec<GenesisItem> = Vec::with_capacity(genesis_count as usize);
    let mut all_cosign_keys: Vec<Vec<Vec<u8>>> = Vec::new();

    for _ in 0..genesis_count {
        let (mut item, cosign_keys, consumed) = parse_genesis_item(rest)?;
        item.siblings.push(fee_anchor_sibling.clone());
        path.push(item);
        all_cosign_keys.push(cosign_keys);
        rest = &rest[consumed..];
    }

    // Compute child_amount for each genesis item.
    // chain_anchor_amount = vtxo_amount + sum(all fee_amounts + all other_output values)
    // We compute backwards: the last child_amount should equal `amount`.
    // child_amount[i] = child_amount[i-1] - sum(siblings[i+1] values excluding fee anchor)
    // Actually: go forward, tracking running value.
    // We don't know the on-chain anchor value, so we compute it:
    //   anchor_value = amount + sum(other_output_values for all items) + sum(fee_amounts)
    // Then child_amount[0] = anchor_value - sum(other_outputs[0]) - fee[0]
    // child_amount[i] = child_amount[i-1] - sum(other_outputs[i]) - fee[i]
    {
        let mut total_other: u64 = 0;
        for item in &path {
            for sib in &item.siblings {
                if let SiblingNode::Compact { value, .. } = sib {
                    total_other = total_other.saturating_add(*value);
                }
            }
        }
        let anchor_value = amount.saturating_add(total_other);
        let mut running = anchor_value;
        for item in path.iter_mut() {
            let sib_sum: u64 = item
                .siblings
                .iter()
                .map(|s| match s {
                    SiblingNode::Compact { value, .. } => *value,
                    SiblingNode::Full(txout) => txout.value.to_sat(),
                })
                .sum();
            running = running.saturating_sub(sib_sum);
            item.child_amount = running;
        }
    }

    // Policy: u8 tag + fields
    let (user_pubkey, policy_consumed) = parse_policy(rest)?;
    rest = &rest[policy_consumed..];

    // Point: OutPoint (36 bytes) = VtxoId
    let (point, point_consumed) = parse_outpoint_consensus(rest)?;
    rest = &rest[point_consumed..];

    if !rest.is_empty() {
        return Err(VPackError::TrailingData(rest.len()));
    }

    // Build the leaf output scriptPubkey.
    // For Pubkey policy, the VTXO output is a P2TR with:
    //   internal_key = MuSig2(user_pubkey, server_pubkey)
    //   script_tree = exit_clause(user_pubkey, exit_delta)
    // We can't compute MuSig2 in no_std, so we store the server_pubkey as
    // script_pubkey for now. The test-level crypto audit uses ark-lib for
    // full verification.
    let leaf = VtxoLeaf {
        amount,
        vout: point.vout,
        sequence: 0x0000_0000,
        expiry: expiry_height,
        exit_delta,
        script_pubkey: if !user_pubkey.is_empty() {
            user_pubkey.clone()
        } else {
            server_pubkey.clone()
        },
    };

    let leaf_siblings = Vec::from([fee_anchor_sibling]);

    Ok(VPackTree {
        leaf,
        leaf_siblings,
        path,
        anchor: anchor_point,
        asset_id: None,
        fee_anchor_script: fee_anchor_script_vec,
        internal_key: [0u8; 32],
        asp_expiry_script: alloc::vec![],
    })
}
