// src/payload/reader.rs
//
// Explicit cursor control: every field is read via split_at / re-slice.
// No reliance on consensus_decode or BorshDeserialize advancing the outer slice.

use crate::error::VPackError;
use crate::header::{Header, TxVariant};
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use alloc::vec::Vec;
use crate::types::{decode_outpoint, Amount, ScriptBuf, TxOut};
use byteorder::{ByteOrder, LittleEndian};

/// The Bounded Reader.
/// Parses a byte slice into a VPackTree, enforcing Header limits and
/// using the correct serialization format for each field type.
pub struct BoundedReader;

impl BoundedReader {
    pub fn parse(header: &Header, mut data: &[u8]) -> Result<VPackTree, VPackError> {
        // ---------------------------------------------------------
        // 1. Parse Prefix Section (Fail-Fast). All three before Tree.
        // Order: Asset ID (conditional) → Anchor OutPoint → fee_anchor_script.
        // ---------------------------------------------------------

        // A. Asset ID (Optional, 32 bytes if Flags & 0x08)
        let asset_id = if header.has_asset_id() {
            if data.len() < 32 {
                return Err(VPackError::IncompleteData);
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[0..32]);
            data = &data[32..]; // Advance cursor manually
            Some(buf)
        } else {
            None
        };

        // B. Anchor OutPoint (Fixed 36 bytes: 32 TxID + 4 vout)
        if data.len() < 36 {
            return Err(VPackError::IncompleteData);
        }
        let (anchor_bytes, rest) = data.split_at(36);
        let mut anchor_slice = anchor_bytes;
        let anchor = decode_outpoint(&mut anchor_slice)?;
        data = rest; // EXPLICITLY ADVANCE THE SLICE

        // C. fee_anchor_script (Borsh Vec<u8>: u32 len LE + that many bytes)
        if data.len() < 4 {
            return Err(VPackError::IncompleteData);
        }
        let script_len = LittleEndian::read_u32(&data[0..4]) as usize;
        let (_, rest) = data.split_at(4);
        data = rest;
        if data.len() < script_len {
            return Err(VPackError::IncompleteData);
        }
        let (script_bytes, rest) = data.split_at(script_len);
        data = rest;
        let fee_anchor_script = script_bytes.to_vec();
        if matches!(header.tx_variant, TxVariant::V3Anchored) && fee_anchor_script.is_empty() {
            return Err(VPackError::FeeAnchorMissing);
        }

        // ---------------------------------------------------------
        // 2. Parse Tree Section (explicit slice advancing only)
        // ---------------------------------------------------------

        // A. Leaf: amount(8) + vout(4) + sequence(4) + expiry(4) + exit_delta(2) + Borsh Vec<u8>(4+len)
        const LEAF_FIXED: usize = 8 + 4 + 4 + 4 + 2; // 22
        if data.len() < LEAF_FIXED + 4 {
            return Err(VPackError::IncompleteData);
        }
        let amount = LittleEndian::read_u64(&data[0..8]);
        let vout = LittleEndian::read_u32(&data[8..12]);
        let sequence = LittleEndian::read_u32(&data[12..16]);
        let expiry = LittleEndian::read_u32(&data[16..20]);
        let exit_delta = LittleEndian::read_u16(&data[20..22]);
        let (_, rest) = data.split_at(LEAF_FIXED);
        data = rest;
        let leaf_script_len = LittleEndian::read_u32(&data[0..4]) as usize;
        let (_, rest) = data.split_at(4);
        data = rest;
        if data.len() < leaf_script_len {
            return Err(VPackError::IncompleteData);
        }
        let (leaf_script_bytes, rest) = data.split_at(leaf_script_len);
        data = rest;
        let leaf = VtxoLeaf {
            amount,
            vout,
            sequence,
            expiry,
            exit_delta,
            script_pubkey: leaf_script_bytes.to_vec(),
        };

        // B. Path length (Borsh u32 = 4 bytes LE)
        if data.len() < 4 {
            return Err(VPackError::IncompleteData);
        }
        let path_len = LittleEndian::read_u32(&data[0..4]);
        let (_, rest) = data.split_at(4);
        data = rest;

        // Borsh Bomb DoS: reject path_len before any allocation (Landmine 2).
        if path_len > header.tree_depth as u32 {
            return Err(VPackError::ExceededMaxDepth(path_len as u16));
        }

        let mut path = Vec::with_capacity(path_len as usize);

        for _item_idx in 0..path_len {
            // C. Siblings length (V-PACK standard: Borsh u32 = 4 bytes LE; do not use u16)
            if data.len() < 4 {
                return Err(VPackError::IncompleteData);
            }
            let siblings_len = LittleEndian::read_u32(&data[0..4]);
            let (_, rest) = data.split_at(4);
            data = rest;

            // SECURITY CHECK: Tree Arity
            if siblings_len > header.tree_arity as u32 {
                return Err(VPackError::ExceededMaxArity(siblings_len as u16));
            }

            let mut siblings = Vec::with_capacity(siblings_len as usize);

            for _sibling_idx in 0..siblings_len {
                let sibling = if header.is_compact() {
                    // COMPACT MODE:
                    // 1. 32-byte hash
                    // 2. 8-byte value (u64 LE)
                    // 3. Borsh Vec<u8> script (u32 len + bytes)

                    // 1. Read Hash (32B)
                    if data.len() < 32 {
                        return Err(VPackError::IncompleteData);
                    }
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&data[..32]);
                    data = &data[32..];

                    // 2. Read Value (8B LE)
                    if data.len() < 8 {
                        return Err(VPackError::IncompleteData);
                    }
                    let value = LittleEndian::read_u64(&data[..8]);
                    data = &data[8..];

                    // 3. Script (Borsh Vec<u8>: u32 len + bytes)
                    if data.len() < 4 {
                        return Err(VPackError::IncompleteData);
                    }
                    let script_len = LittleEndian::read_u32(&data[0..4]) as usize;
                    let (_, rest) = data.split_at(4);
                    data = rest;
                    if data.len() < script_len {
                        return Err(VPackError::IncompleteData);
                    }
                    let (script_slice, rest) = data.split_at(script_len);
                    data = rest;
                    let script = script_slice.to_vec();

                    SiblingNode::Compact {
                        hash,
                        value,
                        script,
                    }
                } else {
                    // FULL MODE: Bitcoin TxOut (Consensus Decode)
                    // Format: [8-byte Value LE] [VarInt ScriptLen] [Script Bytes]
                    // We must manually parse to explicitly advance the cursor

                    // 1. Read value (8 bytes)
                    if data.len() < 8 {
                        return Err(VPackError::IncompleteData);
                    }
                    let value = LittleEndian::read_u64(&data[..8]);
                    let mut cursor = &data[8..];

                    // 2. Read VarInt script length
                    let script_len = if cursor.is_empty() {
                        return Err(VPackError::IncompleteData);
                    } else if cursor[0] < 0xfd {
                        let len = cursor[0] as u64;
                        cursor = &cursor[1..];
                        len
                    } else if cursor[0] == 0xfd {
                        if cursor.len() < 3 {
                            return Err(VPackError::IncompleteData);
                        }
                        let len = LittleEndian::read_u16(&cursor[1..3]) as u64;
                        cursor = &cursor[3..];
                        len
                    } else if cursor[0] == 0xfe {
                        if cursor.len() < 5 {
                            return Err(VPackError::IncompleteData);
                        }
                        let len = LittleEndian::read_u32(&cursor[1..5]) as u64;
                        cursor = &cursor[5..];
                        len
                    } else {
                        if cursor.len() < 9 {
                            return Err(VPackError::IncompleteData);
                        }
                        let len = LittleEndian::read_u64(&cursor[1..9]);
                        cursor = &cursor[9..];
                        len
                    };

                    // 3. Read script bytes
                    let script_len_usize = script_len as usize;
                    if cursor.len() < script_len_usize {
                        return Err(VPackError::IncompleteData);
                    }
                    let script_bytes = &cursor[..script_len_usize];

                    // 4. Reconstruct TxOut and advance data slice
                    let txout = TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: ScriptBuf::from_bytes(script_bytes.to_vec()),
                    };

                    // Calculate total consumed: 8 (value) + VarInt bytes + script bytes
                    let varint_bytes = if script_len < 0xfd {
                        1
                    } else if script_len < 0x1_0000 {
                        3
                    } else if script_len < 0x1_0000_0000 {
                        5
                    } else {
                        9
                    };
                    let total_consumed = 8 + varint_bytes + script_len_usize;
                    data = &data[total_consumed..]; // EXPLICITLY ADVANCE THE SLICE

                    SiblingNode::Full(txout)
                };
                siblings.push(sibling);
            }

            // D. parent_index(4) + sequence(4) + child_amount(8) + child_script_pubkey(4+len) + signature(1 or 1+64)
            if data.len() < 4 {
                return Err(VPackError::IncompleteData);
            }
            let parent_index = LittleEndian::read_u32(&data[0..4]);
            let (_, rest) = data.split_at(4);
            data = rest;
            if data.len() < 4 {
                return Err(VPackError::IncompleteData);
            }
            let sequence = LittleEndian::read_u32(&data[0..4]);
            let (_, rest) = data.split_at(4);
            data = rest;
            if data.len() < 8 {
                return Err(VPackError::IncompleteData);
            }
            let child_amount = LittleEndian::read_u64(&data[0..8]);
            let (_, rest) = data.split_at(8);
            data = rest;
            if data.len() < 4 {
                return Err(VPackError::IncompleteData);
            }
            let child_script_len = LittleEndian::read_u32(&data[0..4]) as usize;
            let (_, rest) = data.split_at(4);
            data = rest;
            if data.len() < child_script_len {
                return Err(VPackError::IncompleteData);
            }
            let (child_script_slice, rest) = data.split_at(child_script_len);
            data = rest;
            let child_script_pubkey = child_script_slice.to_vec();
            if data.is_empty() {
                return Err(VPackError::IncompleteData);
            }
            let sig_tag = data[0];
            let (_, rest) = data.split_at(1);
            data = rest;
            let signature = if sig_tag == 0 {
                None
            } else if sig_tag == 1 {
                if data.len() < 64 {
                    return Err(VPackError::IncompleteData);
                }
                let (sig_bytes, rest) = data.split_at(64);
                data = rest;
                let mut arr = [0u8; 64];
                arr.copy_from_slice(sig_bytes);
                Some(arr)
            } else {
                return Err(VPackError::EncodingError);
            };

            path.push(GenesisItem {
                siblings,
                parent_index,
                sequence,
                child_amount,
                child_script_pubkey,
                signature,
            });
        }

        if !data.is_empty() {
            return Err(VPackError::TrailingData(data.len()));
        }

        Ok(VPackTree {
            leaf,
            path,
            anchor,
            asset_id,
            fee_anchor_script,
        })
    }
}
