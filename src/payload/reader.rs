// src/payload/reader.rs

use crate::error::VPackError;
use crate::header::{Header, TxVariant};
use crate::payload::tree::{VPackTree, GenesisItem, SiblingNode, VtxoLeaf};
use bitcoin::{OutPoint, TxOut};
use bitcoin::consensus::Decodable;
use borsh::BorshDeserialize;
use byteorder::{ByteOrder, LittleEndian};
use alloc::vec::Vec;

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
            if data.len() < 32 { return Err(VPackError::IncompleteData); }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&data[0..32]);
            data = &data[32..]; // Advance cursor manually
            Some(buf)
        } else {
            None
        };

        // B. Anchor OutPoint (36 bytes: 32 TxID + 4 vout)
        let anchor = OutPoint::consensus_decode(&mut data)
            .map_err(|_| VPackError::IncompleteData)?;

        // C. fee_anchor_script (Borsh length-prefixed Vec<u8>)
        let fee_anchor_script = Vec::<u8>::deserialize(&mut data)
            .map_err(|_| VPackError::EncodingError)?;
        if matches!(header.tx_variant, TxVariant::V3Anchored) && fee_anchor_script.is_empty() {
            return Err(VPackError::FeeAnchorMissing);
        }

        // ---------------------------------------------------------
        // 2. Parse Tree Section (Hybrid: Borsh + Bitcoin Consensus)
        // ---------------------------------------------------------

        // A. Parse the Leaf (V-PACK Specific Struct -> Borsh)
        let leaf = VtxoLeaf::deserialize(&mut data)
            .map_err(|_| VPackError::EncodingError)?;

        // B. Parse the Path Length (Borsh u32)
        let path_len = u32::deserialize(&mut data)
            .map_err(|_| VPackError::EncodingError)?;

        // Borsh Bomb DoS: reject path_len before any allocation (Landmine 2).
        if path_len > header.tree_depth as u32 {
            return Err(VPackError::ExceededMaxDepth(path_len as u16));
        }

        let mut path = Vec::with_capacity(path_len as usize);

        for _ in 0..path_len {
            // C. Parse Siblings Length (Borsh u32)
            let siblings_len = u32::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;

            // SECURITY CHECK: Tree Arity
            if siblings_len > header.tree_arity as u32 {
                return Err(VPackError::ExceededMaxArity(siblings_len as u16));
            }

            let mut siblings = Vec::with_capacity(siblings_len as usize);

            for _ in 0..siblings_len {
                let sibling = if header.is_compact() {
                    // COMPACT MODE: 32-byte hash + 8-byte value (u64 LE) + Borsh Vec<u8> script
                    if data.len() < 40 { return Err(VPackError::IncompleteData); }
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&data[0..32]);
                    let value = LittleEndian::read_u64(&data[32..40]);
                    data = &data[40..];
                    let script = Vec::<u8>::deserialize(&mut data)
                        .map_err(|_| VPackError::EncodingError)?;
                    SiblingNode::Compact { hash, value, script }
                } else {
                    // FULL MODE: Bitcoin TxOut (Consensus Decode)
                    // This reads [VarInt Value] [VarInt ScriptLen] [Script Bytes]
                    // This matches the blockchain wire format exactly.
                    let txout = TxOut::consensus_decode(&mut data)
                        .map_err(|_| VPackError::EncodingError)?;
                    SiblingNode::Full(txout)
                };
                siblings.push(sibling);
            }

            // D. parent_index, sequence, child_amount, child_script_pubkey, signature (Borsh)
            let parent_index = u32::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;
            let sequence = u32::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;
            let child_amount = u64::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;
            let child_script_pubkey = Vec::<u8>::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;
            let signature = Option::<[u8; 64]>::deserialize(&mut data)
                .map_err(|_| VPackError::EncodingError)?;

            path.push(GenesisItem {
                siblings,
                parent_index,
                sequence,
                child_amount,
                child_script_pubkey,
                signature,
            });
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