//! Universal De-Siloer: build standard-compliant V-PACK bytes from silo ingredients.
//!
//! Header fields (tree_arity, tree_depth, node_count) are derived from the built tree
//! so Header and Payload are always synchronized.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use byteorder::{ByteOrder, LittleEndian};

use crate::error::VPackError;
use crate::header::{
    Header, TxVariant, FLAG_PROOF_COMPACT, MAX_PAYLOAD_SIZE, MAX_TREE_ARITY, MAX_TREE_DEPTH,
};
use crate::pack;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use crate::VtxoId;

/// Default fee anchor script (hex 51024e73).
const DEFAULT_FEE_ANCHOR_SCRIPT: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

// -----------------------------------------------------------------------------
// Ark Labs ingredients
// -----------------------------------------------------------------------------

/// One output in Ark Labs reconstruction (value + script).
#[derive(Debug, Clone)]
pub struct ArkLabsOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

/// One sibling in a branch step (hash, value, script).
#[derive(Debug, Clone)]
pub struct ArkLabsSibling {
    pub hash: [u8; 32],
    pub value: u64,
    pub script: Vec<u8>,
}

/// Ingredients to rebuild an Ark Labs (V3-Anchored) V-PACK.
#[derive(Debug, Clone)]
pub struct ArkLabsIngredients {
    /// Parent or anchor outpoint, e.g. `"txid:0"` (display order).
    pub anchor_outpoint: String,
    /// Fee anchor script bytes (default 51024e73 if empty).
    pub fee_anchor_script: Vec<u8>,
    /// nSequence (e.g. 0xFFFFFFFF round, 0xFFFFFFFE OOR).
    pub n_sequence: u32,
    /// At least one output; first is the leaf when path is empty.
    pub outputs: Vec<ArkLabsOutput>,
    /// Branch case: siblings for the single path step.
    pub siblings: Option<Vec<ArkLabsSibling>>,
    /// Branch case: child output (value + script) for the path step.
    pub child_output: Option<ArkLabsOutput>,
}

// -----------------------------------------------------------------------------
// Second Tech ingredients
// -----------------------------------------------------------------------------

/// One sibling in a path step.
#[derive(Debug, Clone)]
pub struct SecondTechSibling {
    pub hash: [u8; 32],
    pub value: u64,
    pub script: Vec<u8>,
}

/// One genesis step in the path.
#[derive(Debug, Clone)]
pub struct SecondTechGenesisStep {
    pub siblings: Vec<SecondTechSibling>,
    pub parent_index: u32,
    pub sequence: u32,
    pub child_amount: u64,
    pub child_script_pubkey: Vec<u8>,
}

/// Ingredients to rebuild a Second Tech (V3-Plain) V-PACK. nSequence is always 0.
#[derive(Debug, Clone)]
pub struct SecondTechIngredients {
    pub anchor_outpoint: String,
    pub fee_anchor_script: Vec<u8>,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub exit_delta: u16,
    pub vout: u32,
    pub expiry_height: u32,
    pub path: Vec<SecondTechGenesisStep>,
}

// -----------------------------------------------------------------------------
// Header from tree (synchronized with payload)
// -----------------------------------------------------------------------------

/// Builds a header from the tree so arity, depth, and node_count match the payload.
fn header_from_tree(tx_variant: TxVariant, tree: &VPackTree) -> Result<Header, VPackError> {
    let tree_depth = tree.path.len() as u32;
    let (node_count, tree_arity) = tree
        .path
        .iter()
        .fold((0u32, 0u32), |(count, max_arity), item| {
            let n = item.siblings.len() as u32;
            (count + n, core::cmp::max(max_arity, n))
        });
    let tree_arity = if tree_depth == 0 {
        core::cmp::max(2, tree_arity)
    } else {
        core::cmp::max(2, tree_arity)
    };
    let tree_depth = core::cmp::min(tree_depth, MAX_TREE_DEPTH as u32) as u16;
    let tree_arity = core::cmp::min(tree_arity, MAX_TREE_ARITY as u32) as u16;
    let node_count = core::cmp::min(node_count, (MAX_TREE_DEPTH as u32) * (MAX_TREE_ARITY as u32)) as u16;

    let payload = pack::serialize_payload_for_header(tree)?;
    let payload_len = payload.len();
    if payload_len > MAX_PAYLOAD_SIZE as usize {
        return Err(VPackError::PayloadTooLarge(payload_len as u32));
    }
    let payload_len = payload_len as u32;

    let mut header_buf = [0u8; 20];
    header_buf[0..3].copy_from_slice(&crate::header::MAGIC_BYTES);
    header_buf[3] = FLAG_PROOF_COMPACT;
    header_buf[4] = crate::header::CURRENT_VERSION;
    header_buf[5] = tx_variant.as_u8();
    LittleEndian::write_u16(&mut header_buf[6..8], tree_arity);
    LittleEndian::write_u16(&mut header_buf[8..10], tree_depth);
    LittleEndian::write_u16(&mut header_buf[10..12], node_count);
    LittleEndian::write_u32(&mut header_buf[12..16], 0);
    LittleEndian::write_u32(&mut header_buf[16..20], payload_len);

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&header_buf);
    hasher.update(&payload);
    let checksum = hasher.finalize();

    Ok(Header {
        flags: FLAG_PROOF_COMPACT,
        version: crate::header::CURRENT_VERSION,
        tx_variant,
        tree_arity,
        tree_depth,
        node_count,
        asset_type: 0,
        payload_len,
        checksum,
    })
}

// -----------------------------------------------------------------------------
// Ark Labs: ingredients -> tree
// -----------------------------------------------------------------------------

fn tree_from_ark_labs_ingredients(ingredients: &ArkLabsIngredients) -> Result<VPackTree, VPackError> {
    let anchor_id = VtxoId::from_str(ingredients.anchor_outpoint.trim())
        .map_err(|_| VPackError::InvalidVtxoIdFormat)?;
    let anchor = match anchor_id {
        VtxoId::OutPoint(op) => op,
        VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
    };

    let fee_anchor_script = if ingredients.fee_anchor_script.is_empty() {
        DEFAULT_FEE_ANCHOR_SCRIPT.to_vec()
    } else {
        ingredients.fee_anchor_script.clone()
    };

    let first_output = ingredients
        .outputs
        .first()
        .ok_or(VPackError::EncodingError)?;
    let value = first_output.value;
    let script_pubkey = first_output.script.clone();

    let (path, leaf) = if let Some(ref siblings) = ingredients.siblings {
        let (child_amount, child_script_pubkey) = if let Some(ref co) = ingredients.child_output {
            (co.value, co.script.clone())
        } else {
            (value, script_pubkey.clone())
        };
        let sibling_nodes: Vec<SiblingNode> = siblings
            .iter()
            .map(|s| SiblingNode::Compact {
                hash: s.hash,
                value: s.value,
                script: s.script.clone(),
            })
            .collect();
        let path = if sibling_nodes.is_empty() {
            vec![]
        } else {
            vec![GenesisItem {
                siblings: sibling_nodes,
                parent_index: 0,
                sequence: ingredients.n_sequence,
                child_amount,
                child_script_pubkey: child_script_pubkey.clone(),
                signature: None,
            }]
        };
        let leaf = VtxoLeaf {
            amount: child_amount,
            vout: 0,
            sequence: ingredients.n_sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: child_script_pubkey,
        };
        (path, leaf)
    } else {
        if script_pubkey.is_empty() {
            return Err(VPackError::EncodingError);
        }
        let leaf = VtxoLeaf {
            amount: value,
            vout: 0,
            sequence: ingredients.n_sequence,
            expiry: 0,
            exit_delta: 0,
            script_pubkey,
        };
        (Vec::new(), leaf)
    };

    Ok(VPackTree {
        leaf,
        path,
        anchor,
        asset_id: None,
        fee_anchor_script,
    })
}

// -----------------------------------------------------------------------------
// Second Tech: ingredients -> tree (nSequence = 0)
// -----------------------------------------------------------------------------

fn tree_from_second_tech_ingredients(
    ingredients: &SecondTechIngredients,
) -> Result<VPackTree, VPackError> {
    let anchor_id = VtxoId::from_str(ingredients.anchor_outpoint.trim())
        .map_err(|_| VPackError::InvalidVtxoIdFormat)?;
    let anchor = match anchor_id {
        VtxoId::OutPoint(op) => op,
        VtxoId::Raw(_) => return Err(VPackError::InvalidVtxoIdFormat),
    };

    let fee_anchor_script = if ingredients.fee_anchor_script.is_empty() {
        DEFAULT_FEE_ANCHOR_SCRIPT.to_vec()
    } else {
        ingredients.fee_anchor_script.clone()
    };

    let path: Vec<GenesisItem> = ingredients
        .path
        .iter()
        .map(|step| GenesisItem {
            siblings: step
                .siblings
                .iter()
                .map(|s| SiblingNode::Compact {
                    hash: s.hash,
                    value: s.value,
                    script: s.script.clone(),
                })
                .collect(),
            parent_index: step.parent_index,
            sequence: step.sequence,
            child_amount: step.child_amount,
            child_script_pubkey: step.child_script_pubkey.clone(),
            signature: None,
        })
        .collect();

    let leaf = VtxoLeaf {
        amount: ingredients.amount,
        vout: ingredients.vout,
        sequence: 0,
        expiry: ingredients.expiry_height,
        exit_delta: ingredients.exit_delta,
        script_pubkey: ingredients.script_pubkey.clone(),
    };

    Ok(VPackTree {
        leaf,
        path,
        anchor,
        asset_id: None,
        fee_anchor_script,
    })
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Builds a full V-PACK (Header + Prefix + Tree) from Ark Labs silo ingredients.
/// Fee anchor script and nSequence are applied per forensic requirements.
pub fn create_vpack_ark_labs(ingredients: ArkLabsIngredients) -> Result<Vec<u8>, VPackError> {
    let tree = tree_from_ark_labs_ingredients(&ingredients)?;
    let header = header_from_tree(TxVariant::V3Anchored, &tree)?;
    pack::pack(&header, &tree)
}

/// Builds a full V-PACK (Header + Prefix + Tree) from Second Tech silo ingredients.
/// nSequence is enforced as 0; identity is OutPoint (Hash:Index).
pub fn create_vpack_second_tech(ingredients: SecondTechIngredients) -> Result<Vec<u8>, VPackError> {
    let tree = tree_from_second_tech_ingredients(&ingredients)?;
    let header = header_from_tree(TxVariant::V3Plain, &tree)?;
    pack::pack(&header, &tree)
}

/// Builds a full V-PACK from an existing tree and tx variant (e.g. from LogicAdapter).
/// Used by wasm-vpack for auto-inference: adapter yields tree + variant, then pack and verify.
pub fn create_vpack_from_tree(
    tree: &VPackTree,
    tx_variant: TxVariant,
) -> Result<Vec<u8>, VPackError> {
    let header = header_from_tree(tx_variant, tree)?;
    pack::pack(&header, tree)
}
