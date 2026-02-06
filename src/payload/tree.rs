use bitcoin::{OutPoint, TxOut};
use alloc::vec::Vec;
use borsh::{BorshSerialize, BorshDeserialize};

/// The Fully Parsed V-PACK Tree.
/// This struct is the result of the "Bounded Reader."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VPackTree {
    /// The specific leaf owned by the user.
    pub leaf: VtxoLeaf,
    /// The path from Leaf to Root (The "Recipe").
    /// Validated to not exceed `header.tree_depth`.
    pub path: Vec<GenesisItem>,
    /// The On-Chain Anchor (Parsed from the Prefix).
    pub anchor: OutPoint,
    /// Optional Asset ID (Parsed from the Prefix if flag set).
    pub asset_id: Option<[u8; 32]>,
    /// Fee anchor script (Prefix). Required non-empty for V3-Anchored.
    pub fee_anchor_script: Vec<u8>,
}

/// The User's specific UTXO leaf.
/// Fixed-width fields first, variable-length last for efficient no_std parsing.
/// Field order matches V-BIP-01 v1.1.0 and Borsh wire format.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VtxoLeaf {
    pub amount: u64,
    pub vout: u32,
    pub sequence: u32,
    pub expiry: u32,
    pub exit_delta: u16,
    pub script_pubkey: Vec<u8>,
}

/// A single step in the reconstruction recipe.
/// Field order matches V-BIP-01 and Borsh wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisItem {
    /// The siblings needed to reconstruct the transaction at this level.
    /// Validated to not exceed `header.tree_arity`.
    pub siblings: Vec<SiblingNode>,
    /// The index of the parent node in the next level.
    pub parent_index: u32,
    pub sequence: u32,
    pub child_amount: u64,
    pub child_script_pubkey: Vec<u8>,
    /// Cosigned transition support (Second Tech audit). Borsh: 1-byte tag then 64 bytes if Some.
    pub signature: Option<[u8; 64]>,
}

/// A Sibling can be a Hash (Compact) or a Full TxOut (Hydrated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiblingNode {
    /// Used when `FLAG_PROOF_COMPACT` is set.
    /// 32-byte child VTXO hash (identity), satoshi value (value-checking), and script (transaction reconstruction).
    Compact {
        hash: [u8; 32],
        value: u64,
        script: Vec<u8>,
    },

    /// Used when `FLAG_PROOF_COMPACT` is NOT set.
    /// Full Bitcoin TxOut.
    Full(TxOut),
}

// Manual serialization helper for SiblingNode since it depends on flags,
// usually handled by the custom reader/writer logic.
impl SiblingNode {
    pub fn is_compact(&self) -> bool {
        matches!(self, SiblingNode::Compact { .. })
    }
}