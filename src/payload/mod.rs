pub mod reader;
pub mod tree;

use crate::error::VPackError;
use crate::header::Header;
use crate::payload::tree::{SiblingNode, VPackTree};

/// Validates global policy invariants: fee_anchor_script consistency and sequence/exit_delta
/// consistency along the path. Call after parsing and before engine verification.
pub fn validate_invariants(header: &Header, tree: &VPackTree) -> Result<(), VPackError> {
    // Sequence consistency: every path item must match leaf sequence.
    for item in &tree.path {
        if item.sequence != tree.leaf.sequence {
            return Err(VPackError::PolicyMismatch);
        }
    }

    // Fee anchor consistency: for V3-Anchored with non-empty fee_anchor_script, each level
    // (path items and leaf_siblings) that has siblings must include the fee anchor script.
    if matches!(header.tx_variant, crate::header::TxVariant::V3Anchored)
        && !tree.fee_anchor_script.is_empty()
    {
        let has_fee_anchor = |siblings: &[SiblingNode]| {
            siblings.iter().any(|s| match s {
                SiblingNode::Compact { script, .. } => {
                    script.as_slice() == tree.fee_anchor_script.as_slice()
                }
                SiblingNode::Full(txout) => {
                    txout.script_pubkey.as_bytes() == tree.fee_anchor_script.as_slice()
                }
            })
        };
        for item in &tree.path {
            if !item.siblings.is_empty() && !has_fee_anchor(&item.siblings) {
                return Err(VPackError::PolicyMismatch);
            }
        }
        if !tree.leaf_siblings.is_empty() && !has_fee_anchor(&tree.leaf_siblings) {
            return Err(VPackError::PolicyMismatch);
        }
    }

    Ok(())
}
