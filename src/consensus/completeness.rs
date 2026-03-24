//! Static completeness checks before expensive cryptographic verification.
//!
//! # Exit-ready vs lifecycle
//!
//! [`validate_tree_completeness`] (and the alias [`validate_exit_ready_completeness`]) enforce
//! **exit-ready** data: every [`GenesisItem`](crate::payload::tree::GenesisItem) on the path must
//! carry a populated Schnorr signature. That matches trees where the ASP has already cosigned
//! intermediate spends.
//!
//! **Boarding** or early **out-of-round (OOR)** VTXOs can be valid *protocol* states while
//! signatures are still absent (round not closed). For those trees this function returns
//! [`crate::error::VPackError::TreeIncomplete`] even though the commitment may be legitimate.
//! A future `expected_state` (or similar) parameter could relax signature rules per lifecycle phase
//! (e.g. around a later “Commit 7” style gate).
//!
//! # Depth in [`crate::error::VPackError::TreeIncomplete`]
//!
//! * **`depth == 0`** — **Leaf tier:** `leaf.script_pubkey` or an entry in `leaf_siblings`.
//! * **`depth >= 1`** — **Path:** `depth` is **1-based** from the leaf (`1` = `path[0]`, `2` =
//!   `path[1]`, …).

use crate::error::VPackError;
use crate::payload::tree::{GenesisItem, SiblingNode, VPackTree};
use crate::types::TxOut;

fn signature_is_complete(sig: &Option<[u8; 64]>) -> bool {
    match sig {
        None => false,
        Some(bytes) => bytes.iter().any(|&b| b != 0),
    }
}

fn sibling_node_is_complete(sibling: &SiblingNode) -> bool {
    match sibling {
        SiblingNode::Compact { hash, script, .. } => {
            hash.iter().any(|&b| b != 0) && !script.is_empty()
        }
        SiblingNode::Full(txout) => full_txout_script_nonempty(txout),
    }
}

fn full_txout_script_nonempty(txout: &TxOut) -> bool {
    #[cfg(feature = "wasm")]
    {
        !txout.script_pubkey.as_bytes().is_empty()
    }
    #[cfg(all(feature = "bitcoin", not(feature = "wasm")))]
    {
        !txout.script_pubkey.is_empty()
    }
}

/// Each `leaf_siblings` entry must expose the same material as path siblings (non-zero compact
/// hash, non-empty script, or full txout with non-empty script).
fn validate_leaf_siblings(tree: &VPackTree) -> Result<(), VPackError> {
    for sibling in &tree.leaf_siblings {
        if !sibling_node_is_complete(sibling) {
            return Err(VPackError::TreeIncomplete {
                depth: 0,
                field: "leaf_sibling",
            });
        }
    }
    Ok(())
}

fn validate_genesis_item(item: &GenesisItem, path_depth: u16) -> Result<(), VPackError> {
    if item.siblings.is_empty() {
        return Err(VPackError::TreeIncomplete {
            depth: path_depth,
            field: "siblings",
        });
    }
    for sibling in &item.siblings {
        if !sibling_node_is_complete(sibling) {
            return Err(VPackError::TreeIncomplete {
                depth: path_depth,
                field: "sibling",
            });
        }
    }
    if !signature_is_complete(&item.signature) {
        return Err(VPackError::TreeIncomplete {
            depth: path_depth,
            field: "signature",
        });
    }
    Ok(())
}

/// Ensures withheld data is absent for **exit-ready** verification: non-empty leaf
/// `script_pubkey`, populated [`SiblingNode`](crate::payload::tree::SiblingNode) data in
/// `leaf_siblings` (each entry, if any), then for each path step non-empty sibling lists with
/// complete sibling payloads and a non-zero Schnorr signature.
///
/// See the [module documentation](crate::consensus::completeness) for lifecycle caveats (boarding /
/// OOR). Prefer [`validate_exit_ready_completeness`] when naming this policy in docs.
pub fn validate_tree_completeness(tree: &VPackTree) -> Result<(), VPackError> {
    if tree.leaf.script_pubkey.is_empty() {
        return Err(VPackError::TreeIncomplete {
            depth: 0,
            field: "leaf.script_pubkey",
        });
    }

    validate_leaf_siblings(tree)?;

    for (i, step) in tree.path.iter().enumerate() {
        let path_step_one_based = i.checked_add(1).ok_or(VPackError::ExceededMaxDepth(32))?;
        let path_depth =
            u16::try_from(path_step_one_based).map_err(|_| VPackError::ExceededMaxDepth(32))?;
        validate_genesis_item(step, path_depth)?;
    }

    Ok(())
}

/// Alias for [`validate_tree_completeness`]: same behavior, name reflects **exit-ready**
/// completeness (signatures required on every path step). See the [module](self) for boarding/OOR
/// limitations and future lifecycle-aware validation.
#[inline]
pub fn validate_exit_ready_completeness(tree: &VPackTree) -> Result<(), VPackError> {
    validate_tree_completeness(tree)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::payload::tree::VtxoLeaf;
    use crate::types::hashes::Hash;
    use crate::types::{OutPoint, Txid};

    fn p2tr_like_leaf_script() -> Vec<u8> {
        let mut s = Vec::with_capacity(34);
        s.extend_from_slice(&[0x51u8, 0x20]);
        s.extend_from_slice(&[0xEEu8; 32]);
        s
    }

    fn dummy_tree_with_path(path: Vec<GenesisItem>) -> VPackTree {
        let txid = Txid::from_byte_array([7u8; 32]);
        VPackTree {
            leaf: VtxoLeaf {
                amount: 1000,
                vout: 0,
                sequence: 0xFFFFFFFF,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: p2tr_like_leaf_script(),
            },
            leaf_siblings: Vec::new(),
            path,
            anchor: OutPoint { txid, vout: 0 },
            asset_id: None,
            fee_anchor_script: Vec::from([0x51u8, 0x01, 0x00]),
            internal_key: [1u8; 32],
            asp_expiry_script: Vec::from([0x63u8]),
        }
    }

    #[test]
    fn unit_rejects_empty_leaf_script() {
        let mut tree = dummy_tree_with_path(Vec::new());
        tree.leaf.script_pubkey.clear();
        assert_eq!(
            validate_tree_completeness(&tree),
            Err(VPackError::TreeIncomplete {
                depth: 0,
                field: "leaf.script_pubkey",
            })
        );
    }
}
