//! Payload serialization round-trip tests.

#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::header::{Header, TxVariant, FLAG_PROOF_COMPACT, HEADER_SIZE};
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::pack::pack;
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::payload::reader::BoundedReader;
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::payload::tree::{VPackTree, VtxoLeaf};
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::types::hashes::Hash;
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use crate::types::{OutPoint, Txid};
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
use alloc::vec::Vec;

/// Round-trip: serialize VPackTree to bytes, deserialize back, assert equality.
#[test]
#[cfg(any(feature = "bitcoin", feature = "wasm"))]
fn test_vpack_tree_serialization_roundtrip() {
    let internal_key = [0xAAu8; 32];
    let asp_expiry_script = alloc::vec![0x51, 0x02];

    let txid = Txid::from_byte_array([0x42u8; 32]);
    let anchor = OutPoint { txid, vout: 0 };
    let fee_anchor_script = alloc::vec![0x51, 0x02, 0x4e, 0x73];

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: alloc::vec![0x51, 0x20, 0x00],
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor,
        asset_id: None,
        fee_anchor_script,
        internal_key,
        asp_expiry_script: asp_expiry_script.clone(),
    };

    let header = Header {
        flags: FLAG_PROOF_COMPACT,
        version: 1,
        tx_variant: TxVariant::V3Plain,
        tree_arity: 16,
        tree_depth: 32,
        node_count: 0,
        asset_type: 0,
        payload_len: 0,
        checksum: 0,
    };

    let packed = pack(&header, &tree).expect("pack");
    let parsed_header = Header::from_bytes(&packed[..HEADER_SIZE]).expect("parse header");
    let payload = &packed[HEADER_SIZE..];
    let parsed_tree = BoundedReader::parse(&parsed_header, payload).expect("parse payload");

    assert_eq!(tree, parsed_tree);
    assert_eq!(parsed_tree.internal_key, [0xAAu8; 32]);
    assert_eq!(parsed_tree.asp_expiry_script, asp_expiry_script);
}
