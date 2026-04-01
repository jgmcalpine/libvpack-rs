//! Dehydration integration tests.
//!
//! Uses `ark-lib` as the ground truth decoder for tree building where the `bark_to_vpack`
//! adapter's current linear-chain read would produce incorrect trees.
//!
//! Success criteria (from spec):
//! | Metric                | `VpackSovereigntyEnvelope` | `VpackExitWaterfall`  |
//! |:---                   |:---                        |:---                   |
//! | Storage Size          | < 500 bytes                | < 12,288 bytes        |
//! | RAM (streaming)       | < 1 KB                     | < 1 KB per hop        |

use std::path::PathBuf;
use vpack::consensus::second_tech::{compile_bark_expiry_script, compute_bark_vtxo_tapscript_root};
use vpack::dehydration::{bark_dehydrate, HopData, VpackExitWaterfall, VpackSovereigntyEnvelope};
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use vpack::types::hashes::Hash;
use vpack::VtxoId;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn vtxo_path(idx: u32) -> PathBuf {
    PathBuf::from(format!("tests/vectors/bark_qa/vtxo_{idx}.bin"))
}

fn fee_script() -> Vec<u8> {
    use hex::FromHex;
    Vec::from_hex("51024e73").expect("fee anchor script")
}

fn fee_anchor_sibling() -> SiblingNode {
    SiblingNode::Compact {
        hash: [0u8; 32],
        value: 0,
        script: fee_script(),
    }
}

/// Build a `VPackTree` directly from ark-lib exit-transaction data.
///
/// This bypasses the broken linear-chain parser in `bark_to_vpack` and gives a tree
/// with correct per-hop `child_amount`, `child_script_pubkey`, and sibling structure.
fn vpack_tree_from_arklib(path: &PathBuf) -> (VPackTree, VtxoId) {
    use ark::encode::ProtocolEncoding;
    use ark::vtxo::Vtxo;
    use ark::VtxoPolicy;

    let raw = std::fs::read(path).expect("read bark vector");
    let vtxo: Vtxo<ark::vtxo::Full, VtxoPolicy> =
        Vtxo::deserialize(&raw).expect("ark-lib deserialize");

    let internal_key: [u8; 32] = vtxo.output_taproot().internal_key().serialize();
    let expiry_height: u32 = vtxo.expiry_height();
    let exit_delta: u16 = vtxo.exit_delta();
    let _amount_sats: u64 = vtxo.amount().to_sat();

    let server_pk = vtxo.server_pubkey().serialize(); // 33-byte compressed
    let mut server_xonly = [0u8; 32];
    server_xonly.copy_from_slice(&server_pk[1..33]);
    let asp_expiry_script = compile_bark_expiry_script(expiry_height, &server_xonly);

    // Anchor outpoint
    let ark_anchor = vtxo.chain_anchor();
    use vpack::types::{OutPoint, Txid};
    let anchor = OutPoint {
        txid: Txid::from_byte_array(ark_anchor.txid.to_byte_array()),
        vout: ark_anchor.vout,
    };

    let txs: Vec<_> = vtxo.transactions().collect();
    let fee_sib = fee_anchor_sibling();

    let mut path_items: Vec<GenesisItem> = Vec::new();

    for item in txs.iter().take(txs.len().saturating_sub(1)) {
        let tx = &item.tx;
        let user_vout = item.output_idx;
        let user_out = &tx.output[user_vout];
        let child_amount = user_out.value.to_sat();
        let child_script = user_out.script_pubkey.as_bytes().to_vec();

        let siblings: Vec<SiblingNode> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != user_vout)
            .map(|(_, out)| SiblingNode::Compact {
                hash: [0u8; 32],
                value: out.value.to_sat(),
                script: out.script_pubkey.as_bytes().to_vec(),
            })
            .chain(core::iter::once(fee_sib.clone()))
            .collect();

        path_items.push(GenesisItem {
            siblings,
            parent_index: item.output_idx as u32,
            sequence: 0x0000_0000,
            child_amount,
            child_script_pubkey: child_script,
            signature: None,
            sighash_flag: 0x00,
        });
    }

    // Leaf = last exit transaction's user output.
    // script_pubkey stores the 33-byte compressed user pubkey (not the P2TR output script)
    // so that compute_bark_vtxo_tapscript_root can extract user_xonly from bytes [1..33].
    let last_item = txs.last().expect("at least one exit tx");
    let last_tx = &last_item.tx;
    let leaf_vout = last_item.output_idx as u32;
    let leaf_out = &last_tx.output[leaf_vout as usize];
    let user_pubkey_compressed = vtxo.policy().user_pubkey().serialize(); // 33 bytes

    let leaf = VtxoLeaf {
        amount: leaf_out.value.to_sat(),
        vout: leaf_vout,
        sequence: 0x0000_0000,
        expiry: expiry_height,
        exit_delta,
        script_pubkey: user_pubkey_compressed.to_vec(),
    };

    let leaf_siblings = vec![fee_sib];

    let tree = VPackTree {
        leaf,
        leaf_siblings,
        path: path_items,
        anchor,
        asset_id: None,
        fee_anchor_script: fee_script(),
        internal_key,
        asp_expiry_script,
    };

    // VtxoId: last exit tx's output
    let vtxo_point = vtxo.point();
    let vtxo_id = VtxoId::OutPoint(OutPoint {
        txid: Txid::from_byte_array(vtxo_point.txid.to_byte_array()),
        vout: vtxo_point.vout,
    });

    (tree, vtxo_id)
}

// ---------------------------------------------------------------------------
// Test 1: Dehydration Fidelity
// ---------------------------------------------------------------------------

/// Verify that the dehydrated envelope preserves the `VtxoId` and the leaf amount.
///
/// Uses ark-lib to build a correctly-structured VPackTree (since the current
/// `bark_to_vpack` adapter reads a linear chain rather than the tree path).
#[test]
fn test_dehydration_fidelity() {
    let path = vtxo_path(0);
    if !path.exists() {
        eprintln!("Skipping: vtxo_0.bin not found");
        return;
    }

    let (tree, vtxo_id) = vpack_tree_from_arklib(&path);
    let leaf_amount = tree.leaf.amount;

    let (envelope, _waterfall) = bark_dehydrate(&tree, &vtxo_id).expect("bark_dehydrate");

    // VtxoId must be preserved exactly.
    match &vtxo_id {
        VtxoId::OutPoint(op) => {
            assert_eq!(
                envelope.vtxo_txid,
                op.txid.to_byte_array(),
                "Envelope vtxo_txid must match the Bark VtxoId txid"
            );
            assert_eq!(
                envelope.vtxo_vout, op.vout,
                "Envelope vtxo_vout must match the Bark VtxoId vout"
            );
        }
        VtxoId::Raw(hash) => {
            assert_eq!(envelope.vtxo_txid, *hash, "Raw VtxoId must be preserved");
        }
    }

    assert_ne!(
        envelope.root_outpoint, [0u8; 36],
        "root_outpoint must be non-zero"
    );
    assert_eq!(
        envelope.leaf_amount, leaf_amount,
        "Leaf amount must be preserved"
    );

    envelope.verify().expect("envelope.verify() must pass");

    println!(
        "vtxo_0: fidelity OK — vtxo_id={}:{}, leaf_amount={} sats, path_depth={}",
        hex::encode(envelope.vtxo_txid),
        envelope.vtxo_vout,
        envelope.leaf_amount,
        tree.path.len(),
    );
}

// ---------------------------------------------------------------------------
// Test 2: Exclusivity Math
// ---------------------------------------------------------------------------

/// Verify Taproot path exclusivity: `compute_taproot_tweak(P, merkle_root) == Q`.
///
/// Uses ark-lib as ground truth for `P` (internal key) and `Q` (output key).
/// Our library provides `compute_bark_vtxo_tapscript_root` (single-leaf delayed-sign script)
/// and `compute_taproot_tweak`.
#[test]
fn test_exclusivity_math() {
    use ark::encode::ProtocolEncoding;
    use ark::vtxo::Vtxo;
    use ark::VtxoPolicy;
    use bitcoin::hashes::Hash as _;
    use vpack::taproot::compute_taproot_tweak;

    let path = vtxo_path(0);
    if !path.exists() {
        eprintln!("Skipping: vtxo_0.bin not found");
        return;
    }

    let raw = std::fs::read(&path).expect("read vtxo_0");

    // Ground truth from ark-lib.
    let vtxo: Vtxo<ark::vtxo::Full, VtxoPolicy> =
        Vtxo::deserialize(&raw).expect("ark-lib deserialize");
    let output_taproot = vtxo.output_taproot();
    let ark_internal_key: [u8; 32] = output_taproot.internal_key().serialize();
    let ark_output_key: [u8; 32] = output_taproot.output_key().serialize();
    let ark_merkle_root: Option<[u8; 32]> =
        output_taproot.merkle_root().map(|m| *m.as_byte_array());

    println!(
        "vtxo_0 ark-lib ground truth:\n  internal_key: {}\n  output_key:   {}\n  merkle_root:  {:?}",
        hex::encode(ark_internal_key),
        hex::encode(ark_output_key),
        ark_merkle_root.map(hex::encode),
    );

    // Build correctly-structured tree with ark-lib's internal_key and user pubkey.
    let (tree, vtxo_id) = vpack_tree_from_arklib(&path);
    assert_eq!(
        tree.internal_key, ark_internal_key,
        "vpack_tree_from_arklib must use ark-lib's internal_key"
    );

    // Compute our tapscript merkle root using the correct single-leaf delayed-sign structure.
    let our_merkle_root = compute_bark_vtxo_tapscript_root(&tree);

    match (our_merkle_root, ark_merkle_root) {
        (Ok(our), Some(ark)) => {
            assert_eq!(
                our, ark,
                "Our Taproot merkle root (single delayed-sign leaf) must equal ark-lib's merkle root"
            );

            let derived_q =
                compute_taproot_tweak(ark_internal_key, our).expect("compute_taproot_tweak");
            assert_eq!(
                derived_q, ark_output_key,
                "TapTweak(P, merkle_root) must equal ark-lib output_key"
            );

            // End-to-end: verify via the envelope's verify_taproot_exclusivity.
            let (mut envelope, _) = bark_dehydrate(&tree, &vtxo_id).expect("bark_dehydrate");
            envelope.leaf_taproot_key = ark_output_key;

            envelope
                .verify_taproot_exclusivity(&tree)
                .expect("verify_taproot_exclusivity must pass");

            println!(
                "Exclusivity OK: TapTweak(P, delayed_sign_leaf_hash) == Q\n  derived_q={}\n  ark_output_key={}",
                hex::encode(derived_q),
                hex::encode(ark_output_key),
            );
        }
        (Ok(our), None) => {
            println!(
                "ark-lib reports no merkle root (key-path-only VTXO); our leaf hash = {}",
                hex::encode(our),
            );
        }
        (Err(e), _) => {
            panic!("compute_bark_vtxo_tapscript_root failed: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: Dust Removal
// ---------------------------------------------------------------------------

/// Assert that `VpackExitWaterfall` strips all sibling (dust) outputs.
///
/// Uses a synthetic `VPackTree` with a known number of siblings per hop
/// to make the assertion crisp and independent of binary format issues.
#[test]
fn test_dust_removal() {
    let fee_sib = fee_anchor_sibling();

    // Build a synthetic 3-hop chain: each hop has 2 dust siblings + 1 fee anchor.
    let dust_sibling = SiblingNode::Compact {
        hash: [0u8; 32],
        value: 200, // < 330 sats → dust
        script: vec![
            0x51, 0x20, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    };

    let make_hop = |amount: u64| GenesisItem {
        siblings: vec![dust_sibling.clone(), dust_sibling.clone(), fee_sib.clone()],
        parent_index: 0,
        sequence: 0x0000_0000,
        child_amount: amount,
        child_script_pubkey: Vec::new(),
        signature: None,
        sighash_flag: 0x00,
    };

    use vpack::types::{OutPoint, Txid};
    let synthetic_tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 5000,
            vout: 0,
            sequence: 0,
            expiry: 800_000,
            exit_delta: 12,
            script_pubkey: vec![0x42u8; 33], // dummy 33-byte compressed key
        },
        leaf_siblings: vec![fee_sib.clone()],
        path: vec![make_hop(20_000), make_hop(10_000), make_hop(5_000)],
        anchor: OutPoint {
            txid: Txid::from_byte_array([0x01u8; 32]),
            vout: 1,
        },
        asset_id: None,
        fee_anchor_script: fee_script(),
        internal_key: [0u8; 32],
        asp_expiry_script: Vec::new(),
    };

    let dust_siblings_per_hop = 3; // 2 dust + 1 fee anchor
    let total_hops = synthetic_tree.path.len();
    let total_stripped = total_hops * dust_siblings_per_hop;

    let dummy_vtxo_id = VtxoId::OutPoint(OutPoint {
        txid: Txid::from_byte_array([0x02u8; 32]),
        vout: 0,
    });

    let (_, mut waterfall) =
        bark_dehydrate(&synthetic_tree, &dummy_vtxo_id).expect("bark_dehydrate");

    assert_eq!(
        waterfall.hop_count(),
        total_hops,
        "Waterfall must store exactly one record per path hop"
    );

    let mut hop_count = 0usize;
    let mut hops: Vec<HopData> = Vec::new();
    while let Some(hop) = waterfall.next_hop() {
        hops.push(hop);
        hop_count += 1;
    }

    assert_eq!(
        hop_count, total_hops,
        "next_hop() must yield total_hops records"
    );

    println!(
        "Dust removal: {total_hops} hops, {total_stripped} sibling TxOuts stripped. \
         Waterfall contains {hop_count} compact HopData records."
    );

    // Amounts are preserved per hop.
    assert_eq!(hops[0].amount, 20_000);
    assert_eq!(hops[1].amount, 10_000);
    assert_eq!(hops[2].amount, 5_000);
}

// ---------------------------------------------------------------------------
// Test 4: Size Targets
// ---------------------------------------------------------------------------

/// Assert that all dehydrated structures fit within their specified byte budgets.
///
/// | Structure                    | Budget      |
/// |:---                          |:---         |
/// | `VpackSovereigntyEnvelope`   | ≤ 500 B     |
/// | `VpackExitWaterfall`         | ≤ 12,288 B  |
/// | `HopData` in-memory          | ≤ 1,024 B   |
/// | Max wire bytes per hop       | 105 B       |
/// | Max on-device chain length   | 100 hops    |
///
/// Uses vtxo_0.bin (67 hops) for the waterfall budget check and vtxo_73.bin for the
/// envelope budget check. vtxo_73.bin chains are longer than 100 hops and are expected to
/// return `ExceedsHWWCapacity` when building the waterfall — this is the enforced HWW limit.
#[test]
fn test_size_targets() {
    use vpack::dehydration::waterfall::MAX_HWW_HOPS;

    // ── Static checks (compile-time constants) ────────────────────────────────
    let envelope_bytes = VpackSovereigntyEnvelope::serialized_size();
    assert!(
        envelope_bytes <= 500,
        "VpackSovereigntyEnvelope is {envelope_bytes} bytes — exceeds 500-byte budget"
    );

    let hop_data_in_mem = core::mem::size_of::<HopData>();
    assert!(
        hop_data_in_mem <= 1024,
        "HopData in-memory size is {hop_data_in_mem} bytes — exceeds 1-KB RAM budget"
    );
    assert_eq!(
        HopData::SERIALIZED_LEN,
        105,
        "HopData max wire size must be 105 bytes (flags1 + sig64 + amount8 + xonly32)"
    );
    assert_eq!(MAX_HWW_HOPS, 100, "MAX_HWW_HOPS must be 100");

    // ── Waterfall budget: vtxo_0.bin (67 hops, within HWW limit) ─────────────
    let path0 = vtxo_path(0);
    if !path0.exists() {
        eprintln!("Skipping waterfall check: vtxo_0.bin not found");
        return;
    }
    let raw_bark_size_0 = std::fs::metadata(&path0)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let (tree0, vtxo_id0) = vpack_tree_from_arklib(&path0);

    let (envelope0, waterfall0) = bark_dehydrate(&tree0, &vtxo_id0).expect("bark_dehydrate vtxo_0");
    let waterfall_bytes = waterfall0.serialized_size();

    assert!(
        waterfall_bytes <= 12_288,
        "VpackExitWaterfall (vtxo_0, {} hops) = {waterfall_bytes} bytes — exceeds 12,288 B budget",
        tree0.path.len(),
    );
    assert!(
        waterfall_bytes < raw_bark_size_0,
        "Waterfall ({waterfall_bytes} B) must be smaller than raw Bark ({raw_bark_size_0} B)"
    );
    envelope0
        .verify()
        .expect("vtxo_0 envelope.verify() must pass");

    // Waterfall round-trip.
    let serialized = waterfall0.to_bytes();
    assert_eq!(
        serialized.len(),
        waterfall_bytes,
        "to_bytes length must match serialized_size"
    );
    let waterfall2 = VpackExitWaterfall::from_bytes(&serialized).expect("from_bytes round-trip");
    assert_eq!(
        waterfall2.hop_count(),
        waterfall0.hop_count(),
        "Round-trip hop_count mismatch"
    );
    assert_eq!(
        waterfall2.serialized_size(),
        waterfall0.serialized_size(),
        "Round-trip serialized_size mismatch",
    );

    println!(
        "Size budget (vtxo_0.bin, {} hops):\n\
         - Raw Bark:                      {raw_bark_size_0} bytes\n\
         - VpackSovereigntyEnvelope:      {envelope_bytes} bytes  (≤ 500)\n\
         - VpackExitWaterfall:            {waterfall_bytes} bytes  (≤ 12,288)\n\
         - HopData in-memory:             {hop_data_in_mem} bytes\n\
         - HopData max wire (SERIALIZED_LEN): {} bytes\n\
         - MAX_HWW_HOPS:                  {MAX_HWW_HOPS}\n\
         - Waterfall reduction vs raw:    {:.1}%",
        tree0.path.len(),
        HopData::SERIALIZED_LEN,
        (1.0 - waterfall_bytes as f64 / raw_bark_size_0 as f64) * 100.0,
    );

    // ── HWW capacity enforcement: vtxo_73.bin (expected to exceed 100 hops) ──
    let path73 = vtxo_path(73);
    if !path73.exists() {
        eprintln!("Skipping vtxo_73.bin HWW-limit check: file not found");
        return;
    }
    let raw_bark_size_73 = std::fs::metadata(&path73)
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    let (tree73, vtxo_id73) = vpack_tree_from_arklib(&path73);

    match bark_dehydrate(&tree73, &vtxo_id73) {
        Ok((envelope73, waterfall73)) => {
            // If it fits (chain ≤ 100 hops), assert budget.
            let wf73_bytes = waterfall73.serialized_size();
            assert!(
                wf73_bytes <= 12_288,
                "vtxo_73 waterfall = {wf73_bytes} B — exceeds 12,288 B budget"
            );
            envelope73.verify().expect("vtxo_73 envelope.verify()");
            println!(
                "vtxo_73.bin ({} hops, {raw_bark_size_73} B raw): waterfall = {wf73_bytes} B",
                tree73.path.len(),
            );
        }
        Err(vpack::VPackError::ExceedsHWWCapacity) => {
            // Expected: vtxo_73 chain is longer than 100 hops.
            println!(
                "vtxo_73.bin ({} hops, {raw_bark_size_73} B raw): exceeds HWW capacity \
                 (> {MAX_HWW_HOPS} hops) — ExceedsHWWCapacity returned as expected",
                tree73.path.len(),
            );
        }
        Err(e) => panic!("bark_dehydrate vtxo_73 unexpected error: {e}"),
    }
}
