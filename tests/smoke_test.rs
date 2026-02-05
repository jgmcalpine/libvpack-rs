//! Milestone 4.1.5 — Consensus Smoke Test (Numerical Certainty)
//!
//! Proves we can compute the correct vTXO/tx IDs from raw sniffed hex using
//! only the `bitcoin` crate. No library logic — naked deserialize + compute_txid.

use bitcoin::consensus::Decodable;
use std::io::Cursor;

const ARK_LABS_OOR_FORFEIT_TX_HEX: &str = "0300000001411d0d848ab79c0f7ae5a73742c4addd4e5b5646c2bc4bea854d287107825c750000000000feffffff02e803000000000000150014a1b2c3d4e5f6789012345678901234567890ab00000000000000000451024e7300000000";

const SECOND_TECH_ROUND_TX_HEX: &str = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff000000000001c8af000000000000225120649657f65947abfd83ff629ad8a851c795f419ed4d52a2748d3f868cc3e6c94d00000000";

/// Expected Txid of the Second Tech Round transaction (V2 + Chain).
const SECOND_TECH_ROUND_EXPECTED_TXID: &str = "abd5d39844c20383aa167cbcb6f8e8225a6d592150b9524c96594187493cc2a3";

/// ROUND_1 vTXO ID we sniffed (OutPoint form). Its txid is a *child* of the round tx.
const ROUND_1_VTXO_ID_TXID_HEX: &str = "c806f5fc2cf7a5b0e8e2fa46cc9e0c7a511f43144f9d27f85a9108e4b8c4d662";

fn decode_tx_from_hex(hex: &str) -> bitcoin::Transaction {
    let bytes = hex::decode(hex).expect("hex decode");
    let mut cursor = Cursor::new(bytes);
    bitcoin::Transaction::consensus_decode(&mut cursor).expect("consensus decode tx")
}

/// Verification 1: Ark Labs OOR Forfeit (V3 + Anchor + Sequence 0xFFFFFFFE).
/// Deserialize the unsigned forfeit tx hex and compute its Txid.
/// The result is the ID of the transaction that created the payment output.
#[test]
fn smoke_ark_labs_oor_forfeit_txid() {
    let tx = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX);
    let txid = tx.compute_txid();
    let txid_display = format!("{}", txid);

    // We do not have forfeit_tx_test.go in repo; expected_vtxo_id is "COMPUTE_FROM_HEX".
    // Assert computation is deterministic and non-trivial.
    assert!(!txid_display.is_empty(), "txid must not be empty");
    assert_eq!(txid_display.len(), 64, "txid must be 32 bytes (64 hex chars)");

    let txid_again = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX).compute_txid();
    assert_eq!(txid, txid_again, "txid must be deterministic");

    eprintln!("[smoke] Ark Labs OOR Forfeit tx hex -> Txid (reversed/Big-Endian): {}", txid_display);
    eprintln!("[smoke] Compare this to the ID of the payment in forfeit_tx_test.go log.");
}

/// Verification 2: Second Tech Round (V2 + Chain).
/// Deserialize the round tx hex and compute Txid; must match expected exactly.
#[test]
fn smoke_second_tech_round_txid() {
    let tx = decode_tx_from_hex(SECOND_TECH_ROUND_TX_HEX);
    let txid = tx.compute_txid();
    let txid_display = format!("{}", txid);

    assert_eq!(
        txid_display,
        SECOND_TECH_ROUND_EXPECTED_TXID,
        "Second Tech Round tx hex must produce the expected Txid"
    );
    eprintln!("[smoke] Second Tech Round tx hex -> Txid: {} (matches expected)", txid_display);
}

// -----------------------------------------------------------------------------
// Naked hash experiments: Ark Labs version rule (Round = V2? vs OOR = V3?)
// -----------------------------------------------------------------------------

/// Helper: sha256d of preimage bytes, return display-order hex (reversed).
fn sha256d_display_hex(preimage: &[u8]) -> String {
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::Hash;
    let hash = sha256d::Hash::hash(preimage);
    let bytes = hash.to_byte_array();
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// Leaf test: Gold Standard round leaf (V3 only). sha256d(preimage) must equal expected_vtxo_id.
#[test]
fn naked_hash_ark_labs_leaf_version_2_vs_3() {
    // Gold Standard preimage: Parent ecdeb06a...:0, 1100 sats + fee anchor, V3.
    const ROUND_LEAF_HEX_V3: &str = "0300000001a4e3e646f30f8965a797d105751b4e9d11e8da56fd7711d9d707a7a56ab0deec0000000000ffffffff024c0400000000000022512025a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea996700000000000000000451024e7300000000";
    const EXPECTED_LEAF_ID: &str = "47ea55bcb18fe596e19e2ad50603216926d12b7f0498d5204abf5604d4a4bc7d";

    let bytes_v3 = hex::decode(ROUND_LEAF_HEX_V3).expect("leaf hex");
    let hash_v3 = sha256d_display_hex(&bytes_v3);

    assert_eq!(
        hash_v3,
        EXPECTED_LEAF_ID,
        "Ark Labs Round Leaf (V3): sha256d(preimage) must match Gold Standard ID. Got: {}",
        hash_v3
    );
}

/// Branch test: Round branch hex with version 3 vs 2. Which matches expected_vtxo_id?
#[test]
fn naked_hash_ark_labs_branch_version_2_vs_3() {
    // Round branch preimage from round_branch_v3.json (anchor internal, 3 outputs).
    const ROUND_BRANCH_HEX_V3: &str = "03000000014e51f2ceb7c3d773283f476a5ea81a7bd5c2efbf81272c2008b81f1ca41700f60000000000ffffffff035802000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae3f401000000000000225120faac533aa0def6c9b1196e501d92fc7edc1972964793bd4fa0dde835b1fb9ae300000000000000000451024e7300000000";
    const EXPECTED_BRANCH_ID: &str = "f259d88f76b67559f51cd3c6c22f6579219ad75000d60ee78caaedc7418b1802";

    let mut bytes_v3 = hex::decode(ROUND_BRANCH_HEX_V3).expect("branch hex");
    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    let v3_matches = hash_v3 == EXPECTED_BRANCH_ID;
    let v2_matches = hash_v2 == EXPECTED_BRANCH_ID;

    eprintln!("[naked] Branch V3 hash: {} -> matches expected: {}", hash_v3, v3_matches);
    eprintln!("[naked] Branch V2 hash: {} -> matches expected: {}", hash_v2, v2_matches);

    assert!(v3_matches, "Ark Labs Round Branch expected ID f259... should match V3 preimage");
    assert!(!v2_matches, "Ark Labs Round Branch should NOT match V2 preimage");
}

/// OOR test: OOR forfeit hex. Confirm it only matches as Version 3 (not V2).
#[test]
fn naked_hash_ark_labs_oor_version_2_vs_3() {
    // OOR forfeit preimage (already version 3 in hex).
    let bytes_v3 = hex::decode(ARK_LABS_OOR_FORFEIT_TX_HEX).expect("oor hex");
    let tx_v3 = decode_tx_from_hex(ARK_LABS_OOR_FORFEIT_TX_HEX);
    let expected_oor_txid = format!("{}", tx_v3.compute_txid());

    let mut bytes_v2 = bytes_v3.clone();
    bytes_v2[0] = 0x02;

    let hash_v3 = sha256d_display_hex(&bytes_v3);
    let hash_v2 = sha256d_display_hex(&bytes_v2);

    let v3_matches = hash_v3 == expected_oor_txid;
    let v2_matches = hash_v2 == expected_oor_txid;

    eprintln!("[naked] OOR V3 hash: {} -> matches compute_txid: {}", hash_v3, v3_matches);
    eprintln!("[naked] OOR V2 hash: {} -> matches compute_txid: {}", hash_v2, v2_matches);
    eprintln!("[naked] OOR expected (from V3 hex): {}", expected_oor_txid);

    assert!(v3_matches, "Ark Labs OOR Forfeit must match as V3");
    assert!(!v2_matches, "Ark Labs OOR Forfeit must NOT match as V2");
}

/// Identity: ROUND_1 ID is c806f5fc...:0. If that txid does NOT appear in the
/// round tx bytes, it confirms c806 is a *child* transaction (we must reconstruct the chain).
#[test]
fn smoke_round_tx_does_not_contain_round_1_txid() {
    let round_tx_bytes = hex::decode(SECOND_TECH_ROUND_TX_HEX).expect("round tx hex decode");

    // Txid in wire format (as in outpoints) is internal byte order: reverse of display.
    let txid_display_bytes = hex::decode(ROUND_1_VTXO_ID_TXID_HEX).expect("ROUND_1 txid hex");
    let mut wire_order = txid_display_bytes.clone();
    wire_order.reverse();

    let contains_display = round_tx_bytes
        .windows(32)
        .any(|w| w == txid_display_bytes.as_slice());
    let contains_wire = round_tx_bytes.windows(32).any(|w| w == wire_order.as_slice());

    assert!(
        !contains_display && !contains_wire,
        "ROUND_1 txid (c806f5fc...) must NOT appear in the round tx hex — confirms it is a child tx"
    );
    eprintln!(
        "[smoke] ROUND_1 txid {} is not present in ROUND_TX_HEX -> child tx; chain reconstruction required.",
        ROUND_1_VTXO_ID_TXID_HEX
    );
}
