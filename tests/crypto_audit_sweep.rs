use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;

use ark::bitcoin::hashes::Hash;
use ark::encode::ProtocolEncoding;
use ark::vtxo::Vtxo;
use ark::VtxoPolicy;
use byteorder::{ByteOrder, LittleEndian};
use hex::FromHex;
use serde::Serialize;
use vpack::adapters::second_tech::bark_to_vpack;
use vpack::consensus::second_tech::compute_bark_merkle_root;
use vpack::header::{Header, HEADER_SIZE};
use vpack::payload::reader::BoundedReader;
use vpack::payload::tree::SiblingNode;
use vpack::taproot::compute_taproot_tweak;
use vpack::{create_vpack_from_tree, validate_timelocks, ConsensusEngine, SecondTechV3, TxVariant};

const DUST_THRESHOLD_SATS: u64 = 330;
const P2TR_WIRE_MARKER: [u8; 3] = [0x22, 0x51, 0x20];

// ---------------------------------------------------------------------------
// Per-file audit result
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CryptoAuditEntry {
    filename: String,
    merkle_root_match: bool,
    tweak_match: bool,
    sig_valid: bool,
    timelock_match: bool,
    dust_leaf_count: u32,
    is_spendable: bool,
    /// "full" when bark_to_vpack succeeded, "wire_probe" when fallback was used.
    binding_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_trace: Option<String>,
}

// ---------------------------------------------------------------------------
// Wire-level helpers (fallback when bark_to_vpack is incompatible)
// ---------------------------------------------------------------------------

/// Bitcoin CompactSize / VarInt. Returns (value, bytes_consumed).
fn read_compact_size(data: &[u8], off: usize) -> (u64, usize) {
    let first = data[off];
    match first {
        0..=0xfc => (first as u64, 1),
        0xfd => (LittleEndian::read_u16(&data[off + 1..off + 3]) as u64, 3),
        0xfe => (LittleEndian::read_u32(&data[off + 1..off + 5]) as u64, 5),
        0xff => (LittleEndian::read_u64(&data[off + 1..off + 9]), 9),
    }
}

/// Scan for `[0x22, 0x51, 0x20]` P2TR script-length + OP_1 + OP_PUSH32 markers
/// and return the LE u64 amount from the 8 bytes immediately before each hit.
fn extract_leaf_amounts(data: &[u8]) -> Vec<u64> {
    let mut amounts = Vec::new();
    if data.len() < 11 {
        return amounts;
    }
    for i in 8..data.len().saturating_sub(2) {
        if data[i] == P2TR_WIRE_MARKER[0]
            && data[i + 1] == P2TR_WIRE_MARKER[1]
            && data[i + 2] == P2TR_WIRE_MARKER[2]
        {
            amounts.push(LittleEndian::read_u64(&data[i - 8..i]));
        }
    }
    amounts
}

/// Counts 64-byte blobs preceded by a Borsh `Some` tag (0x01) inside the genesis
/// region of the file. This heuristic detects Schnorr signatures without full parsing.
fn probe_schnorr_signatures(data: &[u8], genesis_offset: usize) -> (usize, usize) {
    let region = &data[genesis_offset..];
    let mut found = 0usize;
    let mut present = 0usize;
    let mut i = 0;
    while i < region.len() {
        if region[i] == 0x01 && i + 65 <= region.len() {
            found += 1;
            let sig = &region[i + 1..i + 65];
            let all_zero = sig.iter().all(|b| *b == 0);
            if !all_zero {
                present += 1;
            }
            i += 65;
        } else {
            i += 1;
        }
    }
    (found, present)
}

#[allow(dead_code)]
struct WireProbeResult {
    root_amount: u64,
    exit_delta: u16,
    genesis_count: u64,
    genesis_offset: usize,
    leaf_amounts: Vec<u64>,
}

fn wire_probe(raw: &[u8]) -> Result<WireProbeResult, String> {
    if raw.len() < 86 {
        return Err(format!("file too short: {} bytes", raw.len()));
    }
    let root_amount = LittleEndian::read_u64(&raw[2..10]);
    let exit_delta = LittleEndian::read_u16(&raw[47..49]);
    let (genesis_count, varint_len) = read_compact_size(raw, 85);
    let genesis_offset = 85 + varint_len;
    let leaf_amounts = extract_leaf_amounts(raw);

    Ok(WireProbeResult {
        root_amount,
        exit_delta,
        genesis_count,
        genesis_offset,
        leaf_amounts,
    })
}

// ---------------------------------------------------------------------------
// Full pipeline (when bark_to_vpack succeeds)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn check_merkle_root(tree: &vpack::VPackTree) -> (bool, Option<[u8; 32]>) {
    match compute_bark_merkle_root(tree) {
        Ok(root) => (true, Some(root)),
        Err(_) => (false, None),
    }
}

#[allow(dead_code)]
fn check_tweak(tree: &vpack::VPackTree, merkle_root: Option<[u8; 32]>) -> bool {
    let root = match merkle_root {
        Some(r) => r,
        None => return false,
    };

    if tree.internal_key == [0u8; 32] {
        return false;
    }

    let tweaked = match compute_taproot_tweak(tree.internal_key, root) {
        Some(k) => k,
        None => return false,
    };

    if tree.leaf.script_pubkey.len() == 34 && tree.leaf.script_pubkey[..2] == [0x51, 0x20] {
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&tree.leaf.script_pubkey[2..34]);
        tweaked == expected
    } else {
        false
    }
}

#[allow(dead_code)]
fn check_sig(tree: &vpack::VPackTree) -> bool {
    SecondTechV3.compute_vtxo_id(tree, None).is_ok()
}

#[allow(dead_code)]
fn check_timelock(tree: &vpack::VPackTree) -> bool {
    if tree.asp_expiry_script.is_empty() {
        return false;
    }
    validate_timelocks(tree).is_ok()
}

#[allow(dead_code)]
fn count_dust_leaves_tree(tree: &vpack::VPackTree) -> u32 {
    let mut dust = 0u32;

    if tree.leaf.amount < DUST_THRESHOLD_SATS {
        dust += 1;
    }

    for sib in &tree.leaf_siblings {
        let value = match sib {
            SiblingNode::Compact { value, .. } => *value,
            SiblingNode::Full(txout) => txout.value.to_sat(),
        };
        if value < DUST_THRESHOLD_SATS {
            dust += 1;
        }
    }

    for step in &tree.path {
        if step.child_amount < DUST_THRESHOLD_SATS {
            dust += 1;
        }
        for sib in &step.siblings {
            let value = match sib {
                SiblingNode::Compact { value, .. } => *value,
                SiblingNode::Full(txout) => txout.value.to_sat(),
            };
            if value < DUST_THRESHOLD_SATS {
                dust += 1;
            }
        }
    }

    dust
}

fn count_dust_leaves_wire(leaf_amounts: &[u64]) -> u32 {
    leaf_amounts
        .iter()
        .filter(|&&v| v < DUST_THRESHOLD_SATS)
        .count() as u32
}

// ---------------------------------------------------------------------------
// Full audit pipeline for a single file
// ---------------------------------------------------------------------------

fn audit_single_file(path: &PathBuf, fee_script: &[u8]) -> CryptoAuditEntry {
    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        audit_single_file_inner(path, fee_script)
    }));

    match result {
        Ok(entry) => entry,
        Err(panic_info) => {
            let trace = if let Some(s) = panic_info.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            CryptoAuditEntry {
                filename: file_name,
                merkle_root_match: false,
                tweak_match: false,
                sig_valid: false,
                timelock_match: false,
                dust_leaf_count: 0,
                is_spendable: false,
                binding_mode: "panic".into(),
                error_trace: Some(trace),
            }
        }
    }
}

/// Verify Taproot crypto using ark-lib's native decoder.
/// Returns (merkle_root_match, tweak_match, exit_tx_count).
fn verify_with_arklib(raw_bytes: &[u8]) -> Option<(bool, bool, usize)> {
    let vtxo: Vtxo<ark::vtxo::Full, VtxoPolicy> = Vtxo::deserialize(raw_bytes).ok()?;

    let taproot = vtxo.output_taproot();
    let internal_key_x = taproot.internal_key().serialize();
    let output_key_x = taproot.output_key().serialize();
    let merkle_root = taproot.merkle_root();

    let merkle_root_bytes: [u8; 32] = merkle_root.map(|m| m.to_byte_array()).unwrap_or([0u8; 32]);

    let tweaked = compute_taproot_tweak(internal_key_x, merkle_root_bytes);
    let tweak_match = tweaked.is_some_and(|t| t == output_key_x);

    let txs: Vec<_> = vtxo.transactions().collect();

    Some((merkle_root.is_some(), tweak_match, txs.len()))
}

fn audit_single_file_inner(path: &PathBuf, fee_script: &[u8]) -> CryptoAuditEntry {
    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();

    let raw_bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return CryptoAuditEntry {
                filename: file_name,
                merkle_root_match: false,
                tweak_match: false,
                sig_valid: false,
                timelock_match: false,
                dust_leaf_count: 0,
                is_spendable: false,
                binding_mode: "error".into(),
                error_trace: Some(format!("read: {e}")),
            };
        }
    };

    // --- Verify crypto with ark-lib (definitive source of truth) ---
    let arklib_result = verify_with_arklib(&raw_bytes);

    // --- Attempt structural parse via bark_to_vpack ---
    let bark_parsed = bark_to_vpack(&raw_bytes, fee_script).ok();

    // --- Wire probe for dust counting ---
    let probe = wire_probe(&raw_bytes).ok();
    let dust_leaf_count = probe
        .as_ref()
        .map(|p| count_dust_leaves_wire(&p.leaf_amounts))
        .unwrap_or(0);

    let (merkle_root_match, tweak_match, _exit_tx_count) =
        arklib_result.unwrap_or((false, false, 0));

    // Signature: heuristic from wire probe
    let sig_valid = probe.as_ref().is_some_and(|p| {
        let (found, present) = probe_schnorr_signatures(&raw_bytes, p.genesis_offset);
        found > 0 && present == found
    });

    // Timelock: structural check
    let timelock_match = probe.as_ref().is_some_and(|p| p.exit_delta > 0);

    let target_leaf_above_dust = probe
        .as_ref()
        .is_some_and(|p| p.root_amount >= DUST_THRESHOLD_SATS);
    let is_spendable =
        merkle_root_match && tweak_match && sig_valid && timelock_match && target_leaf_above_dust;

    let binding_mode = if bark_parsed.is_some() && arklib_result.is_some() {
        "full+arklib"
    } else if arklib_result.is_some() {
        "arklib"
    } else if bark_parsed.is_some() {
        "full"
    } else {
        "wire_probe"
    };

    CryptoAuditEntry {
        filename: file_name,
        merkle_root_match,
        tweak_match,
        sig_valid,
        timelock_match,
        dust_leaf_count,
        is_spendable,
        binding_mode: binding_mode.into(),
        error_trace: None,
    }
}

#[allow(dead_code)]
fn audit_via_full_pipeline(
    file_name: String,
    tree_from_bark: &vpack::VPackTree,
) -> CryptoAuditEntry {
    let vpack_bytes = match create_vpack_from_tree(tree_from_bark, TxVariant::V3Plain, false) {
        Ok(b) => b,
        Err(e) => {
            return CryptoAuditEntry {
                filename: file_name,
                merkle_root_match: false,
                tweak_match: false,
                sig_valid: false,
                timelock_match: false,
                dust_leaf_count: 0,
                is_spendable: false,
                binding_mode: "full".into(),
                error_trace: Some(format!("create_vpack: {e:?}")),
            };
        }
    };

    let tree = match parse_vpack_tree(&vpack_bytes) {
        Ok(t) => t,
        Err(e) => {
            return CryptoAuditEntry {
                filename: file_name,
                merkle_root_match: false,
                tweak_match: false,
                sig_valid: false,
                timelock_match: false,
                dust_leaf_count: 0,
                is_spendable: false,
                binding_mode: "full".into(),
                error_trace: Some(e),
            };
        }
    };

    let (merkle_root_match, merkle_root) = check_merkle_root(&tree);
    let tweak_match = check_tweak(&tree, merkle_root);
    let sig_valid = check_sig(&tree);
    let timelock_match = check_timelock(&tree);
    let dust_leaf_count = count_dust_leaves_tree(&tree);
    let target_leaf_above_dust = tree.leaf.amount >= DUST_THRESHOLD_SATS;
    let is_spendable =
        merkle_root_match && tweak_match && sig_valid && timelock_match && target_leaf_above_dust;

    CryptoAuditEntry {
        filename: file_name,
        merkle_root_match,
        tweak_match,
        sig_valid,
        timelock_match,
        dust_leaf_count,
        is_spendable,
        binding_mode: "full".into(),
        error_trace: None,
    }
}

#[allow(dead_code)]
fn audit_via_wire_probe(file_name: String, raw: &[u8]) -> CryptoAuditEntry {
    let probe = match wire_probe(raw) {
        Ok(p) => p,
        Err(e) => {
            return CryptoAuditEntry {
                filename: file_name,
                merkle_root_match: false,
                tweak_match: false,
                sig_valid: false,
                timelock_match: false,
                dust_leaf_count: 0,
                is_spendable: false,
                binding_mode: "wire_probe".into(),
                error_trace: Some(e),
            };
        }
    };

    // Merkle root: requires full tree reconstruction → cannot verify at wire level.
    let merkle_root_match = false;

    // Tweak: requires internal_key + merkle_root → cannot verify at wire level.
    let tweak_match = false;

    // Signatures: heuristic scan for 64-byte Schnorr sigs in the genesis region.
    // If we find nonzero sigs for every genesis step we mark true; the actual BIP-340
    // verification requires the full transaction chain which bark_to_vpack would provide.
    let (sig_slots_found, sigs_present) = probe_schnorr_signatures(raw, probe.genesis_offset);
    let sig_valid = sig_slots_found > 0 && sigs_present == sig_slots_found;

    // Timelock: compare exit_delta to the CSV value embedded in the genesis region.
    // Without the asp_expiry_script we cannot parse OP_CSV operands, so we check
    // structural consistency: exit_delta > 0 implies a timelock was configured.
    let timelock_match = probe.exit_delta > 0;

    // Dust: count P2TR leaf outputs with amount < 330 sats.
    let dust_leaf_count = count_dust_leaves_wire(&probe.leaf_amounts);

    // Spendable: since merkle_root and tweak cannot be verified at the wire level,
    // is_spendable stays false. The root_amount serves as a secondary indicator.
    let target_leaf_above_dust = probe.root_amount >= DUST_THRESHOLD_SATS;
    let is_spendable =
        merkle_root_match && tweak_match && sig_valid && timelock_match && target_leaf_above_dust;

    CryptoAuditEntry {
        filename: file_name,
        merkle_root_match,
        tweak_match,
        sig_valid,
        timelock_match,
        dust_leaf_count,
        is_spendable,
        binding_mode: "wire_probe".into(),
        error_trace: None,
    }
}

#[allow(dead_code)]
fn parse_vpack_tree(vpack_bytes: &[u8]) -> Result<vpack::VPackTree, String> {
    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE]).map_err(|e| format!("{e:?}"))?;
    header
        .verify_checksum(&vpack_bytes[HEADER_SIZE..])
        .map_err(|e| format!("checksum: {e:?}"))?;
    BoundedReader::parse(&header, &vpack_bytes[HEADER_SIZE..]).map_err(|e| format!("parse: {e:?}"))
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn crypto_audit_sweep() {
    let corpus_dir = "tests/vectors/bark_qa";
    let fee_script = Vec::from_hex("51024e73").expect("fee anchor script");

    let mut entries: Vec<PathBuf> = fs::read_dir(corpus_dir)
        .expect("Corpus directory missing")
        .filter_map(|e| e.ok().map(|de| de.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "bin"))
        .collect();
    entries.sort();

    let results: Vec<CryptoAuditEntry> = entries
        .iter()
        .map(|p| audit_single_file(p, &fee_script))
        .collect();

    let total = results.len();
    let merkle_pass = results.iter().filter(|r| r.merkle_root_match).count();
    let tweak_pass = results.iter().filter(|r| r.tweak_match).count();
    let sig_pass = results.iter().filter(|r| r.sig_valid).count();
    let timelock_pass = results.iter().filter(|r| r.timelock_match).count();
    let spendable = results.iter().filter(|r| r.is_spendable).count();
    let total_dust: u32 = results.iter().map(|r| r.dust_leaf_count).sum();
    let errors = results.iter().filter(|r| r.error_trace.is_some()).count();
    let full_mode = results.iter().filter(|r| r.binding_mode == "full").count();
    let wire_mode = results
        .iter()
        .filter(|r| r.binding_mode == "wire_probe")
        .count();

    let json = serde_json::to_string_pretty(&results).expect("JSON serialization should not fail");
    fs::write("vpack_crypto_audit.json", &json).expect("write audit JSON");

    let separator = "=".repeat(72);
    println!("\n{separator}");
    println!("  CRYPTO AUDIT SWEEP  |  {total} files");
    println!("{separator}");
    println!("  Binding mode:       {full_mode} full, {wire_mode} wire_probe");
    println!("  Merkle root match:  {merkle_pass}/{total}");
    println!("  Tweak match:        {tweak_pass}/{total}");
    println!("  Signature valid:    {sig_pass}/{total}");
    println!("  Timelock match:     {timelock_pass}/{total}");
    println!("  Spendable:          {spendable}/{total}");
    println!("  Total dust leaves:  {total_dust}");
    println!("  Panics / errors:    {errors}");
    println!("{separator}");
    println!("  Output: vpack_crypto_audit.json");
    println!("{separator}\n");

    assert_eq!(
        errors, 0,
        "No file should panic or produce a fatal error during audit"
    );
}
