//! Relative and absolute timelock checks against `asp_expiry_script`.
//!
//! Ensures tree-encoded `nSequence` (CSV) and leaf `expiry` / absolute locktime (CLTV) meet
//! the strictest script-committed thresholds (BIP-68, BIP-112, BIP-113).

use crate::error::{TimelockViolationReason, VPackError};
use crate::payload::tree::VPackTree;

use super::second_tech::decode_script_num;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_CLTV: u8 = 0xb1;
const OP_CSV: u8 = 0xb2;

/// BIP-113 threshold: locktimes below this are block heights; at or above are Unix timestamps.
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP-68 `SEQUENCE_LOCKTIME_DISABLE_FLAG` — when set, relative locktime is not enforced.
const SEQUENCE_DISABLE_BIT: u32 = 1 << 31;

/// BIP-68 `SEQUENCE_LOCKTIME_TYPE_FLAG` — `0` = blocks, `1` = 512-second units.
const SEQUENCE_TYPE_BIT: u32 = 1 << 22;

/// BIP-68 consensus applies relative magnitude only in the lower 16 bits.
const SEQUENCE_MAG_MASK: u32 = 0x0000_FFFF;

/// Strictest CSV / CLTV operands seen while scanning a script (max per category).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequiredTimelocks {
    /// CSV operands with `value < 500_000_000` and BIP-68 type bit clear (block granularity).
    pub max_csv_blocks: Option<u32>,
    /// CSV operands with `value < 500_000_000` and BIP-68 type bit set (512-second granularity).
    pub max_csv_seconds: Option<u32>,
    /// CLTV operands below [`LOCKTIME_THRESHOLD`] (block height).
    pub max_cltv_height: Option<u32>,
    /// CLTV operands at or above [`LOCKTIME_THRESHOLD`] (Mediantime-past / timestamp).
    pub max_cltv_time: Option<u32>,
}

fn merge_max(into: &mut Option<u32>, v: u32) {
    *into = Some(match *into {
        Some(x) => core::cmp::max(x, v),
        None => v,
    });
}

/// Absorbs a CSV stack operand: updates block- or seconds-class maxima (BIP-68 layout on the
/// operand). Operands `>= 500_000_000` are invalid for relative locktime in this classification.
fn absorb_csv_operand(v: u32, out: &mut RequiredTimelocks) -> Result<(), VPackError> {
    if v >= LOCKTIME_THRESHOLD {
        return Err(VPackError::EncodingError);
    }
    let mag = v & SEQUENCE_MAG_MASK;
    if (v & SEQUENCE_TYPE_BIT) == 0 {
        merge_max(&mut out.max_csv_blocks, mag);
    } else {
        merge_max(&mut out.max_csv_seconds, mag);
    }
    Ok(())
}

fn absorb_cltv_operand(v: u32, out: &mut RequiredTimelocks) {
    if v < LOCKTIME_THRESHOLD {
        merge_max(&mut out.max_cltv_height, v);
    } else {
        merge_max(&mut out.max_cltv_time, v);
    }
}

/// Scans the full script and records the **maximum** requirement per CSV/CLTV class.
fn extract_timelock_requirements(script: &[u8]) -> Result<RequiredTimelocks, VPackError> {
    let mut out = RequiredTimelocks::default();
    let mut i = 0usize;
    let mut pending: Option<u32> = None;

    while i < script.len() {
        let b = script[i];
        if b == OP_CSV {
            let v = pending.take().ok_or(VPackError::EncodingError)?;
            absorb_csv_operand(v, &mut out)?;
            i += 1;
            continue;
        }
        if b == OP_CLTV {
            let v = pending.take().ok_or(VPackError::EncodingError)?;
            absorb_cltv_operand(v, &mut out);
            i += 1;
            continue;
        }

        if let Some((next_i, maybe_num)) = decode_push_at(script, i)? {
            pending = maybe_num;
            i = next_i;
            continue;
        }

        pending = None;
        i += 1;
    }

    Ok(out)
}

/// Decodes a push at `i`, returning `(index after push, numeric value if this push is a script
/// number suitable for CSV/CLTV)` or `None` if `script[i]` does not start a push.
///
/// Large data pushes (e.g. `OP_PUSHBYTES_32` pubkeys) advance the cursor but yield `None` so
/// embedded bytes like `0xb2` are not mistaken for `OP_CHECKSEQUENCEVERIFY`.
fn decode_push_at(script: &[u8], i: usize) -> Result<Option<(usize, Option<u32>)>, VPackError> {
    let b = *script.get(i).ok_or(VPackError::EncodingError)?;

    if b == OP_0 {
        return Ok(Some((i + 1, Some(0))));
    }

    if (OP_1..=OP_16).contains(&b) {
        // `OP_1`..=`OP_16` are single-byte small-integer pushes (not `OP_PUSHBYTES_81`).
        let n = u32::from(b - OP_1) + 1;
        return Ok(Some((i + 1, Some(n))));
    }

    if (0x01..=0x4b).contains(&b) {
        let n = b as usize;
        let end = i + 1 + n;
        if end > script.len() {
            return Err(VPackError::EncodingError);
        }
        let data = &script[i + 1..end];
        let numeric = if n <= 5 {
            decode_script_num(data)
        } else {
            None
        };
        return Ok(Some((end, numeric)));
    }

    if b == OP_PUSHDATA1 {
        if i + 1 >= script.len() {
            return Err(VPackError::EncodingError);
        }
        let n = script[i + 1] as usize;
        let end = i + 2 + n;
        if end > script.len() {
            return Err(VPackError::EncodingError);
        }
        let data = &script[i + 2..end];
        let numeric = if n <= 5 {
            decode_script_num(data)
        } else {
            None
        };
        return Ok(Some((end, numeric)));
    }

    if b == OP_PUSHDATA2 {
        if i + 3 > script.len() {
            return Err(VPackError::EncodingError);
        }
        let n = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
        let end = i + 3 + n;
        if end > script.len() {
            return Err(VPackError::EncodingError);
        }
        let data = &script[i + 3..end];
        let numeric = if n <= 5 {
            decode_script_num(data)
        } else {
            None
        };
        return Ok(Some((end, numeric)));
    }

    if b == OP_PUSHDATA4 {
        if i + 5 > script.len() {
            return Err(VPackError::EncodingError);
        }
        let n = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
            as usize;
        let end = i + 5 + n;
        if end > script.len() {
            return Err(VPackError::EncodingError);
        }
        let data = &script[i + 5..end];
        let numeric = if n <= 5 {
            decode_script_num(data)
        } else {
            None
        };
        return Ok(Some((end, numeric)));
    }

    Ok(None)
}

fn validate_n_sequence_for_csv(reqs: &RequiredTimelocks, sequence: u32) -> Result<(), VPackError> {
    let needs_csv = reqs.max_csv_blocks.is_some() || reqs.max_csv_seconds.is_some();
    if !needs_csv {
        return Ok(());
    }

    // BIP-68: bit 31 set disables relative locktime; CSV cannot succeed.
    if (sequence & SEQUENCE_DISABLE_BIT) != 0 {
        return Err(VPackError::TimelockViolation {
            expected: 0,
            actual: sequence,
            is_relative: true,
            reason: TimelockViolationReason::LocktimeDisabled,
        });
    }

    let seq_mag = sequence & SEQUENCE_MAG_MASK;
    let seq_type_seconds = (sequence & SEQUENCE_TYPE_BIT) != 0;

    if let Some(exp) = reqs.max_csv_blocks {
        if seq_type_seconds {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: sequence,
                is_relative: true,
                reason: TimelockViolationReason::TypeMismatch,
            });
        }
        if seq_mag < exp {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: seq_mag,
                is_relative: true,
                reason: TimelockViolationReason::ValueTooLow,
            });
        }
    }

    if let Some(exp) = reqs.max_csv_seconds {
        if !seq_type_seconds {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: sequence,
                is_relative: true,
                reason: TimelockViolationReason::TypeMismatch,
            });
        }
        if seq_mag < exp {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: seq_mag,
                is_relative: true,
                reason: TimelockViolationReason::ValueTooLow,
            });
        }
    }

    Ok(())
}

fn validate_expiry_for_cltv(reqs: &RequiredTimelocks, expiry: u32) -> Result<(), VPackError> {
    if let Some(exp) = reqs.max_cltv_height {
        if expiry >= LOCKTIME_THRESHOLD {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: expiry,
                is_relative: false,
                reason: TimelockViolationReason::TypeMismatch,
            });
        }
        if expiry < exp {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: expiry,
                is_relative: false,
                reason: TimelockViolationReason::ValueTooLow,
            });
        }
    }

    if let Some(exp) = reqs.max_cltv_time {
        if expiry < LOCKTIME_THRESHOLD {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: expiry,
                is_relative: false,
                reason: TimelockViolationReason::TypeMismatch,
            });
        }
        if expiry < exp {
            return Err(VPackError::TimelockViolation {
                expected: exp,
                actual: expiry,
                is_relative: false,
                reason: TimelockViolationReason::ValueTooLow,
            });
        }
    }

    Ok(())
}

/// Validates that path and leaf timelock fields satisfy the strictest CSV / CLTV thresholds in
/// `tree.asp_expiry_script`.
///
/// ## BIP-68 (CSV)
///
/// When a CSV requirement exists, every checked `nSequence` must have bit **31** clear. The type
/// bit (**22**) must match the script (blocks vs 512-second units). Comparison uses only the lower
/// **16** bits of `nSequence` against the stored script magnitudes.
///
/// ## BIP-113 (CLTV)
///
/// [`VtxoLeaf::expiry`](crate::payload::tree::VtxoLeaf::expiry) is compared to `max_cltv_height` or
/// `max_cltv_time` using the same height vs timestamp split as consensus (`500_000_000`).
pub fn validate_timelocks(tree: &VPackTree) -> Result<(), VPackError> {
    let reqs = extract_timelock_requirements(&tree.asp_expiry_script)?;

    if reqs.max_csv_blocks.is_none()
        && reqs.max_csv_seconds.is_none()
        && reqs.max_cltv_height.is_none()
        && reqs.max_cltv_time.is_none()
    {
        return Ok(());
    }

    for step in &tree.path {
        validate_n_sequence_for_csv(&reqs, step.sequence)?;
    }
    validate_n_sequence_for_csv(&reqs, tree.leaf.sequence)?;
    validate_expiry_for_cltv(&reqs, tree.leaf.expiry)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::consensus::second_tech::{compile_bark_expiry_script, decode_script_num};
    use crate::payload::tree::{GenesisItem, VtxoLeaf};
    use crate::types::hashes::Hash;
    use crate::types::{OutPoint, Txid};

    fn minimal_push_csv_script(value: u32) -> Vec<u8> {
        let bytes = super::super::second_tech::encode_bark_cltv(value);
        let mut s = Vec::with_capacity(2 + bytes.len());
        s.push(bytes.len() as u8);
        s.extend_from_slice(&bytes);
        s.push(OP_CSV);
        s
    }

    #[test]
    fn extract_finds_csv_in_ark_style_exit() {
        let script = alloc::vec![OP_1, 0x69, 0x01, 0x2a, OP_CSV, 0x75];
        let got = extract_timelock_requirements(&script).expect("parse");
        assert_eq!(
            got,
            RequiredTimelocks {
                max_csv_blocks: Some(42),
                ..Default::default()
            }
        );
    }

    #[test]
    fn extract_op_16_before_cltv() {
        let script = alloc::vec![OP_16, OP_CLTV];
        let got = extract_timelock_requirements(&script).expect("parse");
        assert_eq!(
            got,
            RequiredTimelocks {
                max_cltv_height: Some(16),
                ..Default::default()
            }
        );
    }

    #[test]
    fn extract_cltv_height_vs_time_split_at_500m() {
        let k = [0xABu8; 32];
        let just_below =
            extract_timelock_requirements(&compile_bark_expiry_script(LOCKTIME_THRESHOLD - 1, &k))
                .expect("parse");
        assert_eq!(
            just_below,
            RequiredTimelocks {
                max_cltv_height: Some(LOCKTIME_THRESHOLD - 1),
                ..Default::default()
            }
        );
        let at_threshold =
            extract_timelock_requirements(&compile_bark_expiry_script(LOCKTIME_THRESHOLD, &k))
                .expect("parse");
        assert_eq!(
            at_threshold,
            RequiredTimelocks {
                max_cltv_time: Some(LOCKTIME_THRESHOLD),
                ..Default::default()
            }
        );
    }

    #[test]
    fn extract_takes_max_csv_and_cltv() {
        let script = alloc::vec![
            0x01, 5, OP_CSV, //
            0x01, 20, OP_CSV, //
            0x01, 100, OP_CLTV, //
            0x01, 30, OP_CLTV,
        ];
        let got = extract_timelock_requirements(&script).expect("parse");
        assert_eq!(
            got,
            RequiredTimelocks {
                max_csv_blocks: Some(20),
                max_cltv_height: Some(100),
                ..Default::default()
            }
        );
    }

    /// Table-driven checks for [`decode_push_at`]: correct cursor advance and script-number extraction
    /// catch pointer / length arithmetic regressions (e.g. mutants flipping `+` / `-`).
    #[test]
    fn test_decode_push_at_exhaustive() {
        struct Case {
            name: &'static str,
            script: Vec<u8>,
            start: usize,
            /// `None` means expect [`VPackError::EncodingError`].
            want: Option<(usize, Option<u32>)>,
        }

        let mut cases: Vec<Case> = Vec::new();

        for n in 1u32..=16 {
            let op = OP_1 + (n - 1) as u8;
            cases.push(Case {
                name: "small_integer_push",
                script: alloc::vec![op],
                start: 0,
                want: Some((1, Some(n))),
            });
        }

        cases.push(Case {
            name: "OP_PUSHBYTES_1",
            script: alloc::vec![0x01, 0xFF],
            start: 0,
            want: Some((2, decode_script_num(&[0xFF]))),
        });

        let mut push75 = alloc::vec![0x4bu8];
        push75.extend_from_slice(&[0xEEu8; 75]);
        cases.push(Case {
            name: "OP_PUSHBYTES_75",
            script: push75,
            start: 0,
            want: Some((76, None)),
        });

        cases.push(Case {
            name: "OP_PUSHDATA1",
            script: alloc::vec![OP_PUSHDATA1, 0x01, 0xAA],
            start: 0,
            want: Some((3, decode_script_num(&[0xAA]))),
        });

        cases.push(Case {
            name: "OP_PUSHDATA2",
            script: alloc::vec![OP_PUSHDATA2, 0x01, 0x00, 0xBB],
            start: 0,
            want: Some((4, decode_script_num(&[0xBB]))),
        });

        cases.push(Case {
            name: "truncated_OP_PUSHBYTES_2",
            script: alloc::vec![0x02, 0xFF],
            start: 0,
            want: None,
        });

        for (idx, case) in cases.iter().enumerate() {
            let got = decode_push_at(&case.script, case.start);
            match &case.want {
                Some((exp_pos, exp_num)) => {
                    let inner = got.expect("decode_push_at should succeed");
                    let (pos, num) = inner.expect("should be a push opcode");
                    assert_eq!(
                        (pos, num),
                        (*exp_pos, *exp_num),
                        "case [{}] {} script={:?} start={}",
                        idx,
                        case.name,
                        case.script,
                        case.start
                    );
                }
                None => {
                    assert!(
                        matches!(got, Err(VPackError::EncodingError)),
                        "case [{}] {} script={:?} start={}: expected EncodingError, got {:?}",
                        idx,
                        case.name,
                        case.script,
                        case.start,
                        got
                    );
                }
            }
        }
    }

    #[test]
    fn validate_csv_path_and_leaf() {
        let txid = Txid::from_byte_array([0x11u8; 32]);
        let script = minimal_push_csv_script(10);
        let mut leaf_spk = alloc::vec![0x51u8, 0x20];
        leaf_spk.extend_from_slice(&[0xAAu8; 32]);
        let tree = VPackTree {
            leaf: VtxoLeaf {
                amount: 1,
                vout: 0,
                sequence: 10,
                expiry: 0,
                exit_delta: 0,
                script_pubkey: leaf_spk,
            },
            leaf_siblings: alloc::vec![],
            path: alloc::vec![
                GenesisItem {
                    sequence: 20,
                    ..Default::default()
                },
                GenesisItem {
                    sequence: 10,
                    ..Default::default()
                },
            ],
            anchor: OutPoint { txid, vout: 0 },
            asset_id: None,
            fee_anchor_script: alloc::vec![],
            internal_key: [0u8; 32],
            asp_expiry_script: script,
        };
        assert!(validate_timelocks(&tree).is_ok());
    }
}
