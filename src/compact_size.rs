//! Bitcoin CompactSize (VarInt) encoding for consensus-critical serialization.
//! Used by pack (TxOut script length) and consensus::tx_factory (vin/vout counts, script lengths).

use alloc::vec::Vec;

use byteorder::ByteOrder;
use byteorder::LittleEndian;

/// Encodes `n` as Bitcoin CompactSize and appends to `buf`.
/// 0–252: 1 byte; 253–0xFFFF: 0xFD + 2B LE; 0x10000–0xFFFFFFFF: 0xFE + 4B LE; else 0xFF + 8B LE.
#[inline]
pub fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n < 0x1_0000 {
        buf.push(0xfd);
        let mut b = [0u8; 2];
        LittleEndian::write_u16(&mut b, n as u16);
        buf.extend_from_slice(&b);
    } else if n < 0x1_0000_0000 {
        buf.push(0xfe);
        let mut b = [0u8; 4];
        LittleEndian::write_u32(&mut b, n as u32);
        buf.extend_from_slice(&b);
    } else {
        buf.push(0xff);
        let mut b = [0u8; 8];
        LittleEndian::write_u64(&mut b, n);
        buf.extend_from_slice(&b);
    }
}

/// Decodes Bitcoin CompactSize from the start of `data`.
/// Returns `Some((value, num_bytes_consumed))` or `None` if insufficient bytes.
#[inline]
pub fn read_compact_size(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let b = data[0];
    if b < 253 {
        Some((b as u64, 1))
    } else if b == 0xfd {
        if data.len() < 3 {
            return None;
        }
        let n = LittleEndian::read_u16(&data[1..3]) as u64;
        Some((n, 3))
    } else if b == 0xfe {
        if data.len() < 5 {
            return None;
        }
        let n = LittleEndian::read_u32(&data[1..5]) as u64;
        Some((n, 5))
    } else {
        if data.len() < 9 {
            return None;
        }
        let n = LittleEndian::read_u64(&data[1..9]);
        Some((n, 9))
    }
}
