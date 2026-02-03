// src/header.rs
use crate::error::VPackError;
use byteorder::{ByteOrder, LittleEndian};

/// The standard V-PACK Magic Bytes ("VPK")
pub const MAGIC_BYTES: [u8; 3] = [0x56, 0x50, 0x4B];

/// Hard Consensus Limits (DoS Protection)
pub const MAX_TREE_DEPTH: u16 = 32;
pub const MAX_TREE_ARITY: u16 = 16;
pub const MAX_PAYLOAD_SIZE: u32 = 1_048_576; // 1MB Hard Cap
pub const HEADER_SIZE: usize = 24;
pub const CURRENT_VERSION: u8 = 1;

/// Header Flags
pub const FLAG_COMPRESSION_LZ4: u8 = 0x01;
pub const FLAG_TESTNET: u8         = 0x02;
pub const FLAG_PROOF_COMPACT: u8   = 0x04;
pub const FLAG_HAS_ASSET_ID: u8    = 0x08;

/// Tx Variant (V-BIP-01: 0x03 = V3-Plain, 0x04 = V3-Anchored).
/// Wire format is u8; internal logic uses this enum for exhaustive matching.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxVariant {
    /// Second Tech: struct-hash / OutPoint-based ID.
    V3Plain = 0x03,
    /// Ark Labs: transaction-reconstruction with mandatory Fee Anchor.
    V3Anchored = 0x04,
}

impl TxVariant {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl core::convert::TryFrom<u8> for TxVariant {
    type Error = VPackError;
    fn try_from(byte: u8) -> Result<Self, VPackError> {
        match byte {
            0x03 => Ok(TxVariant::V3Plain),
            0x04 => Ok(TxVariant::V3Anchored),
            other => Err(VPackError::InvalidTxVariant(other)),
        }
    }
}

/// The V-PACK Header.
/// This is an internal Rust representation. It is NOT `repr(C)` because the
/// wire format (packed) does not match C alignment rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub version: u8,
    pub tx_variant: TxVariant,
    pub tree_arity: u16,
    pub tree_depth: u16,
    // Represents the number of sibling nodes in the Merkle Proof path.
    // This is linear to depth, not exponential to tree size.
    pub node_count: u16,
    pub asset_type: u32,
    pub payload_len: u32,
    pub checksum: u32,
}

impl Header {
    /// Zero-Allocation parsing: Reads the header from the first 24 bytes of a slice.
    /// Manually parses fields to ensure consistency regardless of architecture.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VPackError> {
        if bytes.len() < HEADER_SIZE {
            return Err(VPackError::IncompleteData);
        }

        // 1. Check Magic Bytes
        // We use manual indexing for speed and explicit bounds check
        if bytes[0] != MAGIC_BYTES[0] || bytes[1] != MAGIC_BYTES[1] || bytes[2] != MAGIC_BYTES[2] {
            return Err(VPackError::InvalidMagic);
        }

        // 2. Parse Fields manually (Little-Endian)
        let flags = bytes[3];
        let version = bytes[4];
        let tx_variant = TxVariant::try_from(bytes[5])?;
        
        let tree_arity = LittleEndian::read_u16(&bytes[6..8]);
        let tree_depth = LittleEndian::read_u16(&bytes[8..10]);
        let node_count = LittleEndian::read_u16(&bytes[10..12]);
        
        let asset_type = LittleEndian::read_u32(&bytes[12..16]);
        let payload_len = LittleEndian::read_u32(&bytes[16..20]);
        let checksum = LittleEndian::read_u32(&bytes[20..24]);

        let header = Self {
            flags,
            version,
            tx_variant,
            tree_arity,
            tree_depth,
            node_count,
            asset_type,
            payload_len,
            checksum,
        };

        // 3. Validate logical consistency
        header.validate()?;

        Ok(header)
    }

    /// Serializes the header to a 24-byte array.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        
        buf[0..3].copy_from_slice(&MAGIC_BYTES);
        buf[3] = self.flags;
        buf[4] = self.version;
        buf[5] = self.tx_variant.as_u8();
        
        LittleEndian::write_u16(&mut buf[6..8], self.tree_arity);
        LittleEndian::write_u16(&mut buf[8..10], self.tree_depth);
        LittleEndian::write_u16(&mut buf[10..12], self.node_count);
        
        LittleEndian::write_u32(&mut buf[12..16], self.asset_type);
        LittleEndian::write_u32(&mut buf[16..20], self.payload_len);
        LittleEndian::write_u32(&mut buf[20..24], self.checksum);
        
        buf
    }

    /// Performs structural and logical validation of the Header fields.
    pub fn validate(&self) -> Result<(), VPackError> {
        // Version Lock
        if self.version != CURRENT_VERSION {
            return Err(VPackError::UnsupportedVersion(self.version));
        }

        // Sanity Check: Arity (Must be >= 2)
        if self.tree_arity < 2 {
            return Err(VPackError::InvalidArity(self.tree_arity));
        }

        // Sanity Check: Payload Size
        if self.payload_len == 0 {
            return Err(VPackError::EmptyPayload);
        }
        if self.payload_len > MAX_PAYLOAD_SIZE {
            return Err(VPackError::PayloadTooLarge(self.payload_len));
        }

        // DoS Protection: Tree Limits
        if self.tree_depth > MAX_TREE_DEPTH {
            return Err(VPackError::ExceededMaxDepth(self.tree_depth));
        }
        if self.tree_arity > MAX_TREE_ARITY {
            return Err(VPackError::ExceededMaxArity(self.tree_arity));
        }

        // Node Count Check:
        // This validates the number of sibling nodes in the *Proof*, not the total tree.
        // Max nodes in a proof path = Depth * (Arity - 1).
        // We use a looser bound (Depth * Arity) to prevent overflow edge cases.
        let theoretical_max_nodes = (self.tree_depth as u32) * (self.tree_arity as u32);
        if (self.node_count as u32) > theoretical_max_nodes {
            return Err(VPackError::NodeCountMismatch(self.node_count, theoretical_max_nodes as u16));
        }

        Ok(())
    }

    /// Verifies the integrity of the V-PACK using CRC32.
    /// Optimized to avoid intermediate allocations.
    pub fn verify_checksum(&self, payload: &[u8]) -> Result<(), VPackError> {
        if payload.len() != self.payload_len as usize {
            return Err(VPackError::IncompleteData);
        }

        let mut hasher = crc32fast::Hasher::new();
        
        // 1. Hash Header Fields directly (Matching wire order)
        hasher.update(&MAGIC_BYTES);
        hasher.update(&[self.flags, self.version, self.tx_variant.as_u8()]);
        hasher.update(&self.tree_arity.to_le_bytes());
        hasher.update(&self.tree_depth.to_le_bytes());
        hasher.update(&self.node_count.to_le_bytes());
        hasher.update(&self.asset_type.to_le_bytes());
        hasher.update(&self.payload_len.to_le_bytes());
        // Checksum field (bytes 20-23) is explicitly EXCLUDED
        
        // 2. Hash Payload
        hasher.update(payload);
        
        let calculated = hasher.finalize();
        
        if calculated != self.checksum {
            return Err(VPackError::ChecksumMismatch { 
                expected: self.checksum, 
                found: calculated 
            });
        }

        Ok(())
    }

    // --- Helpers (Const for Compile-Time Evaluation) ---

    pub const fn is_testnet(&self) -> bool {
        (self.flags & FLAG_TESTNET) != 0
    }

    pub const fn is_compact(&self) -> bool {
        (self.flags & FLAG_PROOF_COMPACT) != 0
    }
    
    pub const fn has_asset_id(&self) -> bool {
        (self.flags & FLAG_HAS_ASSET_ID) != 0
    }
}