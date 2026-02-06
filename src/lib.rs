#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

// Needed for Vec
extern crate alloc;

pub mod adapters;
pub mod compact_size;
pub mod consensus;
pub mod error;
pub mod header;
pub mod pack;
pub mod payload;

pub use consensus::{ConsensusEngine, VtxoId};
pub use header::TxVariant;
pub use payload::tree::VPackTree;

use crate::consensus::{ArkLabsV3, SecondTechV3};
use crate::error::VPackError;
use crate::header::{Header, HEADER_SIZE};
use crate::payload::reader::BoundedReader;

/// Verifies a V-PACK byte array against an expected VTXO ID.
///
/// # Arguments
/// * `vpack_bytes` - Complete V-PACK byte array. The first 24 bytes must be the header.
/// * `expected_id` - The expected VTXO ID to verify against.
///
/// # Returns
/// * `Ok(VPackTree)` - Verification succeeded, returns the parsed tree
/// * `Err(VPackError)` - Verification failed (checksum, parsing, or ID mismatch)
pub fn verify(vpack_bytes: &[u8], expected_id: &VtxoId) -> Result<VPackTree, VPackError> {
    #[cfg(test)]
    {
        std::eprintln!("DEBUG VERIFY: Starting verify. Total bytes: {}", vpack_bytes.len());
        let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
    }
    
    // Step 1: Parse Header (first 24 bytes)
    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])?;
    
    #[cfg(test)]
    {
        std::eprintln!("DEBUG VERIFY: Parsed header. Variant: {:?}, Payload len: {}", header.tx_variant, header.payload_len);
        let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
    }

    // Step 2: Extract Payload
    let payload = &vpack_bytes[HEADER_SIZE..];
    
    #[cfg(test)]
    {
        std::eprintln!("DEBUG VERIFY: Extracted payload. Payload bytes: {}, Expected: {}", payload.len(), header.payload_len);
        let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
    }

    // Step 3: Verify Checksum
    header.verify_checksum(payload)?;
    
    #[cfg(test)]
    {
        std::eprintln!("DEBUG VERIFY: Checksum verified. Starting payload parse.");
        let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
    }

    // Step 4: Parse Payload
    let tree = BoundedReader::parse(&header, payload)
        .map_err(|e| {
            #[cfg(test)]
            {
                std::eprintln!("DEBUG VERIFY: ERROR in BoundedReader::parse: {:?}", e);
                let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
            }
            e
        })?;

    // Step 5: Dispatch by Variant and Verify (only 0x03 and 0x04 are valid per TxVariant::try_from)
    match header.tx_variant {
        crate::header::TxVariant::V3Anchored => {
            let engine = ArkLabsV3;
            engine.verify(&tree, expected_id)?;
        }
        crate::header::TxVariant::V3Plain => {
            let engine = SecondTechV3;
            engine.verify(&tree, expected_id)?;
        }
    }

    // Step 6: Return the parsed tree
    Ok(tree)
}

/// Test-only: compute the VTXO ID that would be verified for this V-PACK. Used to fill expected_vtxo_id in vectors.
#[cfg(feature = "std")]
pub fn compute_vtxo_id_from_bytes(vpack_bytes: &[u8]) -> Result<VtxoId, VPackError> {
    let header = Header::from_bytes(&vpack_bytes[..HEADER_SIZE])?;
    header.verify_checksum(&vpack_bytes[HEADER_SIZE..])?;
    let tree = BoundedReader::parse(&header, &vpack_bytes[HEADER_SIZE..])?;
    match header.tx_variant {
        crate::header::TxVariant::V3Anchored => ArkLabsV3.compute_vtxo_id(&tree),
        crate::header::TxVariant::V3Plain => SecondTechV3.compute_vtxo_id(&tree),
    }
}