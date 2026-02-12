/**
 * Maps variant string to issuer label for filename.
 */
function issuerFromVariant(variant: string): string {
  switch (variant) {
    case '0x04':
      return 'ark_labs';
    case '0x03':
      return 'second';
    default:
      return 'unknown';
  }
}

/**
 * Extracts short ID (first 8 hex chars) from reconstructed_tx_id.
 */
function shortIdFromReconstructedTxId(reconstructedTxId: string): string {
  return reconstructedTxId.slice(0, 8);
}

/**
 * Generates standardized V-PACK filename: vtxo_[issuer]_[short_id].vpk
 */
export function buildVpackFilename(
  variant: string,
  reconstructedTxId: string
): string {
  const issuer = issuerFromVariant(variant);
  const shortId = shortIdFromReconstructedTxId(reconstructedTxId);
  return `vtxo_${issuer}_${shortId}.vpk`;
}

/**
 * Triggers browser download of V-PACK binary.
 * Uses Blob + URL.createObjectURL for efficient transfer (no unnecessary cloning).
 */
export function downloadVpackBytes(bytes: Uint8Array, filename: string): void {
  const blob = new Blob([bytes as BufferSource], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
