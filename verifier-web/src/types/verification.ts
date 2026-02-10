export interface ReconstructionOutput {
  value: number;
  script: string;
  note?: string;
}

export interface ReconstructionIngredients {
  topology: string;
  tx_version?: number;
  nSequence?: number;
  parent_outpoint: string;
  fee_anchor_script?: string;
  id_type?: string;
  outputs: ReconstructionOutput[];
}

export interface RawEvidence {
  expected_vtxo_id: string;
}

export interface VtxoInputJson {
  meta?: { variant?: string; description?: string };
  raw_evidence: RawEvidence;
  reconstruction_ingredients: ReconstructionIngredients;
  anchor_value?: number | string;
}

/**
 * Parses "txid:vout_index" into { txid, voutIndex }.
 * Returns null if the format is invalid.
 */
export function parseParentOutpoint(parentOutpoint: string): { txid: string; voutIndex: number } | null {
  const parts = parentOutpoint.split(':');
  if (parts.length !== 2) {
    return null;
  }
  const [txid, voutStr] = parts;
  const voutIndex = parseInt(voutStr, 10);
  if (!txid || txid.length !== 64 || Number.isNaN(voutIndex) || voutIndex < 0) {
    return null;
  }
  return { txid, voutIndex };
}

export type VerificationPhase =
  | 'calculating'
  | 'path_verified'
  | 'sovereign_complete'
  | 'id_mismatch'
  | 'error'
  | 'fetch_failed';

export interface ComputeVtxoIdResult {
  variant: string;
  reconstructed_tx_id: string;
}

export interface VerifyResult {
  variant: string;
  status: string;
  reconstructed_tx_id: string;
}
