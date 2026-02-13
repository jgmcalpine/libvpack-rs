export interface ReconstructionOutput {
  value: number;
  script: string;
  note?: string;
}

export interface ReconstructionIngredients {
  topology?: string;
  tx_version?: number;
  nSequence?: number;
  parent_outpoint?: string;
  anchor_outpoint?: string;
  fee_anchor_script?: string;
  id_type?: string;
  outputs: ReconstructionOutput[];
  [key: string]: unknown;
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
 * Computes the sum of output values from reconstruction_ingredients (self-consistency audit).
 * Uses outputs[] when present; else child_output + siblings[] for branch-style;
 * else path[0] child_amount + siblings for Second Tech chain; else top-level amount (leaf).
 */
export function computeOutputSumFromIngredients(
  ingredients: ReconstructionIngredients | undefined
): number {
  if (!ingredients) return 0;
  const outputs = ingredients.outputs ?? [];
  if (outputs.length > 0) {
    return outputs.reduce((sum, o) => sum + (o.value ?? 0), 0);
  }
  const child = (ingredients as { child_output?: { value?: number } }).child_output?.value ?? 0;
  const siblings = (ingredients as { siblings?: { value?: number }[] }).siblings ?? [];
  const siblingsSum = siblings.reduce((s, n) => s + (n.value ?? 0), 0);
  const branchSum = child + siblingsSum;
  if (branchSum > 0) return branchSum;
  const path = (ingredients as { path?: { child_amount?: number; siblings?: { value?: number }[] }[] }).path;
  if (Array.isArray(path) && path.length > 0) {
    const first = path[0];
    const childAmount = first?.child_amount ?? 0;
    const pathSiblings = first?.siblings ?? [];
    const pathSiblingsSum = pathSiblings.reduce((s, n) => s + (n.value ?? 0), 0);
    const pathSum = childAmount + pathSiblingsSum;
    if (pathSum > 0) return pathSum;
  }
  const amount = (ingredients as { amount?: number }).amount;
  return typeof amount === 'number' && Number.isFinite(amount) ? amount : 0;
}

/**
 * Parses outpoint from either "txid:vout" or raw 64-char hex (txid only, vout 0).
 * Returns null if the format is invalid.
 */
export function parseParentOutpoint(outpointStr: string | undefined): { txid: string; voutIndex: number } | null {
  if (!outpointStr || typeof outpointStr !== 'string') {
    return null;
  }
  const trimmed = outpointStr.trim();
  if (!trimmed) return null;

  const parts = trimmed.split(':');
  if (parts.length === 2) {
    const [txid, voutStr] = parts;
    const voutIndex = parseInt(voutStr, 10);
    if (txid && /^[a-fA-F0-9]{64}$/.test(txid) && !Number.isNaN(voutIndex) && voutIndex >= 0) {
      return { txid, voutIndex };
    }
  }
  // Raw 64-char hex: treat as txid with vout 0
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return { txid: trimmed, voutIndex: 0 };
  }
  return null;
}

export interface AnchorData {
  txid: string;
  voutIndex: number;
  /** Display label for anchor source */
  label: string;
}

/**
 * Extracts anchor outpoint from reconstruction_ingredients.
 * Checks both parent_outpoint and anchor_outpoint (LogicAdapter-compatible).
 * Supports "txid:vout" and raw 64-char hex.
 * In Test Mode, pass isTestMode true to get a mock label when outpoint is missing.
 */
export function extractAnchorData(
  ingredients: ReconstructionIngredients | undefined,
  isTestMode: boolean
): AnchorData | null {
  if (!ingredients) return null;
  const raw =
    ingredients.parent_outpoint ?? ingredients.anchor_outpoint ?? undefined;
  const parsed = parseParentOutpoint(raw);
  if (parsed) {
    return {
      ...parsed,
      label: isTestMode ? 'Mock/Testnet' : 'L1',
    };
  }
  if (isTestMode) {
    return { txid: '', voutIndex: 0, label: 'Anchor: Mock/Testnet' };
  }
  return null;
}

export type L1Status = 'verified' | 'unknown' | 'mock' | 'anchor_not_found' | null;

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

export interface PathDetail {
  txid: string;
  amount: number;
  is_leaf: boolean;
  vout: number;
  has_signature: boolean;
  has_fee_anchor: boolean;
  exit_weight_vb: number; // Estimated vbytes for exit transaction
  /** Raw Bitcoin transaction preimage hex (BIP-431/TRUC). Empty for anchor (L1 tx). */
  tx_preimage_hex?: string;
}

export interface VerifyResult {
  variant: string;
  status: string;
  reconstructed_tx_id: string;
  path_details?: PathDetail[];
}
