const MEMPOOL_API_BASE = 'https://mempool.space/api';

const DEFAULT_FEE_RATE_SATS_VB = 20;

interface MempoolFeesRecommended {
  fastestFee: number;
  halfHourFee: number;
  hourFee: number;
  economyFee: number;
  minimumFee: number;
}

/**
 * Fetches recommended fee rates from mempool.space.
 * Returns the "Fast" rate (halfHourFee) or null if the API is unavailable.
 */
export async function fetchRecommendedFee(): Promise<number | null> {
  const url = `${MEMPOOL_API_BASE}/v1/fees/recommended`;
  try {
    const response = await fetch(url);
    if (!response.ok) {
      return null;
    }
    const data = (await response.json()) as MempoolFeesRecommended;
    return data.halfHourFee ?? data.fastestFee ?? null;
  } catch {
    return null;
  }
}

export { DEFAULT_FEE_RATE_SATS_VB };

interface MempoolVout {
  value: number;
  [key: string]: unknown;
}

interface MempoolTxResponse {
  vout?: MempoolVout[];
  [key: string]: unknown;
}

/**
 * Fetches the output value (in sats) for a given txid and vout index from mempool.space.
 * Returns null if the API is down, the tx is not found, or the vout index is invalid.
 */
export async function fetchTxVoutValue(txid: string, voutIndex: number): Promise<number | null> {
  const url = `${MEMPOOL_API_BASE}/tx/${txid}`;
  try {
    const response = await fetch(url);
    if (!response.ok) {
      return null;
    }
    const data = (await response.json()) as MempoolTxResponse;
    const vout = data.vout?.[voutIndex];
    if (vout == null || typeof vout.value !== 'number') {
      return null;
    }
    return vout.value;
  } catch {
    return null;
  }
}
