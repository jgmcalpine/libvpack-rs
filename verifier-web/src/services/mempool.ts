import { getMempoolUrl } from '../utils/mempoolUrl';
import type { Network } from '../types/network';

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
export async function fetchRecommendedFee(
  network: Network = 'bitcoin',
): Promise<number | null> {
  const base = getMempoolUrl(network);
  const url = `${base}/v1/fees/recommended`;
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
export async function fetchTxVoutValue(
  txid: string,
  voutIndex: number,
  network: Network = 'bitcoin',
): Promise<number | null> {
  const base = getMempoolUrl(network);
  const url = `${base}/tx/${txid}`;
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
