/** 1 block ≈ 10 minutes in Bitcoin. */
export const BLOCKS_PER_DAY = 144;

/** Estimated vbytes for the final sweep transaction (user's L1 address). */
export const SWEEP_TX_WEIGHT = 110;

/** Converts blocks to approximate days (1 block = 10 min). */
export function blocksToDays(blocks: number): number {
  return blocks / BLOCKS_PER_DAY;
}

/** Formats blocks as "~N days" for display. */
export function formatBlocksAsDays(blocks: number): string {
  const days = blocksToDays(blocks);
  if (days < 1) {
    return '~0 days';
  }
  return `~${Math.round(days)} days`;
}

/** Converts sats to BTC string (e.g. "0.0001 BTC"). */
export function satsToBtc(sats: number): string {
  const btc = sats / 100_000_000;
  return `${btc.toFixed(8)} BTC`;
}

/** Threshold above which to show BTC on hover (e.g. 100,000 sats). */
export const SATS_BTC_HOVER_THRESHOLD = 100_000;
