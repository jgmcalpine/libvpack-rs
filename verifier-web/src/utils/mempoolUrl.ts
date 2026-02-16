import type { Network } from '../types/network';

/**
 * Returns the Mempool.space API base URL for the given network.
 */
export function getMempoolUrl(network: Network): string {
  switch (network) {
    case 'bitcoin':
      return 'https://mempool.space/api';
    case 'signet':
      return 'https://mempool.space/signet/api';
    case 'testnet':
      return 'https://mempool.space/testnet/api';
    default:
      return 'https://mempool.space/api';
  }
}

/**
 * Returns the Mempool.space explorer base URL for transaction links.
 */
export function getMempoolExplorerUrl(network: Network): string {
  switch (network) {
    case 'bitcoin':
      return 'https://mempool.space';
    case 'signet':
      return 'https://mempool.space/signet';
    case 'testnet':
      return 'https://mempool.space/testnet';
    default:
      return 'https://mempool.space';
  }
}
