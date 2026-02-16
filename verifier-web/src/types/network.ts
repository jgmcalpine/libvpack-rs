export type Network = 'bitcoin' | 'signet' | 'testnet';

export const NETWORK_LABELS: Record<Network, string> = {
  bitcoin: 'Mainnet',
  signet: 'Signet',
  testnet: 'Testnet',
};
