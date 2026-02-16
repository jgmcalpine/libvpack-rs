import type { Network } from '../types/network';
import { NETWORK_LABELS } from '../types/network';

const SEGMENT_BASE =
  'px-4 py-2.5 rounded-lg font-medium text-sm transition-all border focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 dark:focus:ring-offset-gray-900';

const SEGMENT_INACTIVE =
  'bg-transparent text-gray-600 dark:text-gray-400 border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-800';

const SEGMENT_ACTIVE: Record<Network, string> = {
  bitcoin:
    'bg-orange-500/20 text-orange-400 border-orange-500 shadow-sm shadow-orange-500/20',
  signet:
    'bg-cyan-500/20 text-cyan-400 border-cyan-500 shadow-sm shadow-cyan-500/20',
  testnet:
    'bg-green-500/20 text-green-400 border-green-500 shadow-sm shadow-green-500/20',
};

interface NetworkSwitcherProps {
  network: Network;
  onNetworkChange: (network: Network) => void;
}

function NetworkSwitcher({ network, onNetworkChange }: NetworkSwitcherProps) {
  const networks: Network[] = ['bitcoin', 'signet', 'testnet'];

  return (
    <div
      className="flex flex-wrap gap-2"
      role="group"
      aria-label="Select Bitcoin network"
    >
      {networks.map((n) => (
        <button
          key={n}
          type="button"
          onClick={() => onNetworkChange(n)}
          className={`${SEGMENT_BASE} ${
            network === n ? SEGMENT_ACTIVE[n] : SEGMENT_INACTIVE
          }`}
          aria-pressed={network === n}
        >
          {NETWORK_LABELS[n]}
        </button>
      ))}
    </div>
  );
}

export default NetworkSwitcher;
