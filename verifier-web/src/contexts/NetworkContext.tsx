import {
  createContext,
  useContext,
  useState,
  useCallback,
  type ReactNode,
} from 'react';
import type { Network } from '../types/network';

interface NetworkContextType {
  network: Network;
  setNetwork: (network: Network) => void;
}

const NetworkContext = createContext<NetworkContextType | undefined>(undefined);

interface NetworkProviderProps {
  children: ReactNode;
  defaultNetwork?: Network;
}

export function NetworkProvider({
  children,
  defaultNetwork = 'signet',
}: NetworkProviderProps) {
  const [network, setNetwork] = useState<Network>(defaultNetwork);

  const setNetworkStable = useCallback((n: Network) => {
    setNetwork(n);
  }, []);

  return (
    <NetworkContext.Provider
      value={{ network, setNetwork: setNetworkStable }}
    >
      {children}
    </NetworkContext.Provider>
  );
}

export function useNetwork(): NetworkContextType {
  const context = useContext(NetworkContext);
  if (context === undefined) {
    throw new Error('useNetwork must be used within a NetworkProvider');
  }
  return context;
}
