import { createContext, useContext, useState, type ReactNode } from 'react';

interface TestModeContextType {
  isTestMode: boolean;
  toggleTestMode: () => void;
  setTestMode: (enabled: boolean) => void;
}

const TestModeContext = createContext<TestModeContextType | undefined>(undefined);

interface TestModeProviderProps {
  children: ReactNode;
}

export function TestModeProvider({ children }: TestModeProviderProps) {
  const [isTestMode, setIsTestMode] = useState(false);

  const toggleTestMode = () => {
    setIsTestMode((prev) => !prev);
  };

  const setTestMode = (enabled: boolean) => {
    setIsTestMode(enabled);
  };

  return (
    <TestModeContext.Provider value={{ isTestMode, toggleTestMode, setTestMode }}>
      {children}
    </TestModeContext.Provider>
  );
}

export function useTestMode(): TestModeContextType {
  const context = useContext(TestModeContext);
  if (context === undefined) {
    throw new Error('useTestMode must be used within a TestModeProvider');
  }
  return context;
}
