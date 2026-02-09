import { useEffect, useRef, useState } from 'react';
import initWasm, { init as setPanicHook, wasm_verify } from './wasm/wasm_vpack';
import VTXOInput from './components/VTXOInput';
import ResultBadge from './components/ResultBadge';
import ReconstructedIdBox from './components/ReconstructedIdBox';

type EngineStatus = 'Loading' | 'Ready' | 'Error';

interface VerificationResult {
  variant: string;
  status: string;
  reconstructed_tx_id: string;
}

function App() {
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('Loading');
  const [vtxoData, setVtxoData] = useState<string>('');
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    const initializeWasm = async () => {
      try {
        await initWasm();
        setPanicHook();
        setEngineStatus('Ready');
      } catch (error) {
        console.error('Failed to initialize WASM module:', error);
        setEngineStatus('Error');
      }
    };

    initializeWasm();
  }, []);

  useEffect(() => {
    if (engineStatus !== 'Ready' || !vtxoData.trim()) {
      return;
    }

    // Clear previous timeout
    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
    }

    const verifyData = async () => {
      // Clear previous results when starting new verification
      setVerificationResult(null);
      setVerificationError(null);

      try {
        // Attempt to parse JSON first
        const parsed = JSON.parse(vtxoData);
        
        // Basic validation: check if it has the expected structure
        if (!parsed.raw_evidence?.expected_vtxo_id || !parsed.reconstruction_ingredients) {
          setVerificationError('Invalid JSON structure: missing raw_evidence.expected_vtxo_id or reconstruction_ingredients');
          return;
        }

        // Call WASM verification
        const result = wasm_verify(vtxoData) as VerificationResult;
        setVerificationResult(result);
      } catch (error) {
        if (error instanceof SyntaxError) {
          setVerificationError('Invalid JSON format');
        } else {
          const errorMessage = error instanceof Error ? error.message : String(error);
          setVerificationError(errorMessage);
        }
      }
    };

    // Debounce verification to avoid excessive calls
    timeoutRef.current = window.setTimeout(verifyData, 300);
    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [vtxoData, engineStatus]);

  const shouldShowResults = engineStatus === 'Ready' && vtxoData.trim();

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 py-8 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2 text-gray-900 dark:text-white">
            VTXO Inspector
          </h1>
          <div className="text-sm text-gray-600 dark:text-gray-400">
            VTXO Engine: <span className="font-semibold">{engineStatus}</span>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 space-y-6">
          <VTXOInput value={vtxoData} onChange={setVtxoData} />

          {shouldShowResults && verificationError && (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-red-800 dark:text-red-200 font-medium">Verification Error:</p>
              <p className="text-red-700 dark:text-red-300 text-sm mt-1">{verificationError}</p>
            </div>
          )}

          {shouldShowResults && verificationResult && (
            <div className="space-y-4">
              <ResultBadge 
                status={verificationResult.status} 
                variant={verificationResult.variant}
              />
              <ReconstructedIdBox reconstructedId={verificationResult.reconstructed_tx_id} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
