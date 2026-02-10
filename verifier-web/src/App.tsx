import { useCallback, useEffect, useRef, useState } from 'react';
import initWasm, { init as setPanicHook, wasm_compute_vtxo_id, wasm_verify } from './wasm/wasm_vpack';
import VTXOInput from './components/VTXOInput';
import ReconstructedIdBox from './components/ReconstructedIdBox';
import ProgressiveVerificationBadge from './components/ProgressiveVerificationBadge';
import { fetchTxVoutValue } from './services/mempool';
import {
  parseParentOutpoint,
  type VerificationPhase,
  type VerifyResult,
  type VtxoInputJson,
} from './types/verification';

type EngineStatus = 'Loading' | 'Ready' | 'Error';

function injectAnchorValue(json: string, anchorValue: number): string {
  const parsed = JSON.parse(json) as VtxoInputJson;
  const withAnchor = { ...parsed, anchor_value: anchorValue };
  return JSON.stringify(withAnchor);
}

function App() {
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('Loading');
  const [vtxoData, setVtxoData] = useState('');
  const [phase, setPhase] = useState<VerificationPhase>('calculating');
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [manualAnchorValue, setManualAnchorValue] = useState('');
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

  const runProgressiveVerification = useCallback(async (input: string) => {
    setVerifyResult(null);
    setVerificationError(null);
    setPhase('calculating');

    let parsed: VtxoInputJson;
    try {
      parsed = JSON.parse(input) as VtxoInputJson;
    } catch {
      setVerificationError('Invalid JSON format');
      setPhase('error');
      return;
    }

    if (!parsed.raw_evidence?.expected_vtxo_id || !parsed.reconstruction_ingredients) {
      setVerificationError('Missing raw_evidence.expected_vtxo_id or reconstruction_ingredients');
      setPhase('error');
      return;
    }

    const expectedId = parsed.raw_evidence.expected_vtxo_id;

    try {
      const pathResult = wasm_compute_vtxo_id(input) as { variant: string; reconstructed_tx_id: string };
      if (pathResult.reconstructed_tx_id !== expectedId) {
        setVerificationError(
          `Reconstructed ID does not match. Expected ${expectedId}, got ${pathResult.reconstructed_tx_id}`,
        );
        setPhase('id_mismatch');
        return;
      }
    } catch (pathErr) {
      const msg = pathErr instanceof Error ? pathErr.message : String(pathErr);
      const isMissingExport =
        typeof msg === 'string' && (msg.includes('wasm_compute_vtxo_id') || msg.includes('not a function'));
      setVerificationError(
        isMissingExport
          ? 'Progressive verification requires a rebuilt WASM. Run: cd wasm-vpack && wasm-pack build --target web && npm run wasm:sync'
          : msg,
      );
      setPhase('error');
      return;
    }

    setPhase('path_verified');

    const outpoint = parseParentOutpoint(parsed.reconstruction_ingredients.parent_outpoint);
    if (!outpoint) {
      setVerificationError('Invalid parent_outpoint; enter anchor value manually.');
      setPhase('fetch_failed');
      return;
    }

    const anchorValue = await fetchTxVoutValue(outpoint.txid, outpoint.voutIndex);
    if (anchorValue === null) {
      setVerificationError('Could not fetch L1 value from mempool.space. Enter value below to continue.');
      setPhase('fetch_failed');
      return;
    }

    try {
      const jsonWithAnchor = injectAnchorValue(input, anchorValue);
      const result = wasm_verify(jsonWithAnchor) as VerifyResult;
      setVerifyResult(result);
      setPhase('sovereign_complete');
    } catch (fullErr) {
      setVerificationError(fullErr instanceof Error ? fullErr.message : String(fullErr));
      setPhase('error');
    }
  }, []);

  const handleVerifyWithManualAnchor = useCallback(() => {
    const value = parseInt(manualAnchorValue, 10);
    if (Number.isNaN(value) || value < 0 || !vtxoData.trim()) {
      setVerificationError('Enter a valid non-negative sats value.');
      return;
    }
    setVerificationError(null);
    try {
      const jsonWithAnchor = injectAnchorValue(vtxoData, value);
      const result = wasm_verify(jsonWithAnchor) as VerifyResult;
      setVerifyResult(result);
      setPhase('sovereign_complete');
    } catch (err) {
      setVerificationError(err instanceof Error ? err.message : String(err));
      setPhase('error');
    }
  }, [manualAnchorValue, vtxoData]);

  useEffect(() => {
    if (engineStatus !== 'Ready' || !vtxoData.trim()) {
      return;
    }

    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
    }

    timeoutRef.current = window.setTimeout(() => {
      runProgressiveVerification(vtxoData);
    }, 300);

    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [vtxoData, engineStatus, runProgressiveVerification]);

  const shouldShowResults = engineStatus === 'Ready' && vtxoData.trim();
  const showManualAnchorFallback = shouldShowResults && phase === 'fetch_failed';

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

          {shouldShowResults && (
            <div className="space-y-4">
              <ProgressiveVerificationBadge
                phase={phase}
                errorMessage={verificationError}
              />

              {showManualAnchorFallback && (
                <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg space-y-3">
                  <label htmlFor="manual-anchor" className="block text-sm font-medium text-amber-800 dark:text-amber-200">
                    L1 anchor value (sats)
                  </label>
                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      id="manual-anchor"
                      type="number"
                      min={0}
                      value={manualAnchorValue}
                      onChange={(e) => setManualAnchorValue(e.target.value)}
                      placeholder="e.g. 1100"
                      className="w-32 px-3 py-2 border border-amber-300 dark:border-amber-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    />
                    <button
                      type="button"
                      onClick={handleVerifyWithManualAnchor}
                      className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-2"
                    >
                      Verify with this value
                    </button>
                  </div>
                </div>
              )}

              {phase === 'sovereign_complete' && verifyResult && (
                <ReconstructedIdBox reconstructedId={verifyResult.reconstructed_tx_id} />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
