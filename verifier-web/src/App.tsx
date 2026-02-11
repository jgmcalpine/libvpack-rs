import { useCallback, useEffect, useRef, useState } from 'react';
import initWasm, { init as setPanicHook, wasm_compute_vtxo_id, wasm_verify } from './wasm/wasm_vpack';
import VTXOInput from './components/VTXOInput';
import VectorPillGroup from './components/VectorPillGroup';
import ProgressiveVerificationBadge from './components/ProgressiveVerificationBadge';
import SovereigntyMap from './components/SovereigntyMap';
import MockDataBadge from './components/MockDataBadge';
import { ARK_LABS_VECTORS, SECOND_VECTORS } from './constants/vectors';
import type { VectorEntry } from './constants/vectors';
import { TestModeProvider, useTestMode } from './contexts/TestModeContext';
import { fetchTxVoutValue } from './services/mempool';
import {
  computeOutputSumFromIngredients,
  extractAnchorData,
  parseParentOutpoint,
  type PathDetail,
  type VerificationPhase,
  type VerifyResult,
  type VtxoInputJson,
} from './types/verification';

type EngineStatus = 'Loading' | 'Ready' | 'Error';

/** Pass anchor as string to WASM to avoid JS 53-bit integer precision issues. */
function injectAnchorValue(json: string, anchorValue: number | string): string {
  const parsed = JSON.parse(json) as VtxoInputJson;
  const valueForWasm = typeof anchorValue === 'number' ? String(anchorValue) : anchorValue;
  const withAnchor = { ...parsed, anchor_value: valueForWasm };
  return JSON.stringify(withAnchor);
}

function AppContent() {
  const { isTestMode, toggleTestMode } = useTestMode();
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('Loading');
  const [vtxoData, setVtxoData] = useState('');
  const [selectedVectorId, setSelectedVectorId] = useState<string | null>(null);
  const [phase, setPhase] = useState<VerificationPhase>('calculating');
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [manualAnchorValue, setManualAnchorValue] = useState('');
  const [l1Status, setL1Status] = useState<'verified' | 'unknown' | 'mock' | null>(null);
  const [lastAuditInputValue, setLastAuditInputValue] = useState<number | null>(null);
  const [lastAuditOutputSum, setLastAuditOutputSum] = useState<number | null>(null);
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

  const handleToggleTestMode = useCallback(() => {
    if (isTestMode) {
      setSelectedVectorId(null);
    }
    toggleTestMode();
  }, [isTestMode, toggleTestMode]);

  const clearInvalidStates = useCallback(() => {
    setVerifyResult(null);
    setManualAnchorValue('');
    setLastAuditInputValue(null);
    setLastAuditOutputSum(null);
    setVerificationError(null);
    setL1Status(null);
    setPhase('calculating');
  }, []);

  const handleVtxoDataChange = useCallback(
    (newValue: string) => {
      setVtxoData(newValue);
      setSelectedVectorId(null);
      clearInvalidStates();
    },
    [clearInvalidStates],
  );

  const handleVectorSelect = useCallback(
    (vector: VectorEntry) => {
      const json = vector.getJson();
      setVtxoData(json);
      setSelectedVectorId(vector.id);
      clearInvalidStates();
    },
    [clearInvalidStates],
  );

  const runProgressiveVerification = useCallback(async (input: string) => {
    setVerifyResult(null);
    setVerificationError(null);
    setL1Status(null);
    setLastAuditInputValue(null);
    setLastAuditOutputSum(null);
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

    const outputSum = computeOutputSumFromIngredients(parsed.reconstruction_ingredients);
    let anchorValue: number | null = null;

    if (isTestMode) {
      // Test Mode: self-consistency audit — anchor = sum of outputs so tree math matches.
      anchorValue = outputSum > 0 ? outputSum : 1100;
      setL1Status('mock');
      setLastAuditInputValue(anchorValue);
      setLastAuditOutputSum(outputSum);
    } else {
      // Live mode: need outpoint to fetch L1 value (check both parent_outpoint and anchor_outpoint)
      const outpointStr =
        parsed.reconstruction_ingredients.parent_outpoint ??
        parsed.reconstruction_ingredients.anchor_outpoint;
      const outpoint = parseParentOutpoint(outpointStr);
      if (!outpoint) {
        setVerificationError('Invalid parent_outpoint or anchor_outpoint; enter anchor value manually.');
        setPhase('fetch_failed');
        return;
      }
      anchorValue = await fetchTxVoutValue(outpoint.txid, outpoint.voutIndex);
      if (anchorValue === null) {
        setVerificationError(
          'Could not fetch L1 value from mempool.space. Switch to Test Mode or enter value below to continue.',
        );
        setPhase('fetch_failed');
        return;
      }
      setL1Status('verified');
      setLastAuditInputValue(anchorValue);
      setLastAuditOutputSum(outputSum);
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
  }, [isTestMode]);

  const handleVerifyWithManualAnchor = useCallback(() => {
    const value = parseInt(manualAnchorValue, 10);
    if (Number.isNaN(value) || value < 0 || !vtxoData.trim()) {
      setVerificationError('Enter a valid non-negative sats value.');
      return;
    }
    setVerificationError(null);
    setL1Status('unknown');
    try {
      const parsed = JSON.parse(vtxoData) as VtxoInputJson;
      setLastAuditInputValue(value);
      setLastAuditOutputSum(computeOutputSumFromIngredients(parsed.reconstruction_ingredients));
    } catch {
      // ignore
    }
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
  const showManualAnchorFallback =
    shouldShowResults && phase === 'fetch_failed' && !isTestMode;

  const anchorData = (() => {
    try {
      if (!vtxoData.trim()) return null;
      const parsed = JSON.parse(vtxoData) as VtxoInputJson;
      return extractAnchorData(parsed.reconstruction_ingredients, isTestMode);
    } catch {
      return null;
    }
  })();
  const anchorTxid = anchorData?.txid ?? '';

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 py-8 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-2 text-gray-900 dark:text-white">
            VTXO Inspector
          </h1>
          <div className="flex items-center justify-center gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
            <span>
              VTXO Engine: <span className="font-semibold">{engineStatus}</span>
            </span>
            {isTestMode && <MockDataBadge />}
          </div>
          {/* Test Mode Toggle */}
          <div className="flex items-center justify-center gap-3">
            <button
              id="test-mode-toggle"
              type="button"
              onClick={handleToggleTestMode}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                isTestMode ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600'
              }`}
              aria-label="Toggle test mode"
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  isTestMode ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
            <label htmlFor="test-mode-toggle" className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Test Mode
            </label>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 space-y-6 mb-6">
          {isTestMode && (
            <div className="space-y-4">
              <VectorPillGroup
                title="Ark Labs Group (Variant 0x04)"
                vectors={ARK_LABS_VECTORS}
                accentColor="blue"
                selectedVectorId={selectedVectorId}
                onSelectVector={handleVectorSelect}
              />
              <VectorPillGroup
                title="Second Tech Group (Variant 0x03)"
                vectors={SECOND_VECTORS}
                accentColor="purple"
                selectedVectorId={selectedVectorId}
                onSelectVector={handleVectorSelect}
              />
            </div>
          )}
          <VTXOInput
            value={vtxoData}
            onChange={handleVtxoDataChange}
            readOnly={isTestMode}
          />

          {shouldShowResults && (
            <div className="space-y-4">
              <ProgressiveVerificationBadge
                phase={phase}
                errorMessage={verificationError}
                issuer={verifyResult?.variant}
                l1Status={l1Status}
              />

              {phase === 'error' &&
                (lastAuditInputValue !== null || lastAuditOutputSum !== null) && (
                  <div
                    className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg space-y-2"
                    role="region"
                    aria-label="Audit Ledger"
                  >
                    <h3 className="text-sm font-semibold text-red-800 dark:text-red-200">
                      Audit Ledger
                    </h3>
                    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm text-red-700 dark:text-red-300">
                      <div>
                        <dt className="font-medium">Input value</dt>
                        <dd>
                          {lastAuditInputValue !== null
                            ? `${lastAuditInputValue.toLocaleString()} sats`
                            : '—'}
                          {lastAuditInputValue !== null && (
                            <span className="text-red-600 dark:text-red-400 ml-1">
                              (from blockchain or manual)
                            </span>
                          )}
                        </dd>
                      </div>
                      <div>
                        <dt className="font-medium">Output sum</dt>
                        <dd>
                          {lastAuditOutputSum !== null
                            ? `${lastAuditOutputSum.toLocaleString()} sats`
                            : '—'}
                          {lastAuditOutputSum !== null && (
                            <span className="text-red-600 dark:text-red-400 ml-1">
                              (calculated from JSON)
                            </span>
                          )}
                        </dd>
                      </div>
                    </dl>
                  </div>
                )}

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
            </div>
          )}
        </div>

        {/* Sovereignty Map */}
        {phase === 'sovereign_complete' && verifyResult && (
          <>
            {(() => {
              const raw = verifyResult.path_details;
              const pathDetailsArray = Array.isArray(raw)
                ? raw
                : raw && typeof raw === 'object'
                  ? Object.keys(raw)
                      .filter((k) => /^\d+$/.test(k))
                      .sort((a, b) => Number(a) - Number(b))
                      .map((k) => (raw as Record<string, PathDetail>)[k])
                  : [];
              const hasPathDetails = pathDetailsArray.length > 0;
              return hasPathDetails ? (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
                  <SovereigntyMap
                    pathDetails={pathDetailsArray}
                    anchorTxid={anchorTxid}
                    finalVtxoId={verifyResult.reconstructed_tx_id}
                    variant={verifyResult.variant}
                  />
                </div>
              ) : (
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Note:</strong> Path details not available. The WASM module needs to be rebuilt to include path_details.
                  <br />
                  <br />
                  Current result: <code className="bg-yellow-100 dark:bg-yellow-900/40 px-2 py-1 rounded text-xs">
                    {JSON.stringify({ has_path_details: 'path_details' in verifyResult, path_details_type: typeof verifyResult.path_details, path_details_length: verifyResult.path_details?.length })}
                  </code>
                  <br />
                  <br />
                  Run: <code className="bg-yellow-100 dark:bg-yellow-900/40 px-2 py-1 rounded">cd wasm-vpack && wasm-pack build --target web && cd ../verifier-web && npm run wasm:sync</code>
                </p>
              </div>
              );
            })()}
          </>
        )}
      </div>
    </div>
  );
}

function App() {
  return (
    <TestModeProvider>
      <AppContent />
    </TestModeProvider>
  );
}

export default App;
