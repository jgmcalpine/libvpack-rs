import { useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import initWasm, {
  init as setPanicHook,
  wasm_compute_vtxo_id,
  wasm_export_to_vpack,
  wasm_parse_vpack_header,
  wasm_unpack_to_json,
  wasm_verify,
} from './wasm/wasm_vpack';
import ExportToVpackButton from './components/ExportToVpackButton';
import HeroHeader from './components/HeroHeader';
import ModeTabs, { type AppMode } from './components/ModeTabs';
import ScenarioDescriptionCard, { type VerificationStatus } from './components/ScenarioDescriptionCard';
import ZeroStateCard from './components/ZeroStateCard';
import ScenarioPicker from './components/ScenarioPicker';
import SecureInput from './components/SecureInput';
import SovereigntyPath from './components/SovereigntyPath';
import ExitData from './components/ExitData';
import { ARK_LABS_VECTORS, SECOND_VECTORS } from './constants/vectors';
import type { VectorEntry } from './constants/vectors';
import { TestModeProvider, useTestMode } from './contexts/TestModeContext';
import useTypingEffect from './hooks/useTypingEffect';
import { fetchTxVoutValue } from './services/mempool';
import {
  buildVpackFilename,
  downloadVpackBytes,
} from './utils/exportVpack';
import {
  computeOutputSumFromIngredients,
  extractAnchorData,
  parseParentOutpoint,
  type PathDetail,
  type VerificationPhase,
  type VerifyResult,
  type VtxoInputJson,
} from './types/verification';
import { pathDetailsToTreeData } from './types/arkTree';

type EngineStatus = 'Loading' | 'Ready' | 'Error';

const SCENARIO_GROUPS = [
  {
    title: 'Ark Labs',
    vectors: ARK_LABS_VECTORS,
    accentColor: 'arkLabs' as const,
  },
  {
    title: 'Second Tech',
    vectors: SECOND_VECTORS,
    accentColor: 'secondTech' as const,
  },
];

/** Pass anchor as string to WASM to avoid JS 53-bit integer precision issues. */
function injectAnchorValue(json: string, anchorValue: number | string): string {
  const parsed = JSON.parse(json) as VtxoInputJson;
  const valueForWasm = typeof anchorValue === 'number' ? String(anchorValue) : anchorValue;
  const withAnchor = { ...parsed, anchor_value: valueForWasm };
  return JSON.stringify(withAnchor);
}

function AppContent() {
  const { setTestMode } = useTestMode();
  const [mode, setMode] = useState<AppMode>('demo');
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('Loading');
  const [vtxoData, setVtxoData] = useState('');
  const [selectedVectorId, setSelectedVectorId] = useState<string | null>(null);
  const [typingTarget, setTypingTarget] = useState<string | null>(null);
  const [verificationStatus, setVerificationStatus] = useState<VerificationStatus>('idle');
  const [treeRevealed, setTreeRevealed] = useState(false);
  const [phase, setPhase] = useState<VerificationPhase>('calculating');
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [manualAnchorValue, setManualAnchorValue] = useState('');
  const [, setL1Status] = useState<'verified' | 'unknown' | 'mock' | 'anchor_not_found' | null>(null);
  const [lastAuditInputValue, setLastAuditInputValue] = useState<number | null>(null);
  const [lastAuditOutputSum, setLastAuditOutputSum] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sovereigntyRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<number | null>(null);

  const [typedDisplay] = useTypingEffect({
    targetText: typingTarget ?? '',
    enabled: mode === 'demo' && !!typingTarget,
    charDelayMs: 2,
    charsPerTick: 8,
  });

  const isTestMode = mode === 'demo';
  const effectiveVtxoData = mode === 'demo' && typingTarget ? typedDisplay : vtxoData;

  useEffect(() => {
    setTestMode(isTestMode);
  }, [isTestMode, setTestMode]);

  useEffect(() => {
    if (mode === 'demo' && selectedVectorId) {
      setVerificationStatus('verifying');
      const t = setTimeout(() => setVerificationStatus('verified'), 600);
      return () => clearTimeout(t);
    }
    setVerificationStatus('idle');
  }, [mode, selectedVectorId]);

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

  const clearInvalidStates = useCallback(() => {
    setVerifyResult(null);
    setManualAnchorValue('');
    setLastAuditInputValue(null);
    setLastAuditOutputSum(null);
    setVerificationError(null);
    setL1Status(null);
    setPhase('calculating');
  }, []);

  const handleModeChange = useCallback((newMode: AppMode) => {
    setMode(newMode);
    setVtxoData('');
    setSelectedVectorId(null);
    setTypingTarget(null);
    setTreeRevealed(false);
    clearInvalidStates();
  }, [clearInvalidStates]);

  const handleClearAll = useCallback(() => {
    setVtxoData('');
    setSelectedVectorId(null);
    setTypingTarget(null);
    setTreeRevealed(false);
    clearInvalidStates();
  }, [clearInvalidStates]);

  const handleVtxoDataChange = useCallback(
    (newValue: string) => {
      setVtxoData(newValue);
      setSelectedVectorId(null);
      setTypingTarget(null);
      clearInvalidStates();
    },
    [clearInvalidStates],
  );

  const handleVectorSelect = useCallback(
    (vector: VectorEntry) => {
      clearInvalidStates();
      setTypingTarget(vector.getJson());
      setSelectedVectorId(vector.id);
      setTreeRevealed(false);
    },
    [clearInvalidStates],
  );

  const handleImportVpack = useCallback(() => {
    if (engineStatus !== 'Ready' || !fileInputRef.current) return;
    fileInputRef.current.click();
  }, [engineStatus]);

  const processVpackFile = useCallback(
    async (file: File) => {
      if (engineStatus !== 'Ready') return;

      clearInvalidStates();
      setVerificationError(null);
      setPhase('calculating');

      let bytes: ArrayBuffer;
      try {
        bytes = await file.arrayBuffer();
      } catch {
        setVerificationError('Failed to read file.');
        setPhase('error');
        return;
      }

      const vpackBytes = new Uint8Array(bytes);

      let headerResult: { is_testnet: boolean };
      try {
        headerResult = wasm_parse_vpack_header(vpackBytes) as {
          anchor_txid: string;
          anchor_vout: number;
          tx_variant: string;
          is_testnet: boolean;
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setVerificationError(msg.startsWith('Error:') ? msg : `Error: ${msg}`);
        setPhase('error');
        return;
      }

      if (headerResult.is_testnet) {
        setMode('demo');
      }

      let jsonStr: string;
      try {
        jsonStr = wasm_unpack_to_json(vpackBytes);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setVerificationError(msg.startsWith('Error:') ? msg : `Error: ${msg}`);
        setPhase('error');
        return;
      }

      setVtxoData(jsonStr);
      setSelectedVectorId(null);
      setTypingTarget(null);
    },
    [engineStatus, clearInvalidStates],
  );

  const handleFileSelected = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      event.target.value = '';
      if (file) processVpackFile(file);
    },
    [processVpackFile],
  );

  const handleFileDrop = useCallback(
    (file: File) => processVpackFile(file),
    [processVpackFile],
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
      anchorValue = outputSum > 0 ? outputSum : 1100;
      setL1Status('mock');
      setLastAuditInputValue(anchorValue);
      setLastAuditOutputSum(outputSum);
    } else {
      const outpointStr =
        parsed.reconstruction_ingredients.parent_outpoint ??
        parsed.reconstruction_ingredients.anchor_outpoint;
      const outpoint = parseParentOutpoint(outpointStr);
      if (!outpoint) {
        setVerificationError('Invalid parent_outpoint or anchor_outpoint; enter anchor value manually.');
        setPhase('fetch_failed');
        return;
      }
      const fetchedAnchor = await fetchTxVoutValue(outpoint.txid, outpoint.voutIndex);
      if (fetchedAnchor !== null) {
        anchorValue = fetchedAnchor;
        setL1Status('verified');
      } else {
        anchorValue = outputSum > 0 ? outputSum : 1100;
        setL1Status('anchor_not_found');
      }
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

  const isExportEnabled =
    verifyResult?.status === 'Success' &&
    phase === 'sovereign_complete' &&
    effectiveVtxoData.trim().length > 0;

  const handleExportToVpack = useCallback(() => {
    if (!isExportEnabled || !verifyResult || !effectiveVtxoData.trim()) return;
    try {
      const bytes = wasm_export_to_vpack(effectiveVtxoData);
      const filename = buildVpackFilename(
        verifyResult.variant,
        verifyResult.reconstructed_tx_id,
      );
      downloadVpackBytes(bytes, filename);
    } catch (err) {
      setVerificationError(err instanceof Error ? err.message : String(err));
    }
  }, [isExportEnabled, verifyResult, effectiveVtxoData]);

  const handleVerifyWithManualAnchor = useCallback(() => {
    const value = parseInt(manualAnchorValue, 10);
    if (Number.isNaN(value) || value < 0 || !effectiveVtxoData.trim()) {
      setVerificationError('Enter a valid non-negative sats value.');
      return;
    }
    setVerificationError(null);
    setL1Status('unknown');
    try {
      const parsed = JSON.parse(effectiveVtxoData) as VtxoInputJson;
      setLastAuditInputValue(value);
      setLastAuditOutputSum(computeOutputSumFromIngredients(parsed.reconstruction_ingredients));
    } catch {
      // ignore
    }
    try {
      const jsonWithAnchor = injectAnchorValue(effectiveVtxoData, value);
      const result = wasm_verify(jsonWithAnchor) as VerifyResult;
      setVerifyResult(result);
      setPhase('sovereign_complete');
    } catch (err) {
      setVerificationError(err instanceof Error ? err.message : String(err));
      setPhase('error');
    }
  }, [manualAnchorValue, effectiveVtxoData]);

  const handleVisualizePath = useCallback(() => {
    setTreeRevealed(true);
    requestAnimationFrame(() => {
      sovereigntyRef.current?.scrollIntoView({ behavior: 'smooth' });
    });
  }, []);

  useEffect(() => {
    if (engineStatus !== 'Ready' || !effectiveVtxoData.trim()) {
      return;
    }

    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
    }

    timeoutRef.current = window.setTimeout(() => {
      runProgressiveVerification(effectiveVtxoData);
    }, 300);

    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [effectiveVtxoData, engineStatus, runProgressiveVerification]);

  const shouldShowResults = engineStatus === 'Ready' && effectiveVtxoData.trim();
  const showManualAnchorFallback =
    shouldShowResults && phase === 'fetch_failed' && !isTestMode;
  const canVisualize =
    phase === 'sovereign_complete' &&
    verifyResult &&
    (mode === 'audit' || verificationStatus === 'verified');

  const anchorData = (() => {
    try {
      if (!effectiveVtxoData.trim()) return null;
      const parsed = JSON.parse(effectiveVtxoData) as VtxoInputJson;
      return extractAnchorData(parsed.reconstruction_ingredients, isTestMode);
    } catch {
      return null;
    }
  })();
  const anchorTxid = anchorData?.txid ?? '';

  const demoSecondaryActions = (
    <>
      <ExportToVpackButton
        variant="ghost"
        disabled={!isExportEnabled}
        onExport={handleExportToVpack}
      />
      {effectiveVtxoData.trim() && (
        <button
          type="button"
          onClick={handleClearAll}
          className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:underline focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 rounded"
        >
          Clear
        </button>
      )}
    </>
  );

  const demoContent = (
    <div className="space-y-4">
      <ScenarioPicker
        scenarioGroups={SCENARIO_GROUPS}
        selectedVectorId={selectedVectorId}
        onSelectVector={handleVectorSelect}
      />
      <AnimatePresence mode="wait">
        {!selectedVectorId ? (
          <motion.div
            key="zero-state"
            initial={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <ZeroStateCard />
          </motion.div>
        ) : (
          <motion.div
            key="content"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.2 }}
            className="space-y-4"
          >
            <ScenarioDescriptionCard
              selectedVectorId={selectedVectorId}
              showLocalTestDataTag
              verificationStatus={verificationStatus}
            />
            <SecureInput
              value={effectiveVtxoData}
              onChange={handleVtxoDataChange}
              readOnly
              collapsible
              secondaryActions={demoSecondaryActions}
              showHelpIcon
            />
            <div className="space-y-3">
              <button
                type="button"
                onClick={handleVisualizePath}
                disabled={!canVisualize}
                className={`w-full py-3.5 rounded-lg font-semibold text-base transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 ${
                  canVisualize
                    ? 'bg-violet-600 hover:bg-violet-700 text-white shadow-lg shadow-violet-500/25 cursor-pointer visualize-pulse-violet'
                    : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
                }`}
              >
                Visualize Path
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      {phase === 'error' && verificationError && (
        <div
          className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg space-y-2"
          role="alert"
        >
          <p className="text-sm text-red-700 dark:text-red-300">{verificationError}</p>
          {(lastAuditInputValue !== null || lastAuditOutputSum !== null) && (
            <>
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
            </>
          )}
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
  );

  const auditSecondaryActions = (
    <>
      <ExportToVpackButton
        variant="ghost"
        disabled={!isExportEnabled}
        onExport={handleExportToVpack}
      />
      {effectiveVtxoData.trim() && (
        <button
          type="button"
          onClick={handleClearAll}
          className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:underline focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 rounded"
        >
          Clear
        </button>
      )}
    </>
  );

  const auditContent = (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Paste your VTXO data or import a V-PACK to verify your specific funds. No data leaves your browser.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={handleImportVpack}
          disabled={engineStatus !== 'Ready'}
          className="px-4 py-2 bg-emerald-100 dark:bg-emerald-900/40 hover:bg-emerald-200 dark:hover:bg-emerald-900/60 disabled:opacity-50 disabled:cursor-not-allowed text-emerald-800 dark:text-emerald-200 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 border border-emerald-300 dark:border-emerald-700"
        >
          Import V-PACK
        </button>
      </div>
      <SecureInput
        value={effectiveVtxoData}
        onChange={handleVtxoDataChange}
        readOnly={false}
        onFileDrop={handleFileDrop}
        collapsible
        secondaryActions={auditSecondaryActions}
        showHelpIcon
      />
      <div className="space-y-3">
        <button
            type="button"
            onClick={handleVisualizePath}
            disabled={!canVisualize}
            className={`w-full py-3.5 rounded-lg font-semibold text-base transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 ${
              canVisualize
                ? 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-lg shadow-emerald-500/25 cursor-pointer visualize-pulse-emerald'
                : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
            }`}
          >
            Visualize Path
          </button>
      </div>
      {phase === 'error' && verificationError && (
        <div
          className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg space-y-2"
          role="alert"
        >
          <p className="text-sm text-red-700 dark:text-red-300">{verificationError}</p>
          {(lastAuditInputValue !== null || lastAuditOutputSum !== null) && (
            <>
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
            </>
          )}
        </div>
      )}
      {showManualAnchorFallback && (
        <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg space-y-3">
          <label htmlFor="manual-anchor-audit" className="block text-sm font-medium text-amber-800 dark:text-amber-200">
            L1 anchor value (sats)
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <input
              id="manual-anchor-audit"
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
  );

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 py-8 px-4">
      <input
        ref={fileInputRef}
        type="file"
        accept=".vpk"
        onChange={handleFileSelected}
        className="hidden"
        aria-hidden
      />
      <div className="max-w-6xl mx-auto">
        <HeroHeader
          title="Ark Sovereign Audit"
          subtitle="Verify your off-chain Bitcoin. Simulate your exit path. Trust code, not providers."
        />

        <div
          className={`rounded-lg shadow-lg p-6 space-y-6 mb-6 transition-colors ${
            mode === 'demo'
              ? 'bg-white dark:bg-gray-800 border border-violet-200 dark:border-violet-800/50'
              : 'bg-white dark:bg-gray-800 border border-emerald-200 dark:border-emerald-800/50'
          }`}
        >
          <ModeTabs
            mode={mode}
            onModeChange={handleModeChange}
            demoContent={demoContent}
            auditContent={auditContent}
          />
        </div>

        <div ref={sovereigntyRef}>
          {treeRevealed && phase === 'sovereign_complete' && verifyResult && (
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            >
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
                const treeData = pathDetailsToTreeData(
                  pathDetailsArray,
                  anchorTxid,
                  verifyResult.reconstructed_tx_id
                );
                return hasPathDetails && treeData ? (
                  <div className="space-y-4">
                    <SovereigntyPath
                      treeData={treeData}
                      variant={verifyResult.variant}
                      network={isTestMode ? 'Signet' : 'Mainnet'}
                      blockHeight={isTestMode ? 850_000 : undefined}
                    />
                    <ExitData
                      pathDetails={pathDetailsArray}
                      isTestMode={isTestMode}
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
            </motion.div>
          )}
        </div>
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
