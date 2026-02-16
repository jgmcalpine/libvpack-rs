import { useCallback, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Shield } from 'lucide-react';
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
import type { VectorEntry } from './constants/vectors';
import { NetworkProvider, useNetwork } from './contexts/NetworkContext';
import { TestModeProvider, useTestMode } from './contexts/TestModeContext';
import NetworkSwitcher from './components/NetworkSwitcher';
import ProgressiveVerificationBadge from './components/ProgressiveVerificationBadge';
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
import { NETWORK_LABELS } from './types/network';

type EngineStatus = 'Loading' | 'Ready' | 'Error';

/** Pass anchor as string to WASM to avoid JS 53-bit integer precision issues. */
function injectAnchorValue(json: string, anchorValue: number | string): string {
  const parsed = JSON.parse(json) as VtxoInputJson;
  const valueForWasm = typeof anchorValue === 'number' ? String(anchorValue) : anchorValue;
  const withAnchor = { ...parsed, anchor_value: valueForWasm };
  return JSON.stringify(withAnchor);
}

function AppContent() {
  const { setTestMode } = useTestMode();
  const { network, setNetwork } = useNetwork();
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
  const [l1Status, setL1Status] = useState<'verified' | 'unknown' | 'mock' | 'anchor_not_found' | null>(null);
  const [lastAuditInputValue, setLastAuditInputValue] = useState<number | null>(null);
  const [lastAuditOutputSum, setLastAuditOutputSum] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sovereigntyRef = useRef<HTMLDivElement>(null);
  const sovAuditSectionRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<number | null>(null);

  const [typedDisplay] = useTypingEffect({
    targetText: typingTarget ?? '',
    enabled: mode === 'demo' && !!typingTarget,
    charDelayMs: 2,
    charsPerTick: 8,
  });

  const isTestMode = mode === 'demo';
  const effectiveVtxoData = mode === 'demo' && typingTarget ? typedDisplay : vtxoData;
  const isDataLoading =
    mode === 'demo' && !!typingTarget && typedDisplay !== typingTarget;

  useEffect(() => {
    setTestMode(isTestMode);
  }, [isTestMode, setTestMode]);

  useEffect(() => {
    if (mode === 'demo' && selectedVectorId) {
      const t1 = setTimeout(() => setVerificationStatus('verifying'), 0);
      const t2 = setTimeout(() => setVerificationStatus('verified'), 600);
      return () => {
        clearTimeout(t1);
        clearTimeout(t2);
      };
    }
    const t = setTimeout(() => setVerificationStatus('idle'), 0);
    return () => clearTimeout(t);
  }, [mode, selectedVectorId]);

  useEffect(() => {
    if (mode === 'demo' && selectedVectorId) {
      const timer = setTimeout(() => {
        const target = sovAuditSectionRef.current;
        if (!target) return;
        const targetRect = target.getBoundingClientRect();
        const startY = window.scrollY;
        const targetY =
          startY + targetRect.top - window.innerHeight / 2 + targetRect.height / 2;
        const duration = 600;
        const startTime = performance.now();

        const easeInOutCubic = (t: number) =>
          t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2;

        const step = (now: number) => {
          const elapsed = now - startTime;
          const progress = Math.min(elapsed / duration, 1);
          const eased = easeInOutCubic(progress);
          window.scrollTo(0, startY + (targetY - startY) * eased);
          if (progress < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      }, 350);
      return () => clearTimeout(timer);
    }
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
        setVerificationError(
          'Invalid parent_outpoint or anchor_outpoint. Cannot fetch L1 anchor from network.',
        );
        setPhase('fetch_failed');
        return;
      }
      const fetchedAnchor = await fetchTxVoutValue(
        outpoint.txid,
        outpoint.voutIndex,
        network,
      );
      if (fetchedAnchor !== null) {
        anchorValue = fetchedAnchor;
        setL1Status('verified');
      } else {
        setL1Status('anchor_not_found');
        setVerificationError(
          `INVALID: Anchor not found on ${NETWORK_LABELS[network]}.`,
        );
        setLastAuditInputValue(null);
        setLastAuditOutputSum(outputSum);
        setPhase('anchor_not_found');
        try {
          const displayAnchor = outputSum > 0 ? outputSum : 1100;
          const jsonWithAnchor = injectAnchorValue(input, displayAnchor);
          const result = wasm_verify(jsonWithAnchor) as VerifyResult;
          setVerifyResult(result);
        } catch {
          setVerifyResult(null);
        }
        return;
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
  }, [isTestMode, network]);

  const isExportEnabled =
    verifyResult?.status === 'Success' &&
    phase === 'sovereign_complete' &&
    effectiveVtxoData.trim().length > 0;

  const handleExportToVpack = useCallback(() => {
    if (!isExportEnabled || !verifyResult || !effectiveVtxoData.trim()) return;
    try {
      const isTestnet = network !== 'bitcoin';
      const bytes = wasm_export_to_vpack(effectiveVtxoData, isTestnet);
      const filename = buildVpackFilename(
        verifyResult.variant,
        verifyResult.reconstructed_tx_id,
      );
      downloadVpackBytes(bytes, filename);
    } catch (err) {
      setVerificationError(err instanceof Error ? err.message : String(err));
    }
  }, [isExportEnabled, verifyResult, effectiveVtxoData, network]);

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
  }, [effectiveVtxoData, engineStatus, runProgressiveVerification, network]);

  const shouldShowResults = engineStatus === 'Ready' && effectiveVtxoData.trim();
  const showManualAnchorFallback = false;
  const canVisualize =
    (phase === 'sovereign_complete' || phase === 'anchor_not_found') &&
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
    <div className="flex flex-col gap-3 md:gap-4">
      <AnimatePresence mode="wait">
        {!selectedVectorId && (
          <motion.div
            key="zero-state"
            initial={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="order-1 md:order-2"
          >
            <ZeroStateCard />
          </motion.div>
        )}
      </AnimatePresence>
      <div className={!selectedVectorId ? 'order-2 md:order-1' : undefined}>
        <ScenarioPicker
          selectedVectorId={selectedVectorId}
          onSelectVector={handleVectorSelect}
        />
      </div>
      <AnimatePresence mode="wait">
        {selectedVectorId ? (
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
              isDataLoading={isDataLoading}
            />
            {shouldShowResults && (
              <ProgressiveVerificationBadge
                phase={phase}
                errorMessage={phase === 'error' ? verificationError : undefined}
                l1Status={l1Status}
                issuer={verifyResult?.variant}
                isTestMode
              />
            )}
            <div ref={sovAuditSectionRef} className="space-y-3">
              <button
                type="button"
                onClick={handleVisualizePath}
                disabled={!canVisualize}
                className={`w-full py-3.5 rounded-lg font-semibold text-base transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 flex flex-col items-center gap-1 ${
                  canVisualize
                    ? 'bg-violet-600 hover:bg-violet-700 text-white shadow-lg shadow-violet-500/25 cursor-pointer visualize-pulse-violet'
                    : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
                }`}
              >
                <span>Generate Sovereignty Map</span>
              </button>
              <p className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400" role="status">
                <Shield className="w-4 h-4 shrink-0 text-violet-500 dark:text-violet-400" aria-hidden />
                Sovereign Audit: All verification math performed locally in your browser via WASM. Your data never
                leaves this device.
              </p>
            </div>
          </motion.div>
        ) : null}
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
      <div className="flex flex-col gap-3">
        <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Network
        </label>
        <NetworkSwitcher network={network} onNetworkChange={setNetwork} />
      </div>
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
        isDataLoading={isDataLoading}
      />
      {shouldShowResults && (
        <ProgressiveVerificationBadge
          phase={phase}
          errorMessage={phase === 'error' ? verificationError : undefined}
          l1Status={l1Status}
          issuer={verifyResult?.variant}
          isTestMode={isTestMode}
        />
      )}
      <div className="space-y-3">
        <button
            type="button"
            onClick={handleVisualizePath}
            disabled={!canVisualize}
            className={`w-full py-3.5 rounded-lg font-semibold text-base transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 flex flex-col items-center gap-1 ${
              canVisualize
                ? 'bg-emerald-600 hover:bg-emerald-700 text-white shadow-lg shadow-emerald-500/25 cursor-pointer visualize-pulse-emerald'
                : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
            }`}
          >
            <span>Generate Sovereignty Map</span>
          </button>
          <p className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400" role="status">
            <Shield className="w-4 h-4 shrink-0 text-emerald-500 dark:text-emerald-400" aria-hidden />
            Sovereign Audit: All verification math performed locally in your browser via WASM. Your data never leaves
            this device.
          </p>
      </div>
      {(phase === 'error' || phase === 'anchor_not_found') && verificationError && (
        <div
          className="p-4 bg-red-50 dark:bg-red-900/20 border-2 border-red-300 dark:border-red-700 rounded-lg space-y-2"
          role="alert"
        >
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="inline-flex items-center px-3 py-1 rounded-full text-sm font-bold bg-red-500/20 text-red-700 dark:text-red-300 border border-red-500"
              aria-hidden
            >
              INVALID
            </span>
            <p className="text-sm font-medium text-red-700 dark:text-red-300">
              {verificationError}
            </p>
          </div>
          {phase === 'anchor_not_found' && lastAuditOutputSum !== null && (
            <p className="text-sm text-red-600 dark:text-red-400">
              Math verified ({lastAuditOutputSum.toLocaleString()} sats output sum), but the L1 anchor transaction was not found on the selected network.
            </p>
          )}
          {phase === 'error' &&
            (lastAuditInputValue !== null || lastAuditOutputSum !== null) && (
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
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 py-4 md:py-8 px-4">
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
          subtitle="Verify your off-chain Bitcoin. Simulate your exit path. Trust math, not providers."
        />

        <div
          className={`rounded-lg shadow-lg p-4 md:p-6 space-y-4 md:space-y-6 mb-4 md:mb-6 transition-colors ${
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
          {treeRevealed &&
            (phase === 'sovereign_complete' || phase === 'anchor_not_found') &&
            verifyResult && (
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
                  <div className="space-y-4 relative md:mb-8">
                    {phase === 'anchor_not_found' && (
                      <div
                        className="absolute inset-0 z-20 flex items-center justify-center bg-red-950/80 rounded-2xl pointer-events-none"
                        aria-live="assertive"
                      >
                        <div className="px-6 py-4 rounded-xl border-2 border-red-500 bg-red-900/90 text-red-100 font-bold text-lg shadow-xl">
                          WARNING: L1 LINK BROKEN
                        </div>
                      </div>
                    )}
                    <SovereigntyPath
                      treeData={treeData}
                      pathDetails={pathDetailsArray}
                      isTestMode={isTestMode}
                      variant={verifyResult.variant}
                      network={isTestMode ? 'signet' : network}
                      blockHeight={isTestMode ? 850_000 : undefined}
                      l1Broken={phase === 'anchor_not_found'}
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
      <NetworkProvider defaultNetwork="signet">
        <AppContent />
      </NetworkProvider>
    </TestModeProvider>
  );
}

export default App;
