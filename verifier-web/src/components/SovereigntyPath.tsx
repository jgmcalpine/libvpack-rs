import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Bitcoin,
  CheckCircle2,
  Landmark,
  Waypoints,
  ShieldCheck,
  Loader2,
  X,
} from 'lucide-react';
import type { TreeData, ArkNode } from '../types/arkTree';
import GlassCard from './GlassCard';
import PulsingLine from './PulsingLine';
import AnimatedGrid from './AnimatedGrid';
import NodeDetailModal from './NodeDetailModal';
import ExitData from './ExitData';
import SettlementToken from './SettlementToken';
import type { PathDetail } from '../types/verification';

const AUDIT_STEP_DURATION_MS = 600;
const LINE_HEIGHT = 48;
const EXIT_PHASE_DURATION_MS = 3000;
const DETACHMENT_DELAY_MS = 500;

type SimulationPhase = 'idle' | 'verifying_up' | 'settling_down' | 'completed';

interface SovereigntyPathProps {
  treeData: TreeData;
  pathDetails: PathDetail[];
  isTestMode: boolean;
  variant?: string;
  network?: string;
  blockHeight?: number;
  onLoadComplete?: () => void;
}

type SelectedNodeInfo = { node: PathDetail; nodeType: 'anchor' | 'branch' | 'vtxo' };

function SovereigntyPath({
  treeData,
  pathDetails,
  isTestMode,
  variant = '',
  network = 'Mainnet',
  blockHeight,
  onLoadComplete,
}: SovereigntyPathProps) {
  const [auditStep, setAuditStep] = useState(0);
  const [loadComplete, setLoadComplete] = useState(false);
  const [selectedNodeInfo, setSelectedNodeInfo] = useState<SelectedNodeInfo | null>(null);
  const [exitPhase, setExitPhase] = useState(0);
  const [phaseStatus, setPhaseStatus] = useState<'idle' | 'confirming' | 'mined'>('idle');
  const [simulationPhase, setSimulationPhase] = useState<SimulationPhase>('idle');
  const [isSimulating, setIsSimulating] = useState(false);
  const [hasCompletedSimulation, setHasCompletedSimulation] = useState(false);
  const [settlementPositions, setSettlementPositions] = useState<{
    startY: number;
    endY: number;
    containerWidth: number;
  } | null>(null);
  const [hudDismissed, setHudDismissed] = useState(false);
  const isSimulatingRef = useRef(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const rootCardRef = useRef<HTMLDivElement>(null);
  const rootContentRef = useRef<HTMLDivElement>(null);
  const leafRef = useRef<HTMLDivElement>(null);
  const treeContainerRef = useRef<HTMLDivElement>(null);

  const { l1Anchor, branches, userVtxo } = treeData;
  const auditTotalSteps = 2 + branches.length * 2 + 2;
  const maxAuditStep = auditTotalSteps - 1;
  const exitStepCount = 2 + branches.length;

  useEffect(() => {
    if (auditStep >= maxAuditStep) {
      queueMicrotask(() => {
        setLoadComplete(true);
        onLoadComplete?.();
      });
      return;
    }
    const t = setTimeout(
      () => setAuditStep((s) => Math.min(s + 1, maxAuditStep)),
      AUDIT_STEP_DURATION_MS
    );
    return () => clearTimeout(t);
  }, [auditStep, maxAuditStep, onLoadComplete]);

  const handleSettlementComplete = useCallback(() => {
    if ('vibrate' in navigator) {
      navigator.vibrate([50, 30, 50]);
    }
    setSimulationPhase('completed');
    isSimulatingRef.current = false;
    setIsSimulating(false);
    setHasCompletedSimulation(true);
  }, []);

  const handleSimulateExit = useCallback(() => {
    if (isSimulatingRef.current) return;
    isSimulatingRef.current = true;
    setIsSimulating(true);
    setSimulationPhase('verifying_up');
    setSettlementPositions(null);
    setHudDismissed(false);

    const timeouts: ReturnType<typeof setTimeout>[] = [];
    for (let step = 1; step <= exitStepCount; step += 1) {
      const enterAt = EXIT_PHASE_DURATION_MS * (step - 1);
      timeouts.push(
        setTimeout(() => {
          setExitPhase(step);
          setPhaseStatus('confirming');
        }, enterAt)
      );
      timeouts.push(
        setTimeout(() => setPhaseStatus('mined'), enterAt + 800)
      );
    }

    const leafMinedAt = EXIT_PHASE_DURATION_MS * (exitStepCount - 1) + 800;
    timeouts.push(
      setTimeout(() => {
        setSimulationPhase('settling_down');
      }, leafMinedAt + DETACHMENT_DELAY_MS)
    );

    setExitPhase(1);
    setPhaseStatus('confirming');
    rootRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return () => timeouts.forEach(clearTimeout);
  }, [exitStepCount]);

  useLayoutEffect(() => {
    const rootMeasureEl = rootContentRef.current ?? rootCardRef.current ?? rootRef.current;
    if (simulationPhase !== 'settling_down' || !leafRef.current || !rootMeasureEl || !treeContainerRef.current) {
      return;
    }
    const containerRect = treeContainerRef.current.getBoundingClientRect();
    const leafRect = leafRef.current.getBoundingClientRect();
    const rootRect = rootMeasureEl.getBoundingClientRect();
    const startY = leafRect.top + leafRect.height / 2 - containerRect.top;
    const endY = rootRect.top + rootRect.height / 2 - containerRect.top;
    setSettlementPositions({
      startY,
      endY,
      containerWidth: containerRect.width,
    });
  }, [simulationPhase]);

  const openNodeModal = useCallback((node: ArkNode) => {
    setSelectedNodeInfo({ node: node.pathDetail, nodeType: node.type });
  }, []);

  const rootVisible = auditStep >= 0;
  const lineToFirstBranchVisible = auditStep >= 1;
  const branchVisible = (i: number) => auditStep >= 2 + i * 2;
  const lineBetweenBranchesVisible = (i: number) => auditStep >= 3 + i * 2;
  const lineToFruitVisible = auditStep >= 2 + branches.length * 2;
  const fruitVisible = auditStep >= maxAuditStep;

  const rootHighlighted = exitPhase === 1;
  const rootDimmed = exitPhase > 1 && simulationPhase !== 'settling_down';
  const rootSettled = simulationPhase === 'completed';
  const branchHighlighted = (i: number) => exitPhase === 2 + i;
  const branchDimmed = (i: number) => exitPhase !== 2 + i && exitPhase > 0;
  const leafHighlighted = exitPhase === exitStepCount && simulationPhase !== 'settling_down';
  const leafDimmed =
    (exitPhase < exitStepCount && exitPhase > 0) || simulationPhase === 'settling_down';

  const connectorFillProgress = (connectorIndex: number) =>
    exitPhase === 0 ? 1 : exitPhase >= connectorIndex + 2 ? 1 : 0;
  const connectorBranchToLeafFillProgress = connectorFillProgress(branches.length);

  const isChainComplete = exitPhase === exitStepCount;

  const getStepLabel = (step: number): string => {
    if (step === 1) return 'Broadcast Anchor Transaction to L1.';
    if (step === exitStepCount) return 'Broadcast Final Leaf Transaction.';
    return `Broadcast Branch Transaction (${step - 1} of ${branches.length}).`;
  };

  return (
    <div className="relative min-h-[480px] rounded-2xl overflow-hidden bg-gradient-to-b from-slate-900 to-black">
      <AnimatedGrid />

      <div className="relative z-10 p-4 sm:p-8 pt-40 pb-64 flex flex-col items-center">
        <div className="w-full max-w-2xl text-center mb-6">
          <div className="flex flex-wrap items-center justify-center gap-3">
            <h2 className="text-xl sm:text-2xl font-bold text-white">
              Custody Map
            </h2>
            {loadComplete && (
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/20 border border-emerald-400/40 text-emerald-300 text-sm font-medium">
                <CheckCircle2 className="w-4 h-4" />
                Verified by L1
              </span>
            )}
          </div>
          <p className="text-sm text-slate-400 mt-2">
            Visualizing the link between your funds and the Bitcoin blockchain.
          </p>
        </div>

        <div ref={treeContainerRef} className="relative w-full max-w-3xl">
          <div className="flex flex-col-reverse items-center gap-0 px-4 sm:px-0">
          {/* Root (Bottom) - full width, foundation */}
          <div ref={rootRef} className="w-full max-w-3xl">
          <GlassCard
            delay={0}
            visible={rootVisible}
            onClick={() => openNodeModal(l1Anchor)}
            innerRef={rootCardRef}
            className={`relative w-full p-6 bg-slate-800/60 border-slate-600/40 transition-all duration-300 ${
              rootDimmed ? 'opacity-50' : ''
            } ${rootHighlighted ? 'ring-2 ring-teal-400 shadow-[0_0_24px_rgba(20,184,166,0.3)]' : ''            } ${
              rootSettled
                ? 'ring-2 ring-amber-400 shadow-[0_0_32px_rgba(245,158,11,0.5)]'
                : ''
            }`}
          >
            {rootSettled && (
              <div
                className="absolute inset-0 flex items-center justify-center pointer-events-none z-10"
                aria-hidden
              >
                <motion.div
                  animate={{ scale: [1, 1.08, 1] }}
                  transition={{ duration: 2.5, repeat: Infinity, ease: 'easeInOut' }}
                  style={{
                    filter:
                      'drop-shadow(0 0 12px rgba(245,158,11,0.9)) drop-shadow(0 0 24px rgba(251,191,36,0.6))',
                  }}
                >
                  <Bitcoin className="w-10 h-10 text-amber-400" strokeWidth={1.5} />
                </motion.div>
              </div>
            )}
            <div ref={rootContentRef} className="flex items-center gap-4 relative z-0">
              <div className="p-2.5 rounded-lg bg-slate-700/50">
                <Landmark className="w-7 h-7 text-amber-400" />
              </div>
              <div>
                <p className="text-lg font-semibold text-white">
                  Bitcoin L1 ({network})
                </p>
                {blockHeight !== undefined && (
                  <p className="text-slate-400 text-base mt-0.5 font-mono">
                    Block #{blockHeight.toLocaleString()}
                  </p>
                )}
                {exitPhase === 1 && (
                  <p className="text-amber-400 text-sm mt-1 font-medium">
                    {phaseStatus === 'confirming' ? 'Confirming...' : 'Mined.'}
                  </p>
                )}
              </div>
              {rootVisible && (
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 400, damping: 20 }}
                  className="ml-auto"
                >
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                </motion.div>
              )}
            </div>
          </GlassCard>
          </div>

          {/* Protocol zone separator: gap with dashed line and labels */}
          <div className="relative w-full h-12 flex items-center justify-center">
            <div className="absolute inset-x-0 top-1/2 -translate-y-1/2 h-px border-t border-dashed border-slate-500/60" />
            <span className="absolute right-4 bottom-[100%] mb-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Off-Chain (Ark VTXO)
            </span>
            <span className="absolute right-4 top-[100%] mt-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-500">
              On-Chain (Bitcoin L1)
            </span>
          </div>

          {/* Branches (Middle) - medium width */}
          {branches.map((branch, i) => (
            <div key={branch.id} className="flex flex-col-reverse items-center w-full">
              <div className="relative w-full flex justify-center -mb-1">
                <PulsingLine
                  height={LINE_HEIGHT}
                  visible={
                    i === 0
                      ? lineToFirstBranchVisible
                      : lineBetweenBranchesVisible(i - 1)
                  }
                  delay={0.1}
                  fillProgress={connectorFillProgress(i + 1)}
                />
              </div>
              <GlassCard
                delay={0.1 * (i + 1)}
                visible={branchVisible(i)}
                onClick={() => openNodeModal(branch)}
                className={`relative w-full max-w-lg p-4 transition-all duration-300 ${
                  branchDimmed(i) ? 'opacity-50' : ''
                } ${branchHighlighted(i) ? 'ring-2 ring-teal-400 shadow-[0_0_24px_rgba(20,184,166,0.3)]' : ''}`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-cyan-500/20">
                      <Waypoints className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <p className="text-white font-semibold">
                        Liquidity Provider Branch
                      </p>
                      <p className="text-cyan-300/90 text-sm mt-1 font-mono">
                        Timelock: {branch.timelock ?? '24h'}
                      </p>
                      {branchHighlighted(i) && (
                        <p className="text-teal-400 text-sm mt-1 font-medium">
                          {phaseStatus === 'confirming' ? 'Confirming...' : 'Mined.'}
                        </p>
                      )}
                    </div>
                  </div>
                  {branchVisible(i) && (
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ type: 'spring', stiffness: 400, damping: 20 }}
                    >
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    </motion.div>
                  )}
                </div>
              </GlassCard>
            </div>
          ))}

          {branches.length === 0 ? (
            <div className="w-full flex justify-center -mb-1">
              <PulsingLine
                height={LINE_HEIGHT}
                visible={lineToFirstBranchVisible}
                delay={0.1}
                fillProgress={connectorBranchToLeafFillProgress}
              />
            </div>
          ) : (
            <div className="w-full flex justify-center -mb-1">
              <PulsingLine
                height={LINE_HEIGHT}
                visible={lineToFruitVisible}
                delay={0.1}
                fillProgress={connectorBranchToLeafFillProgress}
              />
            </div>
          )}

          {/* Leaf (Top) - narrow width */}
          <div ref={leafRef} className="w-full max-w-xs">
          <GlassCard
            delay={0.2}
            visible={fruitVisible}
            onClick={() => openNodeModal(userVtxo)}
            className={`relative w-full p-5 border-emerald-500/30 transition-all duration-300 ${
              leafDimmed ? 'opacity-50' : ''
            } ${leafHighlighted ? 'ring-2 ring-teal-400 shadow-[0_0_32px_rgba(20,184,166,0.4)]' : 'shadow-[0_0_24px_rgba(16,185,129,0.15)]'}
            ${isChainComplete ? 'shadow-[0_0_32px_rgba(20,184,166,0.4)]' : ''}`}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/20">
                  <ShieldCheck className="w-6 h-6 text-emerald-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {userVtxo.amountSats?.toLocaleString() ?? '—'} sats
                  </p>
                  <span className="inline-block mt-1 px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-medium">
                    Unspent
                  </span>
                  {leafHighlighted && (
                    <p className="text-emerald-400 text-sm mt-1 font-medium">
                      {phaseStatus === 'confirming' ? 'Confirming...' : 'Mined.'}
                    </p>
                  )}
                </div>
              </div>
              {fruitVisible && (
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 400, damping: 20 }}
                  className="flex-shrink-0"
                >
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                </motion.div>
              )}
            </div>
          </GlassCard>
          </div>
          </div>

          {settlementPositions && (
            <SettlementToken
              startY={settlementPositions.startY}
              endY={settlementPositions.endY}
              containerWidth={settlementPositions.containerWidth}
              nodeCount={2 + branches.length}
              onComplete={handleSettlementComplete}
              isActive={simulationPhase === 'settling_down' || simulationPhase === 'completed'}
              hasArrived={simulationPhase === 'completed'}
            />
          )}
        </div>

        <ExitData
          pathDetails={pathDetails}
          isTestMode={isTestMode}
          sticky
          trailingContent={
            <button
              type="button"
              onClick={handleSimulateExit}
              disabled={isSimulating}
              className={`px-4 py-2 rounded-lg font-medium text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-slate-900 ${
                isSimulating
                  ? 'border border-slate-600 bg-slate-700/50 text-slate-400 cursor-not-allowed'
                  : 'border border-cyan-400/50 bg-transparent text-cyan-400 hover:bg-cyan-400/10 hover:border-cyan-400/70'
              }`}
            >
              {isSimulating ? (
                <span className="inline-flex items-center gap-2">
                  {simulationPhase === 'settling_down' ? (
                    <>Settling to L1...</>
                  ) : (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Simulating Step {exitPhase}...
                    </>
                  )}
                </span>
              ) : (
                <>▶ {hasCompletedSimulation ? 'Replay' : 'Preview'} Claim Process</>
              )}
            </button>
          }
        />

        {((simulationPhase === 'verifying_up' && exitPhase > 0) ||
          simulationPhase === 'settling_down' ||
          (simulationPhase === 'completed' && !hudDismissed)) && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="fixed bottom-[80px] left-4 right-4 md:left-auto md:right-6 md:w-80 z-40 p-4 rounded-xl bg-slate-800/95 border border-slate-600/40 shadow-xl"
          >
            {simulationPhase === 'settling_down' && (
              <>
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-amber-400 font-semibold text-sm">
                    Settling Funds...
                  </span>
                </div>
                <p className="text-sm text-slate-300">
                  The VTXO is claimed. Value is moving from the ephemeral Ark layer back to the Bitcoin L1 blockchain.
                </p>
              </>
            )}
            {simulationPhase === 'completed' && (
              <>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <span className="text-amber-400 font-semibold text-sm">
                    Unilateral Exit Complete
                  </span>
                  <button
                    type="button"
                    onClick={() => setHudDismissed(true)}
                    className="p-1 rounded hover:bg-slate-700/50 text-slate-400 hover:text-slate-200 transition-colors focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-2 focus:ring-offset-slate-800"
                    aria-label="Close"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <p className="text-sm text-slate-300">
                  Your {userVtxo.amountSats?.toLocaleString() ?? '—'} sats are now confirmed in a standard Bitcoin UTXO on the Main Chain. You have full custody.
                </p>
              </>
            )}
            {simulationPhase === 'verifying_up' && exitPhase > 0 && (
              <>
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-cyan-400 font-semibold text-sm">
                    Step {exitPhase} of {exitStepCount}
                  </span>
                </div>
                <p className="text-sm text-slate-300">
                  Step {exitPhase}: {getStepLabel(exitPhase)}
                </p>
                <p className="text-slate-500 text-xs mt-2">
                  Each transaction must be broadcast and confirmed on-chain before the next step.
                </p>
                {phaseStatus === 'confirming' && (
                  <p className="text-amber-400 text-xs mt-1">Confirming...</p>
                )}
                {phaseStatus === 'mined' && exitPhase < exitStepCount && (
                  <p className="text-emerald-400 text-xs mt-1">Mined. Proceeding to next step.</p>
                )}
                {phaseStatus === 'mined' && exitPhase === exitStepCount && (
                  <p className="text-emerald-400 text-xs mt-1">Funds fully realized on-chain.</p>
                )}
              </>
            )}
          </motion.div>
        )}
      </div>

      {selectedNodeInfo && (
        <NodeDetailModal
          node={selectedNodeInfo.node}
          variant={variant}
          nodeType={selectedNodeInfo.nodeType}
          network={network}
          blockHeight={blockHeight}
          onClose={() => setSelectedNodeInfo(null)}
        />
      )}
    </div>
  );
}

export default SovereigntyPath;
