import { useEffect, useState } from 'react';
import { BoxSelect, Fuel, Clock } from 'lucide-react';
import type { PathDetail } from '../types/verification';
import { fetchRecommendedFee, DEFAULT_FEE_RATE_SATS_VB } from '../services/mempool';
import {
  formatBlocksAsDays,
  satsToBtc,
  SATS_BTC_HOVER_THRESHOLD,
  SWEEP_TX_WEIGHT,
} from '../utils/exitData';

interface ExitDataProps {
  pathDetails: PathDetail[];
  isTestMode: boolean;
  /** Optional content to render on the far right (e.g. Preview Claim Process button). */
  trailingContent?: React.ReactNode;
  /** When true, pins the bar to the bottom of the viewport as a sticky HUD. */
  sticky?: boolean;
}

/** Extracts exit_delta from a PathDetail. Supports snake_case (WASM) and camelCase. */
function getExitDelta(p: PathDetail | undefined): number {
  if (!p) return 0;
  const v = p.exit_delta ?? p.exitDelta;
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

function computeExitAggregates(pathDetails: PathDetail[]): {
  txCount: number;
  totalWeightVb: number;
  exitDeltaBlocks: number;
} {
  if (pathDetails.length === 0) {
    return { txCount: 0, totalWeightVb: 0, exitDeltaBlocks: 0 };
  }
  const pathWeightVb = pathDetails.reduce((sum, p) => sum + (p.exit_weight_vb ?? 0), 0);
  const totalWeightVb = pathWeightVb + SWEEP_TX_WEIGHT;
  const leaf = pathDetails.find((p) => p.is_leaf === true) ?? pathDetails[pathDetails.length - 1];
  const exitDeltaBlocks = getExitDelta(leaf);
  const txCount = pathDetails.length;
  return { txCount, totalWeightVb, exitDeltaBlocks };
}

const SECTION_BASE_CLASSES =
  'flex items-center gap-3 px-4 py-3 flex-1 min-w-0 justify-center';

function ExitData({ pathDetails, isTestMode, trailingContent, sticky = false }: ExitDataProps) {
  const [fetchedFeeRate, setFetchedFeeRate] = useState<number | null>(null);
  const feeRateSatsVb = isTestMode ? DEFAULT_FEE_RATE_SATS_VB : (fetchedFeeRate ?? DEFAULT_FEE_RATE_SATS_VB);

  const { txCount, totalWeightVb, exitDeltaBlocks } = computeExitAggregates(
    pathDetails
  );

  const estimatedFeeSats = Math.round(totalWeightVb * feeRateSatsVb);

  useEffect(() => {
    if (isTestMode) return;
    let cancelled = false;
    fetchRecommendedFee().then((rate) => {
      if (!cancelled && rate !== null) {
        setFetchedFeeRate(rate);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [isTestMode]);

  if (pathDetails.length === 0) {
    return null;
  }

  const containerClasses = [
    'flex flex-col sm:flex-row gap-0 overflow-hidden bg-slate-800/80 border-slate-600/50',
    sticky
      ? 'fixed bottom-0 left-0 right-0 z-50 backdrop-blur-md border-t border-slate-700 rounded-t-xl'
      : 'w-full rounded-xl border',
  ].join(' ');

  const inner = (
    <>
      <div className={`${SECTION_BASE_CLASSES} border-b last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0 border-slate-600/50`}>
        <BoxSelect className="w-5 h-5 text-cyan-400 shrink-0" />
        <span className="text-slate-200 text-sm font-medium truncate">
          {txCount} Transaction{txCount !== 1 ? 's' : ''} to Exit
        </span>
      </div>
      <div className={`${SECTION_BASE_CLASSES} border-b last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0 border-slate-600/50`}>
        <Fuel className="w-5 h-5 text-amber-400 shrink-0" />
        <span
          className="text-slate-200 text-sm font-medium truncate"
          title={estimatedFeeSats >= SATS_BTC_HOVER_THRESHOLD ? satsToBtc(estimatedFeeSats) : undefined}
        >
          {estimatedFeeSats.toLocaleString()} sats Estimated Fee
        </span>
      </div>
      <div className={`${SECTION_BASE_CLASSES} border-b last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0 border-slate-600/50`}>
        <Clock className="w-5 h-5 text-emerald-400 shrink-0" />
        <span className="text-slate-200 text-sm font-medium truncate">
          Wait: {exitDeltaBlocks} blocks ({formatBlocksAsDays(exitDeltaBlocks)})
        </span>
      </div>
      {trailingContent && (
        <div className="flex items-center justify-end px-4 py-3 shrink-0 border-t sm:border-t-0 sm:border-l border-slate-600/50">
          {trailingContent}
        </div>
      )}
    </>
  );

  return (
    <div className={containerClasses}>
      {sticky ? <div className="max-w-6xl mx-auto w-full flex flex-col sm:flex-row">{inner}</div> : inner}
    </div>
  );
}

export default ExitData;
