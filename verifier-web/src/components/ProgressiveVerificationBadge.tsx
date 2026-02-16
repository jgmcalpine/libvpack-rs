import type { VerificationPhase } from '../types/verification';

export type L1Status = 'verified' | 'unknown' | 'mock' | 'anchor_not_found' | null;

interface ProgressiveVerificationBadgeProps {
  phase: VerificationPhase;
  errorMessage?: string | null;
  issuer?: string;
  l1Status?: L1Status;
  /** When true (Demo/Test Mode), show purple "Math Verified" for sovereign_complete. */
  isTestMode?: boolean;
}

type PhaseConfigKey = VerificationPhase | 'sovereign_complete_mock';

const PHASE_CONFIG: Record<
  PhaseConfigKey,
  { label: string; icon: string; className: string }
> = {
  calculating: {
    label: 'Calculating...',
    icon: '◌',
    className: 'verification-badge calculating bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600',
  },
  path_verified: {
    label: 'Path Verified',
    icon: '✓',
    className: 'verification-badge path-verified bg-amber-50 dark:bg-amber-900/30 text-amber-800 dark:text-amber-200 border-amber-300 dark:border-amber-700',
  },
  sovereign_complete: {
    label: 'Sovereign Audit Complete',
    icon: '✓',
    className:
      'verification-badge sovereign-complete bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border-green-300 dark:border-green-700',
  },
  sovereign_complete_mock: {
    label: 'Math Verified',
    icon: '✓',
    className:
      'verification-badge math-verified bg-violet-100 dark:bg-violet-900/30 text-violet-800 dark:text-violet-200 border-violet-300 dark:border-violet-700',
  },
  id_mismatch: {
    label: 'ID Mismatch',
    icon: '✗',
    className: 'verification-badge id-mismatch bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700',
  },
  error: {
    label: 'Verification Failed',
    icon: '✗',
    className: 'verification-badge error bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700',
  },
  fetch_failed: {
    label: 'L1 fetch failed',
    icon: '!',
    className: 'verification-badge fetch-failed bg-amber-50 dark:bg-amber-900/30 text-amber-800 dark:text-amber-200 border-amber-300 dark:border-amber-700',
  },
  anchor_not_found: {
    label: 'INVALID: Anchor not found',
    icon: '✗',
    className: 'verification-badge anchor-not-found bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200 border-red-400 dark:border-red-600',
  },
};

const BADGE_BASE_CLASSES = 'inline-flex items-center px-3 py-2 rounded-lg text-sm font-medium';

const L1_STATUS_LABELS: Record<NonNullable<ProgressiveVerificationBadgeProps['l1Status']>, string> = {
  verified: 'L1 Status: Verified',
  unknown: 'L1 Status: Unknown',
  mock: 'Local Test Data',
  anchor_not_found: 'Math Verified, but Anchor not found on Mainnet',
};

function ProgressiveVerificationBadge({
  phase,
  errorMessage,
  issuer,
  l1Status,
  isTestMode = false,
}: ProgressiveVerificationBadgeProps) {
  const effectivePhase: PhaseConfigKey =
    phase === 'sovereign_complete' && isTestMode ? 'sovereign_complete_mock' : phase;
  const config = PHASE_CONFIG[effectivePhase];
  const issuerLabel = issuer === '0x04' ? 'Ark Labs' : issuer === '0x03' ? 'Second Tech' : null;
  const showL1Badge =
    phase === 'sovereign_complete' && l1Status && l1Status !== 'verified';

  return (
    <div className="verification-badge-wrapper">
      <div className="flex items-center gap-3 flex-wrap">
        <div
          className={`${BADGE_BASE_CLASSES} gap-2 border transition-all duration-300 ease-out ${config.className}`}
          role="status"
          aria-live="polite"
        >
          <span className="verification-badge-icon" aria-hidden>
            {config.icon}
          </span>
          <span>{config.label}</span>
        </div>
        {issuerLabel && phase === 'sovereign_complete' && (
          <div
            className={`${BADGE_BASE_CLASSES} border ${
              issuer === '0x04'
                ? 'bg-[#f0eef8] dark:bg-[#e8e4f5] text-[#381993] border-[#381993]'
                : 'bg-white text-black border-gray-300 dark:border-gray-500'
            }`}
          >
            Issuer: {issuerLabel}
          </div>
        )}
        {showL1Badge && (
          <div className={`${BADGE_BASE_CLASSES} bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300`}>
            {L1_STATUS_LABELS[l1Status]}
          </div>
        )}
      </div>
      {errorMessage && (
        <p className="mt-2 text-sm text-red-700 dark:text-red-300">{errorMessage}</p>
      )}
    </div>
  );
}

export default ProgressiveVerificationBadge;
