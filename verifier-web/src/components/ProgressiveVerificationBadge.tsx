import type { VerificationPhase } from '../types/verification';

interface ProgressiveVerificationBadgeProps {
  phase: VerificationPhase;
  errorMessage?: string | null;
}

const PHASE_CONFIG: Record<
  VerificationPhase,
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
    className: 'verification-badge sovereign-complete bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border-green-300 dark:border-green-700',
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
};

function ProgressiveVerificationBadge({ phase, errorMessage }: ProgressiveVerificationBadgeProps) {
  const config = PHASE_CONFIG[phase];

  return (
    <div className="verification-badge-wrapper">
      <div
        className={`inline-flex items-center gap-2 px-4 py-3 rounded-lg border-2 font-semibold transition-all duration-300 ease-out ${config.className}`}
        role="status"
        aria-live="polite"
      >
        <span className="verification-badge-icon" aria-hidden>
          {config.icon}
        </span>
        <span>{config.label}</span>
      </div>
      {errorMessage && (
        <p className="mt-2 text-sm text-red-700 dark:text-red-300">{errorMessage}</p>
      )}
    </div>
  );
}

export default ProgressiveVerificationBadge;
