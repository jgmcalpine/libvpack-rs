import { Loader2, CheckCircle2 } from 'lucide-react';
import { SCENARIO_STORIES } from '../constants/scenarioStories';

export type VerificationStatus = 'idle' | 'verifying' | 'verified';

interface ScenarioDescriptionCardProps {
  selectedVectorId: string | null;
  showLocalTestDataTag?: boolean;
  verificationStatus?: VerificationStatus;
}

const CARD_CLASSES =
  'rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 p-4';

const TITLE_CLASSES = 'text-base font-semibold text-gray-900 dark:text-white';
const DESC_CLASSES = 'text-sm text-gray-600 dark:text-gray-400 mt-1';
const TAG_CLASSES =
  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-300 mt-2';

function ScenarioDescriptionCard({
  selectedVectorId,
  showLocalTestDataTag = false,
  verificationStatus = 'idle',
}: ScenarioDescriptionCardProps) {
  if (!selectedVectorId) return null;

  const story = SCENARIO_STORIES[selectedVectorId];
  if (!story) return null;

  const showVerification = verificationStatus === 'verifying' || verificationStatus === 'verified';

  return (
    <div className={CARD_CLASSES} role="region" aria-label="Scenario description">
      <h4 className={TITLE_CLASSES}>{story.title}</h4>
      <p className={DESC_CLASSES}>{story.description}</p>
      {showVerification && (
        <div className="flex items-center gap-2 mt-3">
          {verificationStatus === 'verifying' && (
            <>
              <Loader2 className="h-4 w-4 animate-spin text-violet-600 dark:text-violet-400 shrink-0" />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Verifying Cryptographic Signatures...
              </span>
            </>
          )}
          {verificationStatus === 'verified' && (
            <>
              <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span className="text-sm text-emerald-700 dark:text-emerald-300">
                Signature Valid (Schnorr).
              </span>
            </>
          )}
        </div>
      )}
      {showLocalTestDataTag && (
        <span className={TAG_CLASSES}>Local Test Data</span>
      )}
    </div>
  );
}

export default ScenarioDescriptionCard;
