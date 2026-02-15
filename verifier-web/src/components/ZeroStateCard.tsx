import { MousePointer } from 'lucide-react';

const CARD_CLASSES =
  'rounded-lg border-2 border-dashed border-slate-400 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 p-6';

const ICON_CLASSES = 'h-10 w-10 text-slate-500 dark:text-slate-400 mb-3';
const HEADLINE_CLASSES = 'text-base font-semibold text-gray-900 dark:text-white mb-2';
const BODY_CLASSES = 'text-sm text-gray-600 dark:text-gray-400 leading-relaxed';

function ZeroStateCard() {
  return (
    <div className={CARD_CLASSES} role="status" aria-label="Getting started">
      <MousePointer className={ICON_CLASSES} aria-hidden />
      <h4 className={HEADLINE_CLASSES}>Ready to Audit</h4>
      <p className={BODY_CLASSES}>
        Select a button above (like <strong>Round Leaf</strong>) to load its V-PACK.
        This will populate the inspector with real cryptographic proofs so you can
        verify the exit path.
      </p>
    </div>
  );
}

export default ZeroStateCard;
