import type { VectorEntry } from '../constants/vectors';

interface ForensicArchiveProps {
  vectors: VectorEntry[];
  selectedVectorId: string | null;
  onSelectVector: (vector: VectorEntry) => void;
  /** Optional display label overrides keyed by vector id */
  labelOverrides?: Record<string, string>;
}

const LABEL_CLASSES = 'text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2';
const CONTAINER_CLASSES = 'flex flex-wrap gap-2';
const BUTTON_BASE =
  'px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2';
const BUTTON_GHOST =
  'bg-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:border-slate-400 dark:hover:border-slate-500';
const BUTTON_SELECTED =
  'bg-purple-50 dark:bg-purple-900/30 border-purple-400 dark:border-purple-600 text-purple-800 dark:text-purple-200';

function ForensicArchive({
  vectors,
  selectedVectorId,
  onSelectVector,
  labelOverrides = {},
}: ForensicArchiveProps) {
  return (
    <div>
      <p className={LABEL_CLASSES}>Additional Edge Cases:</p>
      <div className={CONTAINER_CLASSES}>
        {vectors.map((vector) => {
          const isSelected = selectedVectorId === vector.id;
          const displayLabel = labelOverrides[vector.id] ?? vector.label;
          return (
            <button
              key={vector.id}
              type="button"
              onClick={() => onSelectVector(vector)}
              title={vector.description}
              className={`${BUTTON_BASE} ${isSelected ? BUTTON_SELECTED : BUTTON_GHOST}`}
              aria-pressed={isSelected}
              aria-label={`${displayLabel}: ${vector.description}`}
            >
              {displayLabel}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default ForensicArchive;
