import { Check } from 'lucide-react';
import type { VectorEntry } from '../constants/vectors';

interface VectorPillProps {
  vector: VectorEntry;
  isSelected: boolean;
  onSelect: () => void;
}

const BASE_CLASSES =
  'px-4 py-2 rounded-full border-2 font-medium text-sm transition-all focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2';

const DEFAULT_CLASSES =
  'bg-slate-800 text-gray-100 border-slate-600 hover:bg-slate-700';

const SELECTED_CLASSES = 'bg-purple-600 text-white border-purple-500 pill-border-pulse';

function VectorPill({ vector, isSelected, onSelect }: VectorPillProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      title={vector.description}
      className={`
        ${BASE_CLASSES}
        ${isSelected ? SELECTED_CLASSES : DEFAULT_CLASSES}
      `}
      aria-pressed={isSelected}
      aria-label={`${vector.label}: ${vector.description}`}
    >
      <span className="inline-flex items-center gap-2">
        {isSelected && <Check className="h-4 w-4 shrink-0" strokeWidth={3} />}
        {vector.label}
      </span>
    </button>
  );
}

export default VectorPill;
