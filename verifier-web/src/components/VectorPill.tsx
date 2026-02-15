import { Check } from 'lucide-react';
import type { VectorEntry } from '../constants/vectors';

type AccentColor = 'arkLabs' | 'secondTech';

interface VectorPillProps {
  vector: VectorEntry;
  isSelected: boolean;
  accentColor: AccentColor;
  onSelect: () => void;
}

const ACCENT_STYLES: Record<
  AccentColor,
  { base: string; selected: string; hover: string; focusRing: string }
> = {
  arkLabs: {
    base: 'bg-white dark:bg-gray-800 border-2 border-purple-500 text-gray-900 dark:text-gray-100',
    selected:
      'bg-purple-700 text-white border-[3px] border-purple-800 dark:border-purple-600',
    hover: 'hover:bg-purple-50 dark:hover:bg-purple-900/20 hover:border-purple-600',
    focusRing: 'focus:ring-purple-500',
  },
  secondTech: {
    base: 'border-2 border-gray-300 dark:border-gray-500 text-black dark:text-white bg-white dark:bg-gray-800',
    selected:
      'bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 border-[3px] border-gray-800 dark:border-gray-200',
    hover: 'hover:bg-gray-100 dark:hover:bg-gray-700 hover:border-gray-400',
    focusRing: 'focus:ring-gray-500',
  },
};

function VectorPill({ vector, isSelected, accentColor, onSelect }: VectorPillProps) {
  const styles = ACCENT_STYLES[accentColor];

  return (
    <button
      type="button"
      onClick={onSelect}
      title={vector.description}
      className={`
        px-4 py-2 rounded-full border-2 font-medium text-sm transition-all
        focus:outline-none focus:ring-2 focus:ring-offset-2
        ${styles.base}
        ${isSelected ? styles.selected : styles.hover}
        ${isSelected && accentColor === 'arkLabs' ? 'pill-border-pulse' : ''}
        ${isSelected && accentColor === 'secondTech' ? 'pill-border-pulse-second' : ''}
        ${styles.focusRing}
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
