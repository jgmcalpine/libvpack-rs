import type { VectorEntry } from '../constants/vectors';

interface VectorPillProps {
  vector: VectorEntry;
  isSelected: boolean;
  accentColor: 'blue' | 'purple';
  onSelect: () => void;
}

const ACCENT_STYLES: Record<
  'blue' | 'purple',
  { base: string; selected: string; hover: string }
> = {
  blue: {
    base: 'border-blue-300 dark:border-blue-600 text-blue-700 dark:text-blue-300',
    selected: 'bg-blue-100 dark:bg-blue-900/40 border-blue-500 dark:border-blue-400 ring-2 ring-blue-400/50',
    hover: 'hover:bg-blue-50 dark:hover:bg-blue-900/20 hover:border-blue-400',
  },
  purple: {
    base: 'border-purple-300 dark:border-purple-600 text-purple-700 dark:text-purple-300',
    selected: 'bg-purple-100 dark:bg-purple-900/40 border-purple-500 dark:border-purple-400 ring-2 ring-purple-400/50',
    hover: 'hover:bg-purple-50 dark:hover:bg-purple-900/20 hover:border-purple-400',
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
        ${accentColor === 'blue' ? 'focus:ring-blue-500' : 'focus:ring-purple-500'}
      `}
      aria-pressed={isSelected}
      aria-label={`${vector.label}: ${vector.description}`}
    >
      {vector.label}
    </button>
  );
}

export default VectorPill;
