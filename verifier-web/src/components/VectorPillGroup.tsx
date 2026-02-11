import type { VectorEntry } from '../constants/vectors';
import VectorPill from './VectorPill';

interface VectorPillGroupProps {
  title: string;
  vectors: VectorEntry[];
  accentColor: 'blue' | 'purple';
  selectedVectorId: string | null;
  onSelectVector: (vector: VectorEntry) => void;
}

function VectorPillGroup({
  title,
  vectors,
  accentColor,
  selectedVectorId,
  onSelectVector,
}: VectorPillGroupProps) {
  return (
    <div
      className={`rounded-lg border-2 p-4 ${
        accentColor === 'blue'
          ? 'border-blue-200 dark:border-blue-800 bg-blue-50/30 dark:bg-blue-900/10'
          : 'border-purple-200 dark:border-purple-800 bg-purple-50/30 dark:bg-purple-900/10'
      }`}
    >
      <h3
        className={`text-sm font-semibold uppercase tracking-wide mb-3 ${
          accentColor === 'blue'
            ? 'text-blue-800 dark:text-blue-200'
            : 'text-purple-800 dark:text-purple-200'
        }`}
      >
        {title}
      </h3>
      <div className="flex flex-wrap gap-2">
        {vectors.map((vector) => (
          <VectorPill
            key={vector.id}
            vector={vector}
            isSelected={selectedVectorId === vector.id}
            accentColor={accentColor}
            onSelect={() => onSelectVector(vector)}
          />
        ))}
      </div>
    </div>
  );
}

export default VectorPillGroup;
