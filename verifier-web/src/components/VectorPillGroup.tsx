import type { VectorEntry } from '../constants/vectors';
import VectorPill from './VectorPill';

type AccentColor = 'arkLabs' | 'secondTech';

interface VectorPillGroupProps {
  title: string;
  vectors: VectorEntry[];
  accentColor: AccentColor;
  selectedVectorId: string | null;
  onSelectVector: (vector: VectorEntry) => void;
}

const GROUP_STYLES: Record<AccentColor, { container: string; title: string }> = {
  arkLabs: {
    container:
      'rounded-lg border-2 border-[#381993] p-2.5 bg-[#f0eef8] dark:bg-[#e8e4f5]',
    title: 'text-[10px] font-medium uppercase tracking-wide text-[#381993]/70 dark:text-[#381993]/80',
  },
  secondTech: {
    container:
      'rounded-lg border-2 border-gray-200 dark:border-white p-2.5 bg-white text-black',
    title:
      'text-[10px] font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400',
  },
};

const SUBTITLE_CLASSES = 'text-[9px] font-normal normal-case text-gray-400 dark:text-gray-500 mt-0.5';

function VectorPillGroup({
  title,
  vectors,
  accentColor,
  selectedVectorId,
  onSelectVector,
}: VectorPillGroupProps) {
  const groupStyles = GROUP_STYLES[accentColor];

  return (
    <div className={groupStyles.container}>
      <div className="mb-2">
        <h3 className={groupStyles.title}>
          {title}
        </h3>
        <p className={SUBTITLE_CLASSES}>Reference Implementation</p>
      </div>
      <div className="flex flex-wrap gap-1.5">
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
