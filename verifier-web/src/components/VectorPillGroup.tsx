import { FlaskConical, Cpu } from 'lucide-react';
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

const CONTAINER_CLASSES =
  'rounded-xl border border-slate-300 dark:border-slate-700 p-2.5 bg-transparent';

const TITLE_CLASSES =
  'text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500';
const ICON_CLASSES = 'h-3.5 w-3.5 text-slate-400 dark:text-slate-500 shrink-0';

const GROUP_ICONS: Record<AccentColor, React.ReactNode> = {
  arkLabs: <FlaskConical className={ICON_CLASSES} aria-hidden />,
  secondTech: <Cpu className={ICON_CLASSES} aria-hidden />,
};

function VectorPillGroup({
  title,
  vectors,
  accentColor,
  selectedVectorId,
  onSelectVector,
}: VectorPillGroupProps) {
  const icon = GROUP_ICONS[accentColor];

  return (
    <div className={CONTAINER_CLASSES}>
      <div className="mb-2">
        <h3 className={`${TITLE_CLASSES} flex items-center gap-2`}>
          {icon}
          {title}
        </h3>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {vectors.map((vector) => (
          <VectorPill
            key={vector.id}
            vector={vector}
            isSelected={selectedVectorId === vector.id}
            onSelect={() => onSelectVector(vector)}
          />
        ))}
      </div>
    </div>
  );
}

export default VectorPillGroup;
