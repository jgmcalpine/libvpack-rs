import type { VectorEntry } from '../constants/vectors';
import VectorPillGroup from './VectorPillGroup';

type AccentColor = 'arkLabs' | 'secondTech';

interface ScenarioGroup {
  title: string;
  vectors: VectorEntry[];
  accentColor: AccentColor;
}

interface ScenarioPickerProps {
  scenarioGroups: ScenarioGroup[];
  selectedVectorId: string | null;
  onSelectVector: (vector: VectorEntry) => void;
}

function ScenarioPicker({
  scenarioGroups,
  selectedVectorId,
  onSelectVector,
}: ScenarioPickerProps) {
  return (
    <div>
      <p className="text-sm text-gray-600 dark:text-gray-400 mb-1.5 md:mb-2">
        Choose a transaction type below to simulate a specific exit path using testnet data.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 md:gap-4">
        {scenarioGroups.map(({ title, vectors, accentColor }) => (
          <VectorPillGroup
            key={title}
            title={title}
            vectors={vectors}
            accentColor={accentColor}
            selectedVectorId={selectedVectorId}
            onSelectVector={onSelectVector}
          />
        ))}
      </div>
    </div>
  );
}

export default ScenarioPicker;
export type { ScenarioPickerProps, ScenarioGroup };
