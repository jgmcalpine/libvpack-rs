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
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-700 dark:text-gray-300">
          Load Example Data
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
          Choose a transaction type below to simulate a specific exit path using testnet data.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
