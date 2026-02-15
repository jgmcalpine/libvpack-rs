import { VECTORS } from '../constants/vectors';
import type { VectorEntry } from '../constants/vectors';
import ArchetypeHeroCard from './ArchetypeHeroCard';
import ForensicArchive from './ForensicArchive';

const MERKLE_TREE_VECTOR_ID = 'intermediate-branch';
const CONNECTOR_CHAIN_VECTOR_ID = 'recursive-round';

const FORENSIC_VECTOR_IDS = [
  'round-leaf',
  'off-chain-forfeit',
  'boarding-utxo',
  'chain-payment',
] as const;

const FORENSIC_LABEL_OVERRIDES: Record<string, string> = {
  'chain-payment': 'OOR VTXO',
};

const vectorById = (id: string): VectorEntry | undefined =>
  VECTORS.find((v) => v.id === id);

const forensicVectors = FORENSIC_VECTOR_IDS
  .map((id) => vectorById(id))
  .filter((v): v is VectorEntry => v !== undefined);

interface ScenarioPickerProps {
  selectedVectorId: string | null;
  onSelectVector: (vector: VectorEntry) => void;
}

const INTRO_CLASSES =
  'text-sm text-gray-600 dark:text-gray-400 mb-4';

function ScenarioPicker({
  selectedVectorId,
  onSelectVector,
}: ScenarioPickerProps) {
  const merkleTreeVector = vectorById(MERKLE_TREE_VECTOR_ID);
  const connectorChainVector = vectorById(CONNECTOR_CHAIN_VECTOR_ID);

  return (
    <div>
      <p className={INTRO_CLASSES}>
        Choose a transaction type below to simulate a specific exit path using testnet data.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {merkleTreeVector && (
          <ArchetypeHeroCard
            kind="tree"
            title="The Merkle Tree"
            subtitle="Ark Labs Implementation"
            body="Optimized for massive scaling. A wide, fanned-out structure where one root supports many users."
            techBadge="ID: TxID (32B)"
            isSelected={selectedVectorId === MERKLE_TREE_VECTOR_ID}
            onSelect={() => onSelectVector(merkleTreeVector)}
          />
        )}
        {connectorChainVector && (
          <ArchetypeHeroCard
            kind="chain"
            title="The Connector Chain"
            subtitle="Second Tech Implementation"
            body="Optimized for agility. A recursive, vertical chain of transactions handling sequential history."
            techBadge="ID: OutPoint (36B)"
            isSelected={selectedVectorId === CONNECTOR_CHAIN_VECTOR_ID}
            onSelect={() => onSelectVector(connectorChainVector)}
          />
        )}
      </div>

      <ForensicArchive
        vectors={forensicVectors}
        selectedVectorId={selectedVectorId}
        onSelectVector={onSelectVector}
        labelOverrides={FORENSIC_LABEL_OVERRIDES}
      />
    </div>
  );
}

export default ScenarioPicker;
export type { ScenarioPickerProps };
