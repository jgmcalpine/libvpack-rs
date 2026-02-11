interface VTXOInputProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
}

const BASE_INPUT_CLASSES =
  'w-full h-64 p-4 border rounded-lg font-mono text-sm resize-y focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent';

const READONLY_INPUT_CLASSES =
  'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 text-gray-600 dark:text-gray-400 opacity-75 cursor-not-allowed';

const EDITABLE_INPUT_CLASSES =
  'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100';

function VTXOInput({ value, onChange, readOnly = false }: VTXOInputProps) {
  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    onChange(event.target.value);
  };

  const inputClassName = readOnly
    ? `${BASE_INPUT_CLASSES} ${READONLY_INPUT_CLASSES}`
    : `${BASE_INPUT_CLASSES} ${EDITABLE_INPUT_CLASSES}`;

  return (
    <div className="w-full">
      <label htmlFor="vtxo-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        VTXO Ingredients (JSON)
      </label>
      <textarea
        id="vtxo-input"
        value={value}
        onChange={handleChange}
        readOnly={readOnly}
        placeholder={
          readOnly
            ? 'Select a vector above to populate...'
            : 'Paste VTXO reconstruction ingredients JSON here...'
        }
        className={inputClassName}
      />
    </div>
  );
}

export default VTXOInput;
