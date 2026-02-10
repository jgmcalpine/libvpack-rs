
interface VTXOInputProps {
  value: string;
  onChange: (value: string) => void;
}

function VTXOInput({ value, onChange }: VTXOInputProps) {
  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    onChange(event.target.value);
  };

  return (
    <div className="w-full">
      <label htmlFor="vtxo-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        VTXO Ingredients (JSON)
      </label>
      <textarea
        id="vtxo-input"
        value={value}
        onChange={handleChange}
        placeholder="Paste VTXO reconstruction ingredients JSON here..."
        className="w-full h-64 p-4 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-y"
      />
    </div>
  );
}

export default VTXOInput;
