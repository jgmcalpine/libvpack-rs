import { useState } from 'react';

interface ReconstructedIdBoxProps {
  reconstructedId: string | null;
}

function ReconstructedIdBox({ reconstructedId }: ReconstructedIdBoxProps) {
  const [copied, setCopied] = useState(false);

  if (reconstructedId === null) {
    return null;
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(reconstructedId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  };

  return (
    <div className="w-full">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Reconstructed VTXO ID
      </label>
      <div className="flex items-center gap-2">
        <input
          type="text"
          readOnly
          value={reconstructedId}
          className="flex-1 p-3 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          type="button"
          onClick={handleCopy}
          className="px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

export default ReconstructedIdBox;
