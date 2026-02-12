import { useState } from 'react';
import { X } from 'lucide-react';

const EXPORT_BUTTON_BASE =
  'inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2';
const EXPORT_BUTTON_ENABLED =
  'bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer';
const EXPORT_BUTTON_DISABLED =
  'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed';

const LINK_BASE = 'text-sm text-blue-600 dark:text-blue-400 hover:underline';

const V_PACK_EXPLANATION =
  'A V-PACK is a universal map of your Bitcoin. If your service provider goes offline, you can use this file with any V-PACK recovery tool to reclaim your funds. Exporting a V-PACK ensures you own the "fire escape" instructions, not just the keys.';

export interface ExportToVpackButtonProps {
  disabled: boolean;
  onExport: () => void;
  'aria-label'?: string;
}

function ExportToVpackButton({
  disabled,
  onExport,
  'aria-label': ariaLabel = 'Export to V-PACK',
}: ExportToVpackButtonProps) {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const buttonClassName = disabled
    ? `${EXPORT_BUTTON_BASE} ${EXPORT_BUTTON_DISABLED}`
    : `${EXPORT_BUTTON_BASE} ${EXPORT_BUTTON_ENABLED}`;

  return (
    <div className="flex flex-col gap-2">
      <button
        type="button"
        onClick={onExport}
        disabled={disabled}
        className={`w-full sm:w-auto sm:max-w-[250px] sm:self-start ${buttonClassName}`}
        aria-label={ariaLabel}
      >
        Export to V-PACK
      </button>
      <button
        type="button"
        onClick={() => setIsDrawerOpen((prev) => !prev)}
        className={`self-start ${LINK_BASE}`}
      >
        What is V-PACK?
      </button>
      <div
        className="grid transition-[grid-template-rows] duration-300 ease-in-out"
        style={{ gridTemplateRows: isDrawerOpen ? '1fr' : '0fr' }}
      >
        <div className="min-h-0 overflow-hidden">
          <div className="mt-2 p-4 rounded-lg border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-800/50">
            <div className="flex items-start justify-between gap-2">
              <p className="text-sm text-gray-700 dark:text-gray-300">
                {V_PACK_EXPLANATION}
              </p>
              <button
                type="button"
                onClick={() => setIsDrawerOpen(false)}
                className="shrink-0 p-1 rounded text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ExportToVpackButton;
