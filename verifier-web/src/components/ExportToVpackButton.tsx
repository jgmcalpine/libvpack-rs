const GHOST_BASE =
  'text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:underline focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 rounded disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:no-underline';

const PRIMARY_BASE =
  'inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2';
const PRIMARY_ENABLED =
  'bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer';
const PRIMARY_DISABLED =
  'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed';

const V_PACK_TOOLTIP =
  "A V-PACK is a universal map of your Bitcoin. While wallets manage your keys, V-PACK ensures you possess the 'fire escape' data required to exit to L1 independently if your provider goes offline.";

export interface ExportToVpackButtonProps {
  disabled: boolean;
  onExport: () => void;
  variant?: 'primary' | 'ghost';
  'aria-label'?: string;
}

function ExportToVpackButton({
  disabled,
  onExport,
  variant = 'primary',
  'aria-label': ariaLabel = 'Export to V-PACK',
}: ExportToVpackButtonProps) {
  const isGhost = variant === 'ghost';
  const buttonClassName = isGhost
    ? GHOST_BASE
    : disabled
      ? `${PRIMARY_BASE} ${PRIMARY_DISABLED}`
      : `${PRIMARY_BASE} ${PRIMARY_ENABLED}`;

  return (
    <button
      type="button"
      onClick={onExport}
      disabled={disabled}
      className={isGhost ? buttonClassName : `sm:max-w-[250px] ${buttonClassName}`}
      aria-label={ariaLabel}
      title={V_PACK_TOOLTIP}
    >
      Export to V-PACK
    </button>
  );
}

export default ExportToVpackButton;
