import { useState, useRef, useEffect } from 'react';
import { HelpCircle } from 'lucide-react';

const V_PACK_EXPLANATION =
  'A V-PACK is a portable proof file containing your VTXO data. If your service provider goes offline, you can use this file with any V-PACK recovery tool to reclaim your funds. No data leaves your browser.';

interface VpackHelpTooltipProps {
  /** Element to attach the tooltip to. Omit for icon-only mode. */
  children?: React.ReactNode;
  className?: string;
  /** When true, renders only the help icon (no children). Tooltip triggers on icon hover/click only. */
  iconOnly?: boolean;
}

function VpackHelpTooltip({ children, className = '', iconOnly = false }: VpackHelpTooltipProps) {
  const [isVisible, setIsVisible] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsVisible(false);
      }
    };
    if (isVisible) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isVisible]);

  const handleIconClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsVisible((prev) => !prev);
  };

  const handleIconKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      e.stopPropagation();
      setIsVisible((prev) => !prev);
    }
  };

  const iconTrigger = (
    <span
      role="button"
      tabIndex={0}
      onClick={handleIconClick}
      onKeyDown={handleIconKeyDown}
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
      className="p-1 rounded text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 shrink-0 cursor-pointer inline-flex"
      aria-label="What is a V-PACK?"
    >
      <HelpCircle className="h-4 w-4" />
    </span>
  );

  if (iconOnly) {
    return (
      <div ref={containerRef} className={`relative inline-flex ${className}`}>
        {iconTrigger}
        {isVisible && (
          <div
            className="absolute left-0 top-full mt-2 z-50 w-72 p-3 rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-lg text-sm text-gray-700 dark:text-gray-300"
            role="tooltip"
          >
            {V_PACK_EXPLANATION}
          </div>
        )}
      </div>
    );
  }

  return (
    <div ref={containerRef} className={`relative flex items-stretch w-full ${className}`}>
      <div className="flex items-center gap-2 w-full">
        <div className="flex-1 min-w-0">{children}</div>
        {iconTrigger}
      </div>
      {isVisible && (
        <div
          className="absolute left-0 top-full mt-2 z-50 w-72 p-3 rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-lg text-sm text-gray-700 dark:text-gray-300"
          role="tooltip"
        >
          {V_PACK_EXPLANATION}
        </div>
      )}
    </div>
  );
}

export default VpackHelpTooltip;
