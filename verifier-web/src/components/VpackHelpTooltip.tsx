import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { HelpCircle, X } from 'lucide-react';

const V_PACK_EXPLANATION =
  'A V-PACK is a portable proof file containing your VTXO data. If your service provider goes offline, you can use this file with any V-PACK recovery tool to reclaim your funds. No data leaves your browser.';

const MOBILE_BREAKPOINT = 768;

function useIsMobile(): boolean {
  const [isMobile, setIsMobile] = useState(() =>
    typeof window !== 'undefined'
      ? window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`).matches
      : false,
  );

  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
    const update = () => setIsMobile(mq.matches);
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);

  return isMobile;
}

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
  const isMobile = useIsMobile();

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

  useEffect(() => {
    if (isVisible && isMobile) {
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isVisible, isMobile]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isVisible && isMobile) {
        setIsVisible(false);
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isVisible, isMobile]);

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

  const closeDrawer = () => setIsVisible(false);

  const iconTrigger = (
    <span
      role="button"
      tabIndex={0}
      onClick={handleIconClick}
      onKeyDown={handleIconKeyDown}
      onMouseEnter={() => !isMobile && setIsVisible(true)}
      onMouseLeave={() => !isMobile && setIsVisible(false)}
      className="p-1 rounded text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 shrink-0 cursor-pointer inline-flex"
      aria-label="What is a V-PACK?"
    >
      <HelpCircle className="h-4 w-4" />
    </span>
  );

  const tooltipContent = (
    <div
      className="absolute left-0 top-full mt-2 z-50 w-72 max-w-[calc(100vw-2rem)] p-3 rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-800 shadow-lg text-sm text-gray-700 dark:text-gray-300"
      role="tooltip"
    >
      {V_PACK_EXPLANATION}
    </div>
  );

  const mobileDrawer = (
    <AnimatePresence>
      {isVisible &&
        isMobile && [
          <motion.div
            key="vpack-drawer-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[100] bg-black/40"
            onClick={closeDrawer}
            role="presentation"
          />,
          <motion.div
            key="vpack-drawer-panel"
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            transition={{ type: 'tween', duration: 0.25, ease: 'easeOut' }}
            className="fixed inset-x-0 bottom-0 z-[101] rounded-t-xl bg-white dark:bg-gray-800 shadow-xl border-t border-gray-200 dark:border-gray-700 p-4 pb-[calc(50px+env(safe-area-inset-bottom))] max-h-[70vh] overflow-y-auto"
            role="dialog"
            aria-label="What is a V-PACK?"
          >
            <div className="flex items-start justify-between gap-4">
              <p className="text-sm text-gray-700 dark:text-gray-300 flex-1 min-w-0">
                {V_PACK_EXPLANATION}
              </p>
              <button
                type="button"
                onClick={closeDrawer}
                className="shrink-0 p-1 rounded text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-violet-500"
                aria-label="Close"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </motion.div>,
        ]}
    </AnimatePresence>
  );

  if (iconOnly) {
    return (
      <>
        <div ref={containerRef} className={`relative inline-flex ${className}`}>
          {iconTrigger}
          {isVisible && !isMobile && tooltipContent}
        </div>
        {mobileDrawer}
      </>
    );
  }

  return (
    <>
      <div ref={containerRef} className={`relative flex items-stretch w-full ${className}`}>
        <div className="flex items-center gap-2 w-full">
          <div className="flex-1 min-w-0">{children}</div>
          {iconTrigger}
        </div>
        {isVisible && !isMobile && tooltipContent}
      </div>
      {mobileDrawer}
    </>
  );
}

export default VpackHelpTooltip;
