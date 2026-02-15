import type { ReactNode } from 'react';

export type AppMode = 'demo' | 'audit';

interface ModeTabsProps {
  mode: AppMode;
  onModeChange: (mode: AppMode) => void;
  demoContent: ReactNode;
  auditContent: ReactNode;
}

const TAB_BASE =
  'px-6 py-3 font-bold text-base transition-colors border-b-2 -mb-px';

const TAB_INACTIVE =
  'text-gray-500 dark:text-gray-400 border-transparent hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600';

const TAB_DEMO_ACTIVE =
  'text-violet-600 dark:text-violet-400 border-violet-600 dark:border-violet-400';

const TAB_AUDIT_ACTIVE =
  'text-emerald-600 dark:text-emerald-400 border-emerald-600 dark:border-emerald-400';

function ModeTabs({
  mode,
  onModeChange,
  demoContent,
  auditContent,
}: ModeTabsProps) {
  return (
    <div className="space-y-4">
      <div
        className="flex border-b border-gray-200 dark:border-gray-700"
        role="tablist"
        aria-label="Select mode"
      >
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'demo'}
          aria-controls="demo-panel"
          id="demo-tab"
          onClick={() => onModeChange('demo')}
          className={`${TAB_BASE} ${mode === 'demo' ? TAB_DEMO_ACTIVE : TAB_INACTIVE}`}
        >
          Try the Demo (Testnet Data)
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'audit'}
          aria-controls="audit-panel"
          id="audit-tab"
          onClick={() => onModeChange('audit')}
          className={`${TAB_BASE} ${mode === 'audit' ? TAB_AUDIT_ACTIVE : TAB_INACTIVE}`}
        >
          Audit My Funds (Mainnet)
        </button>
      </div>

      <div
        id="demo-panel"
        role="tabpanel"
        aria-labelledby="demo-tab"
        hidden={mode !== 'demo'}
        className={mode !== 'demo' ? 'sr-only' : undefined}
      >
        {demoContent}
      </div>

      <div
        id="audit-panel"
        role="tabpanel"
        aria-labelledby="audit-tab"
        hidden={mode !== 'audit'}
        className={mode !== 'audit' ? 'sr-only' : undefined}
      >
        {auditContent}
      </div>
    </div>
  );
}

export default ModeTabs;
