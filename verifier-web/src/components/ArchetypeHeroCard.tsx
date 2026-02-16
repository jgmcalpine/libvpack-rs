import React from 'react';
import { GitMerge, Link2 } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export type ArchetypeKind = 'tree' | 'chain';

/** Renders text with **bold** segments as <strong>. */
function renderWithBold(text: string): React.ReactNode {
  const parts = text.split(/\*\*(.+?)\*\*/g);
  return parts.map((part, i) =>
    i % 2 === 1 ? <strong key={i}>{part}</strong> : part
  );
}

interface ArchetypeHeroCardProps {
  kind: ArchetypeKind;
  title: string;
  subtitle: string;
  body: string;
  techBadge: string;
  isSelected: boolean;
  onSelect: () => void;
}

const CARD_BASE =
  'relative flex flex-col p-6 rounded-xl border-2 cursor-pointer transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 items-center md:items-start text-center md:text-left';

const CARD_DEFAULT =
  'bg-white dark:bg-gray-800 border-slate-200 dark:border-slate-700 hover:-translate-y-1 hover:shadow-lg hover:border-purple-500 hover:bg-purple-500/5 dark:hover:bg-purple-500/5';

const CARD_SELECTED =
  'ring-2 ring-purple-500 border-purple-500 dark:border-purple-500 bg-purple-50/50 dark:bg-purple-900/20';

const ICON_BASE = 'h-12 w-12 mb-4 text-slate-600 dark:text-slate-400 shrink-0';
const TITLE_CLASSES = 'text-lg font-bold text-gray-900 dark:text-white mb-0.5';
const SUBTITLE_CLASSES = 'text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3';
const BODY_CLASSES = 'text-sm text-gray-600 dark:text-gray-400 leading-relaxed flex-1';
const BADGE_CLASSES =
  'inline-flex items-center px-2 py-1 rounded-md text-xs font-mono bg-slate-900 dark:bg-slate-950 text-slate-200 dark:text-slate-300';
const SELECT_CTA_CLASSES = 'text-purple-400 dark:text-purple-400 font-semibold text-sm mt-2';

const ARCHETYPE_ICONS: Record<ArchetypeKind, LucideIcon> = {
  tree: GitMerge,
  chain: Link2,
};

function ArchetypeHeroCard({
  kind,
  title,
  subtitle,
  body,
  techBadge,
  isSelected,
  onSelect,
}: ArchetypeHeroCardProps) {
  const Icon = ARCHETYPE_ICONS[kind];

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`${CARD_BASE} ${isSelected ? CARD_SELECTED : CARD_DEFAULT}`}
      aria-pressed={isSelected}
      aria-label={`${title}: ${body}`}
    >
      <Icon className={ICON_BASE} aria-hidden />
      <h3 className={TITLE_CLASSES}>{title}</h3>
      <p className={SUBTITLE_CLASSES}>{subtitle}</p>
      <p className={`${BODY_CLASSES} mb-6`}>
        {renderWithBold(body)}
      </p>
      <span className={BADGE_CLASSES}>{techBadge}</span>
      <span className={SELECT_CTA_CLASSES}>Select Scenario →</span>
    </button>
  );
}

export default ArchetypeHeroCard;
