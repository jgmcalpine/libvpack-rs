import { Shield, Wallet, DoorOpen } from 'lucide-react';

interface FeatureItem {
  icon: React.ReactNode;
  title: string;
  description: string;
}

interface HeroHeaderProps {
  title: string;
  subtitle: string;
  features?: FeatureItem[];
}

const FEATURE_ICON_CLASS = 'h-5 w-5 text-amber-500/90 shrink-0';

const FEATURES: FeatureItem[] = [
  {
    icon: <Shield className={FEATURE_ICON_CLASS} />,
    title: 'Cryptographic Check',
    description: 'Verify signatures locally.',
  },
  {
    icon: <Wallet className={FEATURE_ICON_CLASS} />,
    title: 'Cost Estimator',
    description: 'See L1 fees & time delays.',
  },
  {
    icon: <DoorOpen className={FEATURE_ICON_CLASS} />,
    title: 'Unilateral Exit',
    description: 'Visualize your exit path.',
  },
];

const FEATURE_CARD_BASE =
  'flex items-center gap-2 shrink-0 snap-center rounded-lg px-3 py-2 bg-gray-100/80 dark:bg-gray-800/80';

const FEATURE_ROW_MOBILE =
  'flex flex-row overflow-x-auto gap-4 snap-x snap-mandatory pb-1 -mx-4 px-4 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden';

const FEATURE_ROW_DESKTOP = 'md:flex-wrap md:justify-center md:overflow-visible md:snap-none md:gap-10';

function HeroHeader({ title, subtitle, features = FEATURES }: HeroHeaderProps) {
  return (
    <header className="text-center mb-4 md:mb-8">
      <h1 className="text-2xl md:text-5xl font-bold mb-2 md:mb-3 text-gray-900 dark:text-white tracking-tight">
        {title}
      </h1>
      <p className="text-sm md:text-lg text-gray-600 dark:text-gray-400 mb-4 md:mb-8 max-w-2xl mx-auto line-clamp-2 md:line-clamp-none">
        {subtitle}
      </p>
      <div className={`${FEATURE_ROW_MOBILE} ${FEATURE_ROW_DESKTOP}`}>
        {features.map(({ icon, title: featTitle, description }) => (
          <div
            key={featTitle}
            className={`${FEATURE_CARD_BASE} md:px-0 md:py-0 md:gap-3 md:bg-transparent dark:md:bg-transparent`}
          >
            <div className="flex items-center justify-center w-8 h-8 md:w-10 md:h-10 rounded-lg bg-gray-200/60 dark:bg-gray-700/60 shrink-0">
              {icon}
            </div>
            <div className="min-w-0">
              <p className="text-xs md:text-sm font-semibold text-gray-800 dark:text-gray-200">
                {featTitle}
              </p>
              <p className="text-[10px] md:text-xs text-gray-600 dark:text-gray-400 hidden md:block">
                {description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </header>
  );
}

export default HeroHeader;
export type { HeroHeaderProps, FeatureItem };
