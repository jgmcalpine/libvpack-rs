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

function HeroHeader({ title, subtitle, features = FEATURES }: HeroHeaderProps) {
  return (
    <header className="text-center mb-8">
      <h1 className="text-4xl md:text-5xl font-bold mb-3 text-gray-900 dark:text-white tracking-tight">
        {title}
      </h1>
      <p className="text-lg text-gray-600 dark:text-gray-400 mb-8 max-w-2xl mx-auto">
        {subtitle}
      </p>
      <div className="flex flex-wrap justify-center gap-6 md:gap-10">
        {features.map(({ icon, title: featTitle, description }) => (
          <div
            key={featTitle}
            className="flex items-center gap-3 text-left"
          >
            <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gray-200/60 dark:bg-gray-700/60">
              {icon}
            </div>
            <div>
              <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                {featTitle}
              </p>
              <p className="text-xs text-gray-600 dark:text-gray-400">
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
