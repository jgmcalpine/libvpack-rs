import { Shield } from 'lucide-react';

const badgeClasses =
  'flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200 text-sm';

function PrivacyShieldBadge() {
  return (
    <div className={badgeClasses} role="status" aria-label="Privacy assurance">
      <Shield className="w-5 h-5 flex-shrink-0" />
      <span>
        Sovereign Audit: All verification math performed locally in your browser via WASM. Your data never leaves this
        device.
      </span>
    </div>
  );
}

export default PrivacyShieldBadge;
