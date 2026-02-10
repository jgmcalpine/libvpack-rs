interface MockDataBadgeProps {
  className?: string;
}

function MockDataBadge({ className = '' }: MockDataBadgeProps) {
  return (
    <div
      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300 ${className}`}
    >
      Mock Data
    </div>
  );
}

export default MockDataBadge;
