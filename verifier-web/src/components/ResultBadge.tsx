interface ResultBadgeProps {
  status: string | null;
  variant: string | null;
}

function ResultBadge({ status, variant }: ResultBadgeProps) {
  if (status === null) {
    return null;
  }

  const isSuccess = status === 'Success';
  const badgeColorClasses = isSuccess
    ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 border-green-300 dark:border-green-700'
    : 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 border-red-300 dark:border-red-700';

  return (
    <div className={`inline-flex items-center px-4 py-2 rounded-lg border-2 font-semibold ${badgeColorClasses}`}>
      <span className="mr-2">{isSuccess ? '✓' : '✗'}</span>
      <span>Status: {status}</span>
      {variant && (
        <span className="ml-3 text-xs opacity-75">
          Variant: {variant}
        </span>
      )}
    </div>
  );
}

export default ResultBadge;
