import { useCallback, useMemo, useState } from 'react';
import { CheckCircle2, AlertCircle, ChevronRight, ChevronDown, Loader2 } from 'lucide-react';
import VpackHelpTooltip from './VpackHelpTooltip';

type ValidationState = 'idle' | 'valid' | 'invalid';

interface SecureInputProps {
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  onValidationChange?: (isValid: boolean) => void;
  validateStructure?: (text: string) => boolean;
  onFileDrop?: (file: File) => void;
  /** When true, wraps content in a collapsible accordion (collapsed by default). */
  collapsible?: boolean;
  /** Slot for secondary actions (Export, Clear) rendered inside the accordion footer. */
  secondaryActions?: React.ReactNode;
  /** When true, shows a (?) help icon next to the accordion toggle. */
  showHelpIcon?: boolean;
  /** When true, shows a subtle loading indicator where Data Loaded would appear. */
  isDataLoading?: boolean;
}

const BASE_INPUT_CLASSES =
  'w-full min-h-[140px] h-40 p-4 border rounded-lg font-mono text-sm resize-y focus:outline-none focus:ring-2 focus:border-transparent transition-colors';

const READONLY_CLASSES =
  'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 text-gray-600 dark:text-gray-400 opacity-75 cursor-not-allowed';

const EDITABLE_CLASSES =
  'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100';

const AUDIT_FOCUS_RING = 'focus:ring-emerald-500 focus:border-emerald-500';

function defaultValidate(text: string): boolean {
  if (!text.trim()) return false;
  try {
    const parsed = JSON.parse(text);
    return (
      typeof parsed === 'object' &&
      parsed !== null &&
      'reconstruction_ingredients' in parsed
    );
  } catch {
    return false;
  }
}

function SecureInput({
  value,
  onChange,
  readOnly = false,
  onValidationChange,
  validateStructure = defaultValidate,
  onFileDrop,
  collapsible = false,
  secondaryActions,
  showHelpIcon = false,
  isDataLoading = false,
}: SecureInputProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (!onFileDrop) return;
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, [onFileDrop]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    if (!onFileDrop) return;
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, [onFileDrop]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    if (!onFileDrop) return;
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file?.name.endsWith('.vpk')) {
      onFileDrop(file);
    }
  }, [onFileDrop]);

  const validationState = useMemo((): ValidationState => {
    if (!value.trim()) return 'idle';
    return validateStructure(value) ? 'valid' : 'invalid';
  }, [value, validateStructure]);

  const handleChange = useCallback(
    (event: React.ChangeEvent<HTMLTextAreaElement>) => {
      const newValue = event.target.value;
      onChange(newValue);
      if (onValidationChange && newValue.trim()) {
        onValidationChange(validateStructure(newValue));
      }
    },
    [onChange, onValidationChange, validateStructure],
  );

  const inputClassName = [
    BASE_INPUT_CLASSES,
    readOnly ? READONLY_CLASSES : EDITABLE_CLASSES,
    !readOnly && AUDIT_FOCUS_RING,
  ]
    .filter(Boolean)
    .join(' ');

  const placeholder = readOnly
    ? 'Select a scenario above to populate...'
    : 'Paste your VTXO JSON here, or drag and drop your V-PACK file...';

  const hasValidData = validationState === 'valid';

  const toggleLabel = (
    <span className="flex items-center gap-2 flex-1">
      <span className="text-gray-600 dark:text-gray-400">
        {isExpanded ? (
          <ChevronDown className="h-4 w-4 inline" />
        ) : (
          <ChevronRight className="h-4 w-4 inline" />
        )}
      </span>
      <span>View Raw V-PACK Data (Advanced)</span>
      {showHelpIcon && <VpackHelpTooltip iconOnly />}
      {hasValidData && (
        <span
          className="flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400"
          role="status"
        >
          <CheckCircle2 className="h-4 w-4" />
          Data Loaded
        </span>
      )}
      {!hasValidData && isDataLoading && (
        <span
          className="text-gray-400 dark:text-gray-500"
          role="status"
          aria-live="polite"
          title="Loading data..."
        >
          <Loader2 className="h-4 w-4 animate-spin shrink-0" />
        </span>
      )}
    </span>
  );

  const textareaBlock = (
    <div
      className={`relative ${onFileDrop ? 'cursor-pointer' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {isDragging && onFileDrop && (
        <div className="absolute inset-0 z-10 flex items-center justify-center rounded-lg border-2 border-dashed border-emerald-500 bg-emerald-50/90 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 font-medium">
          Drop V-PACK file here
        </div>
      )}
      <textarea
        id="secure-vtxo-input"
        value={value}
        onChange={handleChange}
        readOnly={readOnly}
        placeholder={placeholder}
        className={inputClassName}
        aria-invalid={validationState === 'invalid'}
      />
    </div>
  );

  const validationFeedback = (
    <div className="flex items-center gap-2 mt-2">
      {validationState === 'invalid' && value.trim() && (
        <span
          className="flex items-center gap-1 text-sm text-amber-600 dark:text-amber-400"
          role="alert"
        >
          <AlertCircle className="h-4 w-4" />
          Invalid JSON or missing structure
        </span>
      )}
    </div>
  );

  if (collapsible) {
    return (
      <div className="w-full">
        <button
          type="button"
          onClick={() => setIsExpanded((prev) => !prev)}
          className="flex items-center gap-2 w-full text-left py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 rounded"
          aria-expanded={isExpanded}
          aria-controls="secure-input-accordion"
        >
          {toggleLabel}
        </button>
        <div
          id="secure-input-accordion"
          className="grid transition-[grid-template-rows] duration-200 ease-out"
          style={{ gridTemplateRows: isExpanded ? '1fr' : '0fr' }}
        >
          <div className="min-h-0 overflow-hidden">
            <div className="pt-2 space-y-2">
              {textareaBlock}
              {validationFeedback}
              {secondaryActions && (
                <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-gray-200 dark:border-gray-700">
                  {secondaryActions}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full space-y-2">
      <label
        htmlFor="secure-vtxo-input"
        className="block text-sm font-medium text-gray-700 dark:text-gray-300"
      >
        VTXO Ingredients (JSON)
      </label>
      {textareaBlock}
      {validationFeedback}
    </div>
  );
}

export default SecureInput;
export type { SecureInputProps };
