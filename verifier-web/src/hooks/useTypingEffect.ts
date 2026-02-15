import { useCallback, useEffect, useRef, useState } from 'react';

interface UseTypingEffectOptions {
  targetText: string;
  enabled: boolean;
  charDelayMs?: number;
  /** Chars to add per tick; higher = faster typing. */
  charsPerTick?: number;
  onComplete?: () => void;
}

/**
 * Types out targetText when enabled. Uses charsPerTick for batched typing speed.
 * Returns the current displayed string and a function to skip to completion.
 */
function useTypingEffect({
  targetText,
  enabled,
  charDelayMs = 8,
  charsPerTick = 5,
  onComplete,
}: UseTypingEffectOptions): [string, () => void] {
  const [displayedText, setDisplayedText] = useState('');
  const indexRef = useRef(0);
  const timeoutRef = useRef<number | null>(null);
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  const skipToEnd = useCallback(() => {
    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    setDisplayedText(targetText);
    indexRef.current = targetText.length;
    onCompleteRef.current?.();
  }, [targetText]);

  useEffect(() => {
    if (!enabled || !targetText) {
      setDisplayedText('');
      indexRef.current = 0;
      return;
    }

    indexRef.current = 0;
    setDisplayedText('');

    const typeNext = () => {
      if (indexRef.current >= targetText.length) {
        onCompleteRef.current?.();
        return;
      }
      indexRef.current = Math.min(indexRef.current + charsPerTick, targetText.length);
      setDisplayedText(targetText.slice(0, indexRef.current));
      timeoutRef.current = window.setTimeout(typeNext, charDelayMs);
    };

    timeoutRef.current = window.setTimeout(typeNext, charDelayMs);

    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [targetText, enabled, charDelayMs, charsPerTick]);

  return [displayedText, skipToEnd];
}

export default useTypingEffect;
