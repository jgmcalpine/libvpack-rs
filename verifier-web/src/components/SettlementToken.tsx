import { useEffect } from 'react';
import { motion, useAnimation } from 'framer-motion';
import { Bitcoin } from 'lucide-react';

const EASE_DESCENT: [number, number, number, number] = [0.22, 0.61, 0.36, 1];

interface SettlementTokenProps {
  startY: number;
  endY: number;
  containerWidth: number;
  nodeCount: number;
  onComplete: () => void;
  isActive: boolean;
  hasArrived: boolean;
}

function SettlementToken({
  startY,
  endY,
  containerWidth,
  nodeCount,
  onComplete,
  isActive,
  hasArrived,
}: SettlementTokenProps) {
  const controls = useAnimation();
  const descentDurationS = nodeCount;

  useEffect(() => {
    if (!isActive || hasArrived) return;

    const runDescent = async () => {
      await controls.start({
        top: endY,
        transition: {
          duration: descentDurationS,
          ease: EASE_DESCENT,
        },
      });
      onComplete();
    };

    runDescent();
  }, [isActive, hasArrived, endY, descentDurationS, controls, onComplete]);

  if (!isActive || hasArrived) return null;

  const iconGlowStyle = {
    filter: 'drop-shadow(0 0 12px rgba(245,158,11,0.9)) drop-shadow(0 0 24px rgba(251,191,36,0.6))',
  };

  const centerX = containerWidth / 2;

  return (
    <div className="absolute inset-0 pointer-events-none z-50" aria-hidden>
      <motion.div
        initial={{ top: startY }}
        animate={controls}
        className="absolute w-14 h-14 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center"
        style={{ left: centerX }}
      >
        <motion.div
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          style={iconGlowStyle}
        >
          <Bitcoin className="w-10 h-10 text-amber-400" strokeWidth={1.5} />
        </motion.div>
      </motion.div>
    </div>
  );
}

export default SettlementToken;
