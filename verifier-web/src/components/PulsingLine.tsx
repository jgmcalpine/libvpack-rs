import { motion } from 'framer-motion';
import { Clock } from 'lucide-react';

interface PulsingLineProps {
  height: number;
  visible?: boolean;
  delay?: number;
  showTimer?: boolean;
  /** 0-1, for "fluid filling" animation during simulate exit */
  fillProgress?: number;
}

function PulsingLine({
  height,
  visible = true,
  delay = 0,
  showTimer = false,
  fillProgress = 1,
}: PulsingLineProps) {
  const isSimulating = fillProgress < 1;
  const pathLength = height;

  return (
    <motion.div
      initial={{ opacity: 0, scaleY: 0 }}
      animate={
        visible
          ? { opacity: 1, scaleY: 1 }
          : { opacity: 0, scaleY: 0 }
      }
      transition={{ duration: 0.5, delay }}
      className="relative w-full flex justify-center origin-top"
      style={{ height }}
    >
      <svg
        width="4"
        height={height}
        className="flex-shrink-0"
        aria-hidden
      >
        <defs>
          <linearGradient id="pulseGradient" x1="0" y1="1" x2="0" y2="0">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
            <stop offset="50%" stopColor="#22d3ee" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#67e8f9" stopOpacity="0.4" />
          </linearGradient>
          <linearGradient id="fillGradient" x1="0" y1="1" x2="0" y2="0">
            <stop offset="0%" stopColor="#F7931A" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
        </defs>
        {/* Base line (dim when simulating) */}
        <line
          x1="2"
          y1={height}
          x2="2"
          y2="0"
          stroke="url(#pulseGradient)"
          strokeWidth="2"
          strokeLinecap="round"
          opacity={isSimulating ? 0.3 : 1}
        />
        {/* Fluid fill - draws from bottom to top */}
        {isSimulating && (
          <motion.line
            x1="2"
            y1={height}
            x2="2"
            y2="0"
            stroke="url(#fillGradient)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={pathLength}
            initial={{ strokeDashoffset: pathLength }}
            animate={{ strokeDashoffset: pathLength * (1 - fillProgress) }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
          />
        )}
      </svg>
      {visible && !showTimer && !isSimulating && (
        <motion.div
          animate={{
            opacity: [0.2, 0.7, 0.2],
          }}
          transition={{
            duration: 1.2,
            repeat: Infinity,
          }}
          className="absolute top-0 left-1/2 -translate-x-1/2 w-1 bg-cyan-400/50 rounded-full"
          style={{ height }}
        />
      )}
      {visible && showTimer && (
        <motion.div
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-amber-500/30 border border-amber-400/50"
        >
          <motion.div
            animate={{ opacity: [0.6, 1, 0.6] }}
            transition={{ duration: 1.5, repeat: Infinity }}
          >
            <Clock className="w-4 h-4 text-amber-400" />
          </motion.div>
        </motion.div>
      )}
    </motion.div>
  );
}

export default PulsingLine;
