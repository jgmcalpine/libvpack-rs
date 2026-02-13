import { motion } from 'framer-motion';

function AnimatedGrid() {
  return (
    <div
      className="absolute inset-0 overflow-hidden pointer-events-none opacity-30"
      aria-hidden
    >
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `
            linear-gradient(to right, white 1px, transparent 1px),
            linear-gradient(to bottom, white 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      />
      <motion.div
        className="absolute inset-0 bg-gradient-to-b from-transparent via-cyan-500/5 to-transparent"
        animate={{
          opacity: [0.3, 0.6, 0.3],
        }}
        transition={{
          duration: 4,
          repeat: Infinity,
          repeatType: 'reverse',
        }}
      />
    </div>
  );
}

export default AnimatedGrid;
