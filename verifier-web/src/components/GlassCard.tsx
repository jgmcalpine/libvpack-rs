import { motion } from 'framer-motion';

interface GlassCardProps {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
  delay?: number;
  visible?: boolean;
  innerRef?: React.RefObject<HTMLDivElement | null>;
}

const glassStyles = 'backdrop-blur-md bg-white/5 border border-white/10 rounded-xl';

function GlassCard({
  children,
  onClick,
  className = '',
  delay = 0,
  visible = true,
  innerRef,
}: GlassCardProps) {
  return (
    <motion.div
      ref={innerRef}
      initial={{ opacity: 0, y: 12 }}
      animate={visible ? { opacity: 1, y: 0 } : { opacity: 0.5, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className={`relative ${glassStyles} ${onClick ? 'cursor-pointer hover:bg-white/10 hover:border-white/20 transition-colors' : ''} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      {children}
    </motion.div>
  );
}

export default GlassCard;
