import React from 'react';

interface MotionBlurTitleProps {
  label?: string;
  title: string;
  className?: string;
}

export const MotionBlurTitle: React.FC<MotionBlurTitleProps> = ({
  label = 'Phase',
  title,
  className = '',
}) => {
  return (
    <div className={`space-y-1 select-none ${className}`}>
      {label && (
        <span className="text-[11px] font-mono uppercase tracking-[0.25em] text-slate-400 font-medium block">
          {label}
        </span>
      )}
      <div className="relative inline-block">
        {/* Layer 3: Farthest motion blur ghost */}
        <span
          aria-hidden="true"
          className="absolute -left-3 top-0 text-white/10 blur-[8px] font-black font-display text-4xl sm:text-6xl lg:text-7xl tracking-tighter"
        >
          {title}
        </span>
        {/* Layer 2: Mid motion blur trail */}
        <span
          aria-hidden="true"
          className="absolute -left-1.5 top-0 text-white/30 blur-[3px] font-black font-display text-4xl sm:text-6xl lg:text-7xl tracking-tighter"
        >
          {title}
        </span>
        {/* Layer 1: Crisp foreground text */}
        <h2 className="relative font-black font-display text-4xl sm:text-6xl lg:text-7xl tracking-tighter text-white">
          {title}
        </h2>
      </div>
    </div>
  );
};
