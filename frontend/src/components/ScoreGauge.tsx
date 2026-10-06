import React from 'react';
import { cn } from '../utils/cn';

interface ScoreGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  size = 150,
  strokeWidth = 9,
  className,
}) => {
  const normalizedScore = Math.max(0, Math.min(100, score));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (normalizedScore / 100) * circumference;

  const getColor = (val: number) => {
    if (val >= 90) return '#10b981'; // emerald
    if (val >= 75) return '#f59e0b'; // amber
    return '#ef4444'; // red
  };

  const getLabel = (val: number) => {
    if (val >= 90) return 'EXCELLENT';
    if (val >= 75) return 'ACCEPTABLE';
    if (val >= 50) return 'ELEVATED RISK';
    return 'CRITICAL BREACH';
  };

  const color = getColor(normalizedScore);

  return (
    <div className={cn('relative flex flex-col items-center justify-center select-none', className)}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#E2E8F0"
          strokeWidth={strokeWidth}
        />
        {/* Progress track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>

      {/* Center typography */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-4xl font-extrabold tracking-tight font-display text-slate-900">
          {Math.round(normalizedScore)}
        </span>
        <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase -mt-0.5">
          / 100
        </span>
      </div>

      <div
        className="mt-3 text-[10px] font-mono font-bold tracking-widest uppercase px-3 py-0.5 rounded-full border transition-all"
        style={{
          color,
          backgroundColor: `${color}10`,
          borderColor: `${color}30`,
        }}
      >
        {getLabel(normalizedScore)}
      </div>
    </div>
  );
};
