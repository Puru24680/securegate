import React from 'react';
import { Severity } from '../types';
import { cn } from '../utils/cn';

interface SeverityBadgeProps {
  severity: Severity | string;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  className,
  size = 'md',
}) => {
  const sev = (severity || 'Low').toLowerCase();

  const styles = {
    critical: 'bg-rose-50 text-rose-700 border-rose-200',
    high: 'bg-orange-50 text-orange-700 border-orange-200',
    medium: 'bg-amber-50 text-amber-800 border-amber-200',
    low: 'bg-sky-50 text-sky-700 border-sky-200',
    informational: 'bg-slate-100 text-slate-600 border-slate-200',
  }[sev] || 'bg-slate-100 text-slate-600 border-slate-200';

  const dotColor = {
    critical: 'bg-rose-600',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-sky-500',
    informational: 'bg-slate-400',
  }[sev] || 'bg-slate-400';

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 gap-1.5 font-medium',
    md: 'text-xs px-2.5 py-0.5 gap-1.5 font-medium',
    lg: 'text-xs sm:text-sm px-3 py-1 gap-2 font-medium',
  }[size];

  // Title case the label
  const formattedLabel = severity
    ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()
    : 'Low';

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border transition-colors select-none',
        styles,
        sizeClasses,
        className
      )}
    >
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', dotColor)} />
      <span>{formattedLabel}</span>
    </span>
  );
};
