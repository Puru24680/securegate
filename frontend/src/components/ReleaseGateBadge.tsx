import React from 'react';
import { ReleaseStatus } from '../types';
import { cn } from '../utils/cn';
import { ShieldAlert, ShieldCheck, AlertTriangle, Clock } from 'lucide-react';

interface ReleaseGateBadgeProps {
  status: ReleaseStatus | string;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const ReleaseGateBadge: React.FC<ReleaseGateBadgeProps> = ({
  status,
  className,
  size = 'md',
  showIcon = true,
}) => {
  const st = (status || 'PASS').toUpperCase();

  const config = {
    BLOCK: {
      bg: 'bg-rose-50 text-rose-700 border-rose-200',
      icon: ShieldAlert,
      label: 'Block',
      indicator: 'bg-rose-500',
    },
    REVIEW: {
      bg: 'bg-amber-50 text-amber-800 border-amber-200',
      icon: AlertTriangle,
      label: 'Review',
      indicator: 'bg-amber-500',
    },
    PASS: {
      bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      icon: ShieldCheck,
      label: 'Pass',
      indicator: 'bg-emerald-500',
    },
    PENDING: {
      bg: 'bg-slate-100 text-slate-700 border-slate-200',
      icon: Clock,
      label: 'Evaluating',
      indicator: 'bg-slate-400',
    },
  }[st] || {
    bg: 'bg-slate-100 text-slate-700 border-slate-200',
    icon: Clock,
    label: st,
    indicator: 'bg-slate-400',
  };

  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 gap-1.5 font-medium',
    md: 'text-xs px-2.5 py-0.5 gap-1.5 font-medium',
    lg: 'text-xs sm:text-sm px-3.5 py-1 gap-2 font-medium',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border transition-colors select-none',
        config.bg,
        sizeClasses,
        className
      )}
    >
      {showIcon && <Icon className="w-3.5 h-3.5 flex-shrink-0" />}
      <span>{config.label}</span>
    </span>
  );
};
