import React from 'react';
import { Shield, Sparkles, CheckCircle2 } from 'lucide-react';

interface OrbitSpecCardProps {
  targetName?: string;
  scannerName?: string;
  policyName?: string;
  gateStatus?: string;
}

export const OrbitSpecCard: React.FC<OrbitSpecCardProps> = ({
  targetName = 'OWASP Juice Shop',
  scannerName = 'OWASP ZAP 2.14',
  policyName = 'Zero High Tolerance',
  gateStatus = 'BLOCKED',
}) => {
  const isBlocked = gateStatus === 'BLOCK' || gateStatus === 'BLOCKED';
  const isReview = gateStatus === 'REVIEW';

  return (
    <div className="rounded-3xl p-6 sm:p-8 border border-slate-200/80 bg-white shadow-sm">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left: Spec Sheet Columns */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 sm:gap-10 font-sans">
          <div className="space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
              Target Application
            </span>
            <div className="text-sm sm:text-base font-bold text-slate-900 font-display">
              {targetName}
            </div>
            <span className="text-[11px] text-slate-500 block">
              Local Staging Container
            </span>
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
              Detection Engine
            </span>
            <div className="text-sm sm:text-base font-bold text-slate-900 font-display">
              {scannerName}
            </div>
            <span className="text-[11px] text-slate-500 block">
              DAST Dynamic Scanner
            </span>
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
              Gating Threshold
            </span>
            <div className="text-sm sm:text-base font-bold text-slate-900 font-display">
              {policyName}
            </div>
            <span className="text-[11px] text-slate-500 block">
              Strict Production Gate
            </span>
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
              Gate Verdict
            </span>
            <div className="flex items-center gap-2">
              <span
                className={`text-sm sm:text-base font-bold font-mono tracking-wider ${
                  isBlocked
                    ? 'text-rose-600'
                    : isReview
                    ? 'text-amber-600'
                    : 'text-emerald-600'
                }`}
              >
                {gateStatus}
              </span>
              <span
                className={`w-2 h-2 rounded-full ${
                  isBlocked
                    ? 'bg-rose-500 animate-ping'
                    : isReview
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
              />
            </div>
            <span className="text-[11px] text-slate-500 block">
              Deterministic Engine
            </span>
          </div>
        </div>

        {/* Right: Signature Orbital Brand Mark */}
        <div className="flex items-center gap-4 flex-shrink-0 lg:border-l lg:border-slate-100 lg:pl-8">
          <div className="relative w-11 h-11 flex items-center justify-center">
            {/* Outer ring */}
            <div className="absolute inset-0 rounded-full border border-emerald-400/50 animate-[spin_8s_linear_infinite]" />
            {/* Tilted elliptical ring */}
            <div className="absolute inset-0.5 rounded-full border border-slate-300 transform -rotate-45" />
            {/* Center dot */}
            <div className="w-3.5 h-3.5 rounded-full bg-emerald-500 shadow-sm" />
          </div>
          <div>
            <div className="text-lg font-black font-display tracking-tight text-slate-900 flex items-center gap-1">
              SECURE<span className="text-emerald-600">GATE</span>
              <span className="text-[9px] font-mono uppercase bg-emerald-50 text-emerald-700 px-1.5 py-0.2 rounded border border-emerald-200 ml-1">
                PRE-RELEASE
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400 tracking-wider uppercase block">
              DevSecOps Gating System
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
