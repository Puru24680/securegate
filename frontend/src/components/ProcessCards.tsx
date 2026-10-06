import React from 'react';

interface ProcessCardsProps {
  onSelectPhase?: (phaseIndex: number) => void;
}

export const ProcessCards: React.FC<ProcessCardsProps> = ({ onSelectPhase }) => {
  const steps = [
    {
      step: '01',
      title: 'Target Ingestion',
      duration: '1 min',
      highlight: false,
      tags: ['OWASP Juice Shop', 'Endpoint Crawl', 'Port 3000'],
      description: 'Authorized baseline targeting local vulnerable application instances.',
    },
    {
      step: '02',
      title: 'DAST Normalization',
      duration: '35 sec',
      highlight: true, // Signature highlight from Image 2
      tags: ['ZAP JSON Alerts', 'Deduplication', 'CWE / OWASP 2021'],
      description: 'Strips noise, deduplicates signatures, and maps alerts to OWASP Top 10.',
    },
    {
      step: '03',
      title: 'Posture Scoring',
      duration: 'Realtime',
      highlight: false,
      tags: ['Diminishing Penalty', 'Confidence Multiplier', 'Score / 100'],
      description: 'Deterministic mathematical algorithm balancing exploit severity and confidence.',
    },
    {
      step: '04',
      title: 'Release Gate',
      duration: 'Instant',
      highlight: false,
      tags: ['PASS / REVIEW / BLOCK', 'CI/CD Pipeline Stop', 'Audit Dossier'],
      description: 'Enforces strict production threshold policy before code is promoted.',
    },
  ];

  return (
    <div className="space-y-4 select-none">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-emerald-600 font-bold bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200">
            Phase &bull; Execution Pipeline
          </span>
          <h3 className="text-xl font-bold font-display text-slate-900 mt-1">
            Gate Architecture Workflow
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">4 Automated Stages</span>
      </div>

      {/* 4 Monolith Cards Side-by-Side (Matching Image 2 Orbit AI) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {steps.map((item, idx) => (
          <div
            key={idx}
            onClick={() => onSelectPhase && onSelectPhase(idx)}
            className={`rounded-3xl p-6 flex flex-col justify-between min-h-[300px] transition-all duration-200 cursor-pointer ${
              item.highlight
                ? 'bg-emerald-900 text-white shadow-md border border-emerald-800'
                : 'bg-white text-slate-900 border border-slate-200/80 shadow-sm hover:border-slate-300 hover:shadow-md'
            }`}
          >
            {/* Top Row: Constellation Dots Icon & Duration Badge */}
            <div className="flex items-center justify-between">
              {/* Three dots constellation icon */}
              <div className="flex items-center gap-1 opacity-70">
                <span className={`w-1.5 h-1.5 rounded-full ${item.highlight ? 'bg-white' : 'bg-slate-400'}`} />
                <span className={`w-1.5 h-1.5 rounded-full -mt-1 ${item.highlight ? 'bg-white' : 'bg-slate-400'}`} />
                <span className={`w-1.5 h-1.5 rounded-full ${item.highlight ? 'bg-white' : 'bg-slate-400'}`} />
              </div>

              <span className={`text-xs font-mono ${item.highlight ? 'text-emerald-200' : 'text-slate-400'}`}>
                {item.duration}
              </span>
            </div>

            {/* Middle: Step Title & Description */}
            <div className="space-y-2 my-auto py-4">
              <span className={`text-[10px] font-mono uppercase tracking-widest font-bold block ${item.highlight ? 'text-emerald-300' : 'text-emerald-600'}`}>
                Stage {item.step}
              </span>
              <h4 className="text-xl font-bold font-display tracking-tight">
                {item.title}
              </h4>
              <p className={`text-xs font-sans leading-relaxed ${item.highlight ? 'text-emerald-100/80' : 'text-slate-500'}`}>
                {item.description}
              </p>
            </div>

            {/* Bottom: Rounded Pill Buttons for Tags */}
            <div className={`flex flex-wrap gap-1.5 pt-4 border-t ${item.highlight ? 'border-emerald-800/80' : 'border-slate-100'}`}>
              {item.tags.map((tag, tIdx) => (
                <span
                  key={tIdx}
                  className={`px-2.5 py-1 rounded-full text-[10px] font-mono ${
                    item.highlight
                      ? 'bg-emerald-800/80 text-emerald-100 border border-emerald-700'
                      : 'bg-slate-100 text-slate-600 border border-slate-200'
                  }`}
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
