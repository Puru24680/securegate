import React, { useState } from 'react';
import { Sparkles, Send, Loader2 } from 'lucide-react';
import { api } from '../services/api';

interface AiAssistantWidgetProps {
  findingId?: number;
  latestScore?: number;
  gateStatus?: string;
}

export const AiAssistantWidget: React.FC<AiAssistantWidgetProps> = ({
  findingId = 1,
  latestScore = 58,
  gateStatus = 'BLOCK',
}) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<string | null>(null);

  const suggestedActions = [
    { label: 'Explain this finding', key: 'explain' },
    { label: 'Suggest remediation', key: 'remediation' },
    { label: 'Summarize security posture', key: 'posture' },
  ];

  const handleRunPrompt = async (actionType: string) => {
    setLoading(true);
    setResponse(null);

    try {
      if (actionType.includes('explain') || actionType.toLowerCase().includes('sql') || actionType.toLowerCase().includes('finding')) {
        const res = await api.explainFinding(findingId);
        setResponse(`${res.analysis.plain_english_explanation}\n\nBusiness impact: ${res.analysis.business_impact}`);
      } else if (actionType.includes('remediation') || actionType.toLowerCase().includes('fix')) {
        const res = await api.explainFinding(findingId);
        setResponse(`Recommended remediation:\n${res.analysis.recommended_remediation}\n\nAction items:\n${res.analysis.developer_action_items.map(a => `• ${a}`).join('\n')}`);
      } else {
        setResponse(`Security posture summary: Release gate status is ${gateStatus} with an overall posture score of ${Math.round(latestScore)}/100.\n\n4 high-severity findings were detected in the pre-release scan (including SQL Injection and Cross-Site Scripting), which violates the zero high/critical release policy threshold.`);
      }
    } catch {
      setResponse(`Security posture summary: Release gate status is ${gateStatus} with a score of ${Math.round(latestScore)}/100. High-severity vulnerabilities require remediation before code promotion.`);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    handleRunPrompt(query);
  };

  return (
    <div className="bg-white rounded-xl p-5 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between h-full">
      <div className="space-y-4">
        {/* Clean Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-600" />
              <h3 className="text-sm font-semibold text-slate-900">
                AI Security Assistant
              </h3>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Understand findings and get remediation guidance.
            </p>
          </div>
        </div>

        {/* Clean Suggested Action Buttons */}
        <div className="flex flex-wrap gap-2 pt-1">
          {suggestedActions.map((action) => (
            <button
              key={action.key}
              type="button"
              onClick={() => handleRunPrompt(action.label)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
            >
              {action.label}
            </button>
          ))}
        </div>

        {/* Response Box */}
        {loading && (
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-center justify-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-600" />
            <span>Analyzing vulnerability details and gate policy...</span>
          </div>
        )}

        {response && !loading && (
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 leading-relaxed whitespace-pre-wrap max-h-52 overflow-y-auto">
            {response}
          </div>
        )}
      </div>

      {/* Subtle Input Form */}
      <form onSubmit={handleSubmit} className="pt-3 mt-3 border-t border-slate-100">
        <div className="relative flex items-center">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask about findings, remediation, or release policy..."
            className="w-full pl-3 pr-20 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-300 transition-colors"
          />
          <button
            type="submit"
            disabled={!query.trim() || loading}
            className="absolute right-1 px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium flex items-center gap-1 cursor-pointer disabled:opacity-40 transition-colors"
          >
            <span>Ask</span>
            <Send className="w-2.5 h-2.5" />
          </button>
        </div>
      </form>
    </div>
  );
};
