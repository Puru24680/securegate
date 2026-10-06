import React, { useState } from 'react';
import { Sparkles, Send, Loader2, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import { Finding, Scan, ReleaseStatus } from '../types';

interface AiAssistantWidgetProps {
  activeScan?: Scan | null;
  releaseGate?: {
    status: ReleaseStatus;
    reason: string;
    version: string;
    blocking_findings: number;
    review_findings: number;
  };
  metrics?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    total_findings: number;
  };
  securityScore?: number;
  findings?: Finding[];
}

export const AiAssistantWidget: React.FC<AiAssistantWidgetProps> = ({
  activeScan,
  releaseGate,
  metrics = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total_findings: 0 },
  securityScore = 100,
  findings = [],
}) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<string | null>(null);

  const topFinding = findings.length > 0 ? findings[0] : null;
  const status = releaseGate?.status || (metrics.critical > 0 || metrics.high > 0 ? 'BLOCK' : metrics.medium > 0 ? 'REVIEW' : 'PASS');

  const generateDynamicPostureSummary = () => {
    const scanId = activeScan?.scan_identifier || 'Current scan';
    const score = Math.round(securityScore);

    if (status === 'BLOCK') {
      const critStr = metrics.critical > 0 ? `${metrics.critical} Critical` : '';
      const highStr = metrics.high > 0 ? `${metrics.high} High` : '';
      const violatingParts = [critStr, highStr].filter(Boolean).join(' and ');

      return `PRE-RELEASE SECURITY GATE DECISION: BLOCK\nTarget: ${activeScan?.target_url || 'Target Application'} | Scan: ${scanId} | Score: ${score}/100\n\nCurrent scan contains ${violatingParts || 'High/Critical'} vulnerabilities (${metrics.medium} Medium, ${metrics.low} Low, ${metrics.informational} Informational).\n\nPolicy: Critical and High findings are not permitted.\n\nAction: Fix the reported High/Critical vulnerabilities and run the security scan again before code promotion.`;
    }

    if (status === 'REVIEW') {
      return `PRE-RELEASE SECURITY GATE DECISION: REVIEW\nTarget: ${activeScan?.target_url || 'Target Application'} | Scan: ${scanId} | Score: ${score}/100\n\nCurrent scan contains 0 Critical and 0 High findings, with ${metrics.medium} Medium findings (${metrics.low} Low, ${metrics.informational} Informational).\n\nPolicy: Medium-severity findings require AppSec review and risk acceptance prior to release.\n\nAction: Review Medium findings with the security lead to sign off on candidate release.`;
    }

    return `PRE-RELEASE SECURITY GATE DECISION: PASS\nTarget: ${activeScan?.target_url || 'Target Application'} | Scan: ${scanId} | Score: ${score}/100\n\nNo Critical or High vulnerabilities detected (0 Critical, 0 High, ${metrics.medium} Medium, ${metrics.low} Low, ${metrics.informational} Informational).\n\nPolicy: All pre-release security gating criteria are satisfied.\n\nAction: Ready for release.`;
  };

  const handleRunPrompt = async (actionKey: string) => {
    setLoading(true);
    setResponse(null);

    try {
      if (actionKey === 'posture' || actionKey.toLowerCase().includes('summary') || actionKey.toLowerCase().includes('posture') || actionKey.toLowerCase().includes('gate')) {
        setResponse(generateDynamicPostureSummary());
      } else if (actionKey === 'explain' || actionKey.toLowerCase().includes('explain') || actionKey.toLowerCase().includes('finding')) {
        if (topFinding) {
          const res = await api.explainFinding(topFinding.id);
          setResponse(
            `Vulnerability: ${topFinding.name} [${topFinding.severity.toUpperCase()} • ${topFinding.cwe_id || 'CWE'}]\nEndpoint: ${topFinding.method} ${topFinding.url}\n\nAnalysis:\n${res.analysis.plain_english_explanation}\n\nTechnical Impact:\n${res.analysis.technical_impact}\n\nBusiness Impact:\n${res.analysis.business_impact}\n\nGate Impact: ${
              topFinding.severity === 'Critical' || topFinding.severity === 'High'
                ? 'BLOCK — High/Critical findings strictly violate the release gate policy.'
                : topFinding.severity === 'Medium'
                ? 'REVIEW — Medium findings require security sign-off.'
                : 'PASS — Non-blocking finding satisfies policy.'
            }`
          );
        } else {
          setResponse(generateDynamicPostureSummary());
        }
      } else if (actionKey === 'remediation' || actionKey.toLowerCase().includes('remediation') || actionKey.toLowerCase().includes('fix')) {
        if (topFinding) {
          const res = await api.explainFinding(topFinding.id);
          const actions = res.analysis.developer_action_items.map((item, idx) => `${idx + 1}. ${item}`).join('\n');
          setResponse(
            `Remediation Guidance for ${topFinding.name}:\n${res.analysis.recommended_remediation}\n\nDeveloper Action Items:\n${actions}\n\nScan Solution: ${topFinding.solution || 'Apply standard defensive coding standards.'}`
          );
        } else {
          setResponse(`No active findings require remediation. All security gating checks passed.`);
        }
      } else {
        // Natural language query
        if (topFinding) {
          const res = await api.explainFinding(topFinding.id);
          setResponse(
            `Analysis regarding "${query}":\n\n${res.analysis.plain_english_explanation}\n\nRecommended Action:\n${res.analysis.recommended_remediation}`
          );
        } else {
          setResponse(generateDynamicPostureSummary());
        }
      }
    } catch {
      setResponse(generateDynamicPostureSummary());
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
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-600" />
              <h3 className="text-sm font-semibold text-slate-900">
                Security Analysis Assistant
              </h3>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Deterministic gate evaluation & AppSec remediation advisory
            </p>
          </div>
          <span className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider ${
            status === 'BLOCK' ? 'bg-rose-50 text-rose-700 border border-rose-200' :
            status === 'REVIEW' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
            'bg-emerald-50 text-emerald-700 border border-emerald-200'
          }`}>
            {status}
          </span>
        </div>

        {/* Suggested Action Buttons */}
        <div className="flex flex-wrap gap-2 pt-1">
          <button
            type="button"
            onClick={() => handleRunPrompt('posture')}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
          >
            Summarize active scan
          </button>
          {topFinding && (
            <>
              <button
                type="button"
                onClick={() => handleRunPrompt('explain')}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
              >
                Explain top finding
              </button>
              <button
                type="button"
                onClick={() => handleRunPrompt('remediation')}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
              >
                Remediation guidance
              </button>
            </>
          )}
        </div>

        {/* Response Box */}
        {loading && (
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-center justify-center gap-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-600" />
            <span>Analyzing active scan context and policy rules...</span>
          </div>
        )}

        {response && !loading && (
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 leading-relaxed whitespace-pre-wrap max-h-56 overflow-y-auto font-mono text-[11px]">
            {response}
          </div>
        )}
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="pt-3 mt-3 border-t border-slate-100">
        <div className="relative flex items-center">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask about active findings, gate policy, or remediation..."
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
