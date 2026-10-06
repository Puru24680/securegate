import React, { useState } from 'react';
import { Finding, FindingStatus, AIAnalysisResult } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { api } from '../services/api';
import {
  X,
  ShieldAlert,
  Terminal,
  ExternalLink,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  FileCode2,
  Network,
  Copy,
  Check,
  Loader2,
} from 'lucide-react';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusUpdated?: (updatedFinding: Finding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onStatusUpdated,
}) => {
  const [activeTab, setActiveTab] = useState<'details' | 'ai'>('details');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState(false);

  if (!finding) return null;

  const handleStatusChange = async (newStatus: FindingStatus) => {
    try {
      setUpdatingStatus(true);
      const updated = await api.updateFindingStatus(finding.id, newStatus);
      if (onStatusUpdated) onStatusUpdated(updated);
    } catch (err) {
      alert(`Failed to update status: ${err}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleExplainAI = async () => {
    setActiveTab('ai');
    if (aiResult) return;
    try {
      setAiLoading(true);
      const res = await api.explainFinding(finding.id);
      setAiResult(res);
    } catch (err) {
      alert(`AI Analysis error: ${err}`);
    } finally {
      setAiLoading(false);
    }
  };

  const copyEvidence = () => {
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence);
      setCopiedEvidence(true);
      setTimeout(() => setCopiedEvidence(false), 2000);
    }
  };

  const isBlocking = finding.severity === 'Critical' || finding.severity === 'High';
  const isReview = finding.severity === 'Medium';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/30 backdrop-blur-xs">
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-start justify-between p-6 border-b border-slate-100">
          <div className="space-y-1.5 pr-6">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} size="sm" />
              <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                {finding.cwe_id}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200 font-normal">
                {finding.owasp_category}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-md bg-slate-50 text-slate-500 border border-slate-200 capitalize">
                Status: {finding.status}
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold text-slate-900 tracking-tight">
              {finding.name}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-100 px-6 gap-2 bg-slate-50/50">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-2.5 px-3 text-xs font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'details'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Finding details</span>
          </button>
          <button
            onClick={handleExplainAI}
            className={`py-2.5 px-3 text-xs font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'ai'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            <span>AI remediation advisor</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {activeTab === 'details' ? (
            <>
              {/* Release Impact Callout Banner */}
              <div
                className={`p-4 rounded-lg border flex items-start gap-3 ${
                  isBlocking
                    ? 'bg-rose-50/70 border-rose-200 text-rose-900'
                    : isReview
                    ? 'bg-amber-50/70 border-amber-200 text-amber-900'
                    : 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
                }`}
              >
                <ShieldAlert className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-600" />
                <div className="space-y-0.5 text-xs">
                  <div className="font-semibold">
                    Gate policy impact:{' '}
                    {isBlocking ? 'Deployment blocked' : isReview ? 'Review required' : 'Passing'}
                  </div>
                  <p className="text-slate-600 leading-relaxed">
                    {isBlocking
                      ? `This finding triggers a release block due to ${finding.severity} severity policy violation.`
                      : isReview
                      ? 'This finding requires security sign-off before production release.'
                      : 'This finding satisfies the current release policy criteria.'}
                  </p>
                </div>
              </div>

              {/* Endpoint & Target Info */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium flex items-center gap-1.5">
                    <Network className="w-3 h-3 text-slate-600" /> Affected endpoint
                  </div>
                  <div className="text-xs text-slate-800 break-all font-medium">
                    <span className="font-semibold text-slate-700 mr-1.5 px-1.5 py-0.5 rounded bg-slate-200 text-[10px]">
                      {finding.method}
                    </span>
                    {finding.url || 'N/A'}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 space-y-1">
                  <div className="text-[11px] text-slate-500 font-medium flex items-center gap-1.5">
                    <Terminal className="w-3 h-3 text-amber-600" /> Vulnerable parameter
                  </div>
                  <div className="text-xs text-slate-800">
                    {finding.parameter ? (
                      <code className="bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200 text-amber-800 text-[11px]">
                        {finding.parameter}
                      </code>
                    ) : (
                      <span className="text-slate-400">None / Response header</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-semibold text-slate-700">
                  Description
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/80 text-xs text-slate-700 leading-relaxed">
                  {finding.description || 'No detailed description provided.'}
                </div>
              </div>

              {/* Attack Evidence */}
              {finding.evidence && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-slate-700">
                      Scanner evidence
                    </h3>
                    <button
                      onClick={copyEvidence}
                      className="text-xs text-slate-600 hover:text-slate-900 flex items-center gap-1 px-2 py-0.5 rounded border border-slate-200 bg-white hover:bg-slate-50 transition-colors cursor-pointer"
                    >
                      {copiedEvidence ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedEvidence ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-lg bg-slate-900 text-slate-100 text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {finding.evidence}
                  </pre>
                </div>
              )}

              {/* Remediation Guidance */}
              <div className="space-y-1.5">
                <h3 className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Remediation guidance
                </h3>
                <div className="p-3.5 rounded-lg bg-emerald-50/50 border border-emerald-200 text-xs text-emerald-950 leading-relaxed">
                  {finding.solution || 'Follow standard OWASP cheat sheet recommendations.'}
                </div>
              </div>

              {/* Reference Links */}
              {finding.reference && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-semibold text-slate-700">
                    References
                  </h3>
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/80 text-xs space-y-1">
                    {finding.reference.split('\n').map((refUrl, i) => (
                      refUrl.trim() && (
                        <div key={i} className="flex items-center gap-1.5 text-emerald-700 hover:underline">
                          <ExternalLink className="w-3 h-3 flex-shrink-0" />
                          <a href={refUrl.trim()} target="_blank" rel="noopener noreferrer" className="break-all">
                            {refUrl.trim()}
                          </a>
                        </div>
                      )
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            /* AI Advisor Tab */
            <div className="space-y-4">
              {aiLoading ? (
                <div className="py-16 text-center space-y-3">
                  <Loader2 className="w-6 h-6 animate-spin text-emerald-600 mx-auto" />
                  <p className="text-xs font-medium text-slate-700">
                    Consulting AI security advisor...
                  </p>
                </div>
              ) : aiResult ? (
                <div className="space-y-4">
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-center justify-between">
                    <span>Model: {aiResult.provider} {aiResult.model ? `(${aiResult.model})` : ''}</span>
                    <span className="text-emerald-700 font-medium">Verified AppSec guidance</span>
                  </div>

                  <div className="space-y-1.5">
                    <h4 className="text-xs font-semibold text-slate-800">
                      Summary
                    </h4>
                    <p className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 leading-relaxed">
                      {aiResult.analysis.plain_english_explanation}
                    </p>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                      <h4 className="text-xs font-semibold text-slate-800">
                        Business impact
                      </h4>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        {aiResult.analysis.business_impact}
                      </p>
                    </div>

                    <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                      <h4 className="text-xs font-semibold text-slate-800">
                        Technical impact
                      </h4>
                      <p className="text-xs text-slate-600 leading-relaxed">
                        {aiResult.analysis.technical_impact}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <h4 className="text-xs font-semibold text-slate-800">
                      Developer action items
                    </h4>
                    <div className="space-y-1.5">
                      {aiResult.analysis.developer_action_items.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 flex items-start gap-2.5"
                        >
                          <span className="w-4 h-4 rounded-full bg-slate-200 text-slate-700 flex items-center justify-center text-[10px] font-semibold flex-shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span className="leading-relaxed">{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="flex items-center justify-between p-4 border-t border-slate-100 bg-slate-50/50">
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleStatusChange('open')}
              disabled={updatingStatus || finding.status === 'open'}
              className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition-colors cursor-pointer disabled:opacity-40"
            >
              Mark as open
            </button>
            <button
              onClick={() => handleStatusChange('reviewed')}
              disabled={updatingStatus || finding.status === 'reviewed'}
              className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition-colors cursor-pointer disabled:opacity-40"
            >
              Mark as reviewed
            </button>
            <button
              onClick={() => handleStatusChange('fixed')}
              disabled={updatingStatus || finding.status === 'fixed'}
              className="px-3 py-1.5 text-xs rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium transition-colors cursor-pointer disabled:opacity-40 shadow-xs"
            >
              Mark as fixed
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
