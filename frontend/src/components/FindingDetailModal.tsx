import React, { useState, useEffect } from 'react';
import { Finding, FindingStatus, AIAnalysisResult, FindingOccurrence } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { api } from '../services/api';
import {
  X,
  ShieldAlert,
  ShieldCheck,
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
  Info,
  Calendar,
  Fingerprint,
  History,
  Lock,
  Flag,
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
  const [activeTab, setActiveTab] = useState<'details' | 'ai' | 'timeline'>('details');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [occurrences, setOccurrences] = useState<FindingOccurrence[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  // Risk acceptance dialog state
  const [isAcceptRiskOpen, setIsAcceptRiskOpen] = useState(false);
  const [justification, setJustification] = useState('');
  const [approvedBy, setApprovedBy] = useState('');
  const [daysValid, setDaysValid] = useState(90);
  const [acceptingRisk, setAcceptingRisk] = useState(false);

  // False positive dialog state
  const [isFalsePositiveOpen, setIsFalsePositiveOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [submittingFp, setSubmittingFp] = useState(false);

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

  const handleAcceptRiskSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!justification.trim()) {
      alert('Business justification is required');
      return;
    }
    try {
      setAcceptingRisk(true);
      const res = await api.acceptRisk(finding.id, {
        justification: justification.trim(),
        approved_by: approvedBy.trim() || undefined,
        days_valid: daysValid,
      });
      setIsAcceptRiskOpen(false);
      setJustification('');
      if (onStatusUpdated) onStatusUpdated(res.finding);
    } catch (err) {
      alert(`Failed to accept risk: ${err}`);
    } finally {
      setAcceptingRisk(false);
    }
  };

  const handleFalsePositiveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fpReason.trim()) {
      alert('Technical reason is required');
      return;
    }
    try {
      setSubmittingFp(true);
      const res = await api.markFalsePositive(finding.id, {
        reason: fpReason.trim(),
      });
      setIsFalsePositiveOpen(false);
      setFpReason('');
      if (onStatusUpdated) onStatusUpdated(res.finding);
    } catch (err) {
      alert(`Failed to mark false positive: ${err}`);
    } finally {
      setSubmittingFp(false);
    }
  };

  const handleLoadTimeline = async () => {
    setActiveTab('timeline');
    try {
      setLoadingTimeline(true);
      const res = await api.getFindingOccurrences(finding.id);
      setOccurrences(res.occurrences);
    } catch (err) {
      console.error('Failed to load occurrences:', err);
    } finally {
      setLoadingTimeline(false);
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

  const isCritical = finding.severity === 'Critical';
  const isHigh = finding.severity === 'High';
  const isMedium = finding.severity === 'Medium';
  const isBlocking = (isCritical || isHigh) && finding.status !== 'accepted' && finding.status !== 'false_positive';

  const gateImpactText =
    finding.status === 'accepted'
      ? 'EXCEPTION — Risk formally accepted by security governance. Does not block release.'
      : finding.status === 'false_positive'
      ? 'SUPPRESSED — Marked as False Positive. Excluded from release gating.'
      : isBlocking
      ? `BLOCK — ${finding.severity} severity finding violates release gate policy.`
      : isMedium
      ? `REVIEW — Medium severity finding requires security sign-off before release.`
      : `PASS — ${finding.severity} severity finding satisfies release gate policy.`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/40 backdrop-blur-xs">
      <div className="relative w-full max-w-3xl max-h-[92vh] flex flex-col bg-white border border-slate-200 rounded-xl shadow-2xl overflow-hidden font-sans">
        {/* Modal Header */}
        <div className="flex items-start justify-between p-6 border-b border-slate-100">
          <div className="space-y-1.5 pr-6">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} size="sm" />
              {finding.status === 'accepted' ? (
                <span className="text-xs px-2 py-0.5 rounded-md bg-amber-50 text-amber-800 border border-amber-200 font-bold">
                  Accepted Risk
                </span>
              ) : finding.status === 'false_positive' ? (
                <span className="text-xs px-2 py-0.5 rounded-md bg-blue-50 text-blue-800 border border-blue-200 font-bold">
                  False Positive
                </span>
              ) : (
                <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200 capitalize font-medium">
                  Status: {finding.status}
                </span>
              )}

              <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                {finding.cwe_id || 'CWE Unspecified'}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200 font-normal">
                {finding.owasp_category || 'OWASP Top 10'}
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
            onClick={handleLoadTimeline}
            className={`py-2.5 px-3 text-xs font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'timeline'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Scan History & Recurrence</span>
          </button>
          <button
            onClick={handleExplainAI}
            className={`py-2.5 px-3 text-xs font-medium border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'ai'
                ? 'border-emerald-600 text-emerald-700'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            <span>AI Copilot Analysis</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'details' && (
            <div className="space-y-6">
              {/* Release Gate Impact Banner */}
              <div
                className={`p-3.5 rounded-lg border flex items-start gap-3 ${
                  finding.status === 'accepted'
                    ? 'bg-amber-50/70 border-amber-200 text-amber-900'
                    : finding.status === 'false_positive'
                    ? 'bg-blue-50/70 border-blue-200 text-blue-900'
                    : isBlocking
                    ? 'bg-red-50/70 border-red-200 text-red-900'
                    : isMedium
                    ? 'bg-amber-50/70 border-amber-200 text-amber-900'
                    : 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
                }`}
              >
                {finding.status === 'accepted' ? (
                  <Lock className="w-4 h-4 text-amber-700 mt-0.5 flex-shrink-0" />
                ) : finding.status === 'false_positive' ? (
                  <Flag className="w-4 h-4 text-blue-700 mt-0.5 flex-shrink-0" />
                ) : isBlocking ? (
                  <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-emerald-600 mt-0.5 flex-shrink-0" />
                )}
                <div className="text-xs">
                  <div className="font-semibold mb-0.5">Release Gate Evaluation</div>
                  <div className="leading-relaxed opacity-90">{gateImpactText}</div>
                </div>
              </div>

              {/* Fingerprint & Deduplication Metadata */}
              {finding.fingerprint && (
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
                  <div className="flex items-center justify-between text-slate-500">
                    <span className="flex items-center gap-1 font-semibold text-slate-700">
                      <Fingerprint className="w-3.5 h-3.5 text-slate-500" />
                      Canonical Vulnerability Fingerprint:
                    </span>
                    <span className="font-mono text-[10px] text-slate-500 truncate max-w-xs">
                      {finding.fingerprint}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-[11px] text-slate-500 pt-1">
                    <span>First Seen: {finding.first_seen ? new Date(finding.first_seen).toLocaleDateString() : 'N/A'}</span>
                    <span>Last Observed: {finding.last_seen ? new Date(finding.last_seen).toLocaleDateString() : 'N/A'}</span>
                    <span>Confidence: {finding.confidence}</span>
                  </div>
                </div>
              )}

              {/* Vulnerability Description */}
              <div>
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                  Vulnerability Description
                </h3>
                <p className="text-xs text-slate-600 leading-relaxed whitespace-pre-line bg-slate-50 p-3.5 rounded-lg border border-slate-100">
                  {finding.description || 'No description provided.'}
                </p>
              </div>

              {/* Endpoint & Parameter */}
              <div>
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                  Affected Endpoint & Parameter
                </h3>
                <div className="bg-slate-900 rounded-lg p-3 text-slate-200 text-xs font-mono space-y-1.5 overflow-x-auto">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-400 font-bold">{finding.method || 'GET'}</span>
                    <span className="text-slate-100">{finding.url || finding.endpoint || 'N/A'}</span>
                  </div>
                  {finding.parameter && (
                    <div className="text-slate-400 text-[11px]">
                      Parameter: <span className="text-amber-300">{finding.parameter}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Attack Evidence */}
              {finding.evidence && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Attack Vector & Evidence
                    </h3>
                    <button
                      onClick={copyEvidence}
                      className="text-xs text-slate-500 hover:text-slate-800 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedEvidence ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedEvidence ? 'Copied' : 'Copy payload'}</span>
                    </button>
                  </div>
                  <pre className="bg-slate-900 text-emerald-400 p-3 rounded-lg text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-40">
                    {finding.evidence}
                  </pre>
                </div>
              )}

              {/* Recommended Fix */}
              {finding.solution && (
                <div>
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                    Remediation Guidance
                  </h3>
                  <div className="p-3.5 rounded-lg bg-emerald-50/60 border border-emerald-200 text-xs text-slate-700 leading-relaxed">
                    {finding.solution}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Scan Occurrences & Timeline
              </h3>
              {loadingTimeline ? (
                <div className="p-8 text-center text-xs text-slate-400">Loading historical occurrences...</div>
              ) : occurrences.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 bg-slate-50 rounded-lg">
                  No previous occurrences recorded. This finding is newly discovered in this scan.
                </div>
              ) : (
                <div className="space-y-3">
                  {occurrences.map((occ, idx) => (
                    <div key={occ.id} className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-800">
                          Occurrence #{occurrences.length - idx} (Scan #{occ.scan_id})
                        </span>
                        <span className="text-slate-400 font-mono text-[11px]">
                          {new Date(occ.created_at).toLocaleString()}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] text-slate-600">
                        {occ.method} {occ.url}
                      </div>
                      {occ.parameter && (
                        <div className="text-[11px] text-slate-500">
                          Parameter: <span className="text-slate-700 font-mono">{occ.parameter}</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai' && (
            <div className="space-y-4">
              {aiLoading ? (
                <div className="p-12 text-center space-y-3">
                  <Loader2 className="w-6 h-6 animate-spin mx-auto text-emerald-600" />
                  <div className="text-xs text-slate-500">Analyzing vulnerability context and code remediation...</div>
                </div>
              ) : aiResult ? (
                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                    <div className="text-xs font-bold text-slate-900">Plain English Explanation</div>
                    <div className="text-xs text-slate-700 leading-relaxed">
                      {aiResult.analysis.plain_english_explanation}
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-emerald-50 border border-emerald-200 space-y-2">
                    <div className="text-xs font-bold text-emerald-900">Recommended Fix</div>
                    <div className="text-xs text-emerald-800 leading-relaxed whitespace-pre-wrap font-mono">
                      {aiResult.analysis.recommended_remediation}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </div>

        {/* Modal Governance Footer */}
        <div className="flex items-center justify-between p-4 border-t border-slate-100 bg-slate-50/50">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setIsAcceptRiskOpen(true)}
              className="px-3 py-1.5 text-xs rounded-lg border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-800 font-medium transition cursor-pointer"
            >
              Accept Risk
            </button>
            <button
              onClick={() => setIsFalsePositiveOpen(true)}
              className="px-3 py-1.5 text-xs rounded-lg border border-blue-300 bg-blue-50 hover:bg-blue-100 text-blue-800 font-medium transition cursor-pointer"
            >
              False Positive
            </button>
            <button
              onClick={() => handleStatusChange('resolved')}
              disabled={updatingStatus || finding.status === 'resolved'}
              className="px-3 py-1.5 text-xs rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium transition cursor-pointer disabled:opacity-40"
            >
              Mark Resolved
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>

      {/* Accept Risk Dialog */}
      {isAcceptRiskOpen && (
        <div className="fixed inset-0 z-60 flex items-center justify-center p-4 bg-slate-900/40">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-2xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Formal Risk Acceptance</h3>
            <p className="text-xs text-slate-500">
              Provide a valid business justification to accept the security risk of this finding.
            </p>
            <form onSubmit={handleAcceptRiskSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Justification <span className="text-red-500">*</span>
                </label>
                <textarea
                  rows={3}
                  placeholder="Compensating WAF rule deployed; risk accepted until sprint 24 refactor."
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Approver Name</label>
                  <input
                    type="text"
                    placeholder="Security Lead"
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Days Valid</label>
                  <select
                    value={daysValid}
                    onChange={(e) => setDaysValid(parseInt(e.target.value, 10))}
                    className="w-full p-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  >
                    <option value={30}>30 Days</option>
                    <option value={60}>60 Days</option>
                    <option value={90}>90 Days</option>
                    <option value={180}>180 Days</option>
                  </select>
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAcceptRiskOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={acceptingRisk}
                  className="px-4 py-1.5 text-xs bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-semibold"
                >
                  {acceptingRisk ? 'Submitting...' : 'Sign Off & Accept'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* False Positive Dialog */}
      {isFalsePositiveOpen && (
        <div className="fixed inset-0 z-60 flex items-center justify-center p-4 bg-slate-900/40">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-2xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Mark as False Positive</h3>
            <p className="text-xs text-slate-500">
              Provide technical rationale explaining why this finding is a false positive.
            </p>
            <form onSubmit={handleFalsePositiveSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Technical Explanation <span className="text-red-500">*</span>
                </label>
                <textarea
                  rows={3}
                  placeholder="Header is intentionally stripped at CDN proxy layer before hitting client."
                  value={fpReason}
                  onChange={(e) => setFpReason(e.target.value)}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                  required
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsFalsePositiveOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingFp}
                  className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold"
                >
                  {submittingFp ? 'Submitting...' : 'Confirm False Positive'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
