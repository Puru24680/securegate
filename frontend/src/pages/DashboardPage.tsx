import React, { useState, useEffect, useMemo } from 'react';
import { DashboardData, Finding } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingDetailModal } from '../components/FindingDetailModal';
import { AiAssistantWidget } from '../components/AiAssistantWidget';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronRight,
  CheckCircle2,
  Lock,
  ArrowRight,
  Info,
} from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface DashboardPageProps {
  data: DashboardData | null;
  loading: boolean;
  onNavigate: (tab: string) => void;
  onOpenNewScan: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  data,
  loading,
  onNavigate,
  onOpenNewScan,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);

  useEffect(() => {
    if (data?.latest_scan?.id) {
      api.getFindings({ scan_id: data.latest_scan.id, per_page: 50 })
        .then((res) => {
          setLiveFindings(res?.findings || []);
        })
        .catch(() => {
          setLiveFindings([]);
        });
    } else {
      setLiveFindings([]);
    }
  }, [data?.latest_scan?.id]);

  const activeFindings = liveFindings;

  const actualScanHistory = useMemo(() => {
    const scans = data?.recent_scans || [];
    if (scans.length <= 1) return [];
    return [...scans].reverse().map((s) => ({
      date: new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      security_score: Math.round(s.security_score),
      scan_identifier: s.scan_identifier,
    }));
  }, [data?.recent_scans]);

  const cleanUrl = (url: string) => {
    try {
      if (url.startsWith('http://') || url.startsWith('https://')) {
        const u = new URL(url);
        return u.pathname + u.search;
      }
      return url;
    } catch {
      return url;
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse font-sans">
        <div className="h-8 bg-slate-200/70 rounded-lg w-48" />
        <div className="h-40 bg-slate-200/70 rounded-xl w-full" />
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-24 bg-slate-200/70 rounded-xl" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-6 h-64 bg-slate-200/70 rounded-xl" />
          <div className="lg:col-span-6 h-64 bg-slate-200/70 rounded-xl" />
        </div>
      </div>
    );
  }

  if (!data || data.empty) {
    return (
      <div className="py-20 text-center max-w-md mx-auto space-y-4 bg-white p-8 rounded-xl border border-slate-200 shadow-xs font-sans">
        <div className="w-12 h-12 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-200 flex items-center justify-center mx-auto">
          <Shield className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-base font-semibold text-slate-900">No Security Scans Recorded</h3>
          <p className="text-xs text-slate-500">
            Import an OWASP ZAP scan to evaluate pre-release security gating.
          </p>
        </div>
        <button
          onClick={onOpenNewScan}
          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium cursor-pointer shadow-xs transition-colors"
        >
          Import scan
        </button>
      </div>
    );
  }

  const { release_gate, metrics, latest_scan, security_score, project, release_policy } = data;
  const isBlocked = release_gate.status === 'BLOCK';
  const isReview = release_gate.status === 'REVIEW';
  const isPass = release_gate.status === 'PASS';

  const formatScanTime = (dateStr?: string) => {
    if (!dateStr) return 'Recently';
    try {
      const d = new Date(dateStr);
      const diffMinutes = Math.floor((Date.now() - d.getTime()) / 60000);
      if (diffMinutes < 1) return 'Just now';
      if (diffMinutes < 60) return `${diffMinutes} minutes ago`;
      const diffHours = Math.floor(diffMinutes / 60);
      if (diffHours < 24) return `${diffHours} hours ago`;
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
      return 'Recently';
    }
  };

  const totalFindingsCount =
    metrics.total_findings ||
    metrics.critical + metrics.high + metrics.medium + metrics.low + metrics.informational;

  // Exact policy mappings from configuration or defaults
  const policyRules = [
    { severity: 'Critical', action: (release_policy?.critical || 'BLOCK').toUpperCase(), color: 'text-rose-700 bg-rose-50 border-rose-200' },
    { severity: 'High', action: (release_policy?.high || 'BLOCK').toUpperCase(), color: 'text-rose-700 bg-rose-50 border-rose-200' },
    { severity: 'Medium', action: (release_policy?.medium || 'REVIEW').toUpperCase(), color: 'text-amber-800 bg-amber-50 border-amber-200' },
    { severity: 'Low', action: (release_policy?.low || 'PASS').toUpperCase(), color: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
    { severity: 'Informational', action: (release_policy?.informational || 'PASS').toUpperCase(), color: 'text-slate-700 bg-slate-50 border-slate-200' },
  ];

  return (
    <div className="space-y-6 select-none max-w-7xl font-sans">
      {/* 1. Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Dashboard
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            {project?.name || 'OWASP Juice Shop'} &bull; Active scan: <span className="font-mono text-slate-700 font-semibold">{latest_scan?.scan_identifier || 'N/A'}</span> ({formatScanTime(latest_scan?.created_at)})
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenNewScan}
            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium cursor-pointer shadow-xs transition-colors"
          >
            Import scan
          </button>
        </div>
      </div>

      {/* 2. PRE-RELEASE SECURITY GATE HERO SECTION (Dominant Primary Feature) */}
      <div
        className={`p-6 sm:p-7 rounded-2xl bg-white border shadow-[0_2px_8px_rgba(0,0,0,0.04)] relative overflow-hidden ${
          isBlocked
            ? 'border-rose-200 border-l-[6px] border-l-rose-600 bg-gradient-to-r from-rose-50/20 to-white'
            : isReview
            ? 'border-amber-200 border-l-[6px] border-l-amber-500 bg-gradient-to-r from-amber-50/20 to-white'
            : 'border-emerald-200 border-l-[6px] border-l-emerald-600 bg-gradient-to-r from-emerald-50/20 to-white'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-bold tracking-wider uppercase text-slate-500 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5" />
                PRE-RELEASE SECURITY GATE
              </span>
              <span className="text-slate-300">&bull;</span>
              <span className="text-xs text-slate-500">
                Release Gate Decision
              </span>
            </div>

            <div className="flex items-center gap-4 flex-wrap">
              <span
                className={`text-4xl sm:text-5xl font-extrabold tracking-tight ${
                  isBlocked ? 'text-rose-600' : isReview ? 'text-amber-600' : 'text-emerald-600'
                }`}
              >
                {release_gate.status}
              </span>
              <div className="space-y-0.5">
                <span
                  className={`inline-block px-3 py-1 text-xs font-bold rounded-md ${
                    isBlocked
                      ? 'bg-rose-100 text-rose-800 border border-rose-300'
                      : isReview
                      ? 'bg-amber-100 text-amber-900 border border-amber-300'
                      : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                  }`}
                >
                  {isBlocked ? 'Release blocked' : isReview ? 'Review required' : 'Ready for release'}
                </span>
                <div className="text-[11px] text-slate-500">
                  Target build: {release_gate.version || 'Candidate Release'}
                </div>
              </div>
            </div>

            {/* Severity Counts Pills */}
            <div className="flex items-center gap-2 flex-wrap pt-1">
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${metrics.critical > 0 ? 'bg-rose-100 text-rose-800 border border-rose-200' : 'bg-slate-100 text-slate-600'}`}>
                {metrics.critical} Critical
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${metrics.high > 0 ? 'bg-rose-100 text-rose-800 border border-rose-200' : 'bg-slate-100 text-slate-600'}`}>
                {metrics.high} High
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${metrics.medium > 0 ? 'bg-amber-100 text-amber-900 border border-amber-200' : 'bg-slate-100 text-slate-600'}`}>
                {metrics.medium} Medium
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-100 text-slate-600">
                {metrics.low} Low
              </span>
              <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-100 text-slate-600">
                {metrics.informational} Informational
              </span>
            </div>

            {/* Exact Reason & Action */}
            <p className="text-xs sm:text-sm text-slate-700 max-w-3xl leading-relaxed pt-1">
              <span className="font-semibold text-slate-900">Reason: </span>
              {release_gate.reason || (
                isBlocked
                  ? 'High/Critical vulnerabilities violate the release policy.'
                  : isReview
                  ? 'Medium severity findings require security sign-off.'
                  : 'No High or Critical vulnerabilities were detected. The release can proceed.'
              )}
            </p>
          </div>

          <div className="flex flex-col sm:flex-row md:flex-col gap-2.5 flex-shrink-0 md:min-w-[150px]">
            <button
              onClick={() => onNavigate('findings')}
              className="px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition-colors cursor-pointer shadow-xs text-center"
            >
              View findings ({totalFindingsCount})
            </button>
            <button
              onClick={() => onNavigate('releases')}
              className="px-4 py-2.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium transition-colors cursor-pointer text-center"
            >
              Release history
            </button>
          </div>
        </div>
      </div>

      {/* 3. METRICS ROW: 5 SEVERITIES + SECONDARY SECURITY SCORE */}
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-3 sm:gap-3.5">
        {/* Critical */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">Critical</div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.critical > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
            {metrics.critical}
          </div>
          <div className="text-[11px] text-slate-400">Max allowed: 0</div>
        </div>

        {/* High */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">High</div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.high > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
            {metrics.high}
          </div>
          <div className="text-[11px] text-slate-400">Max allowed: 0</div>
        </div>

        {/* Medium */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">Medium</div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.medium > 0 ? 'text-amber-600' : 'text-slate-900'}`}>
            {metrics.medium}
          </div>
          <div className="text-[11px] text-slate-400">Review required</div>
        </div>

        {/* Low */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">Low</div>
          <div className="text-2xl font-bold text-slate-900 tracking-tight">
            {metrics.low}
          </div>
          <div className="text-[11px] text-slate-400">Allowed</div>
        </div>

        {/* Informational (Strictly Distinct from Low) */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">Informational</div>
          <div className="text-2xl font-bold text-slate-900 tracking-tight">
            {metrics.informational}
          </div>
          <div className="text-[11px] text-slate-400">Allowed</div>
        </div>

        {/* Secondary Metric: Security Score */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1 bg-slate-50/30">
          <div className="text-xs text-slate-500 font-medium">Security score</div>
          <div className="text-2xl font-bold text-slate-900 tracking-tight">
            {Math.round(security_score)}{' '}
            <span className="text-xs font-normal text-slate-400">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-500">Secondary score</div>
        </div>
      </div>

      {/* 4. MIDDLE SECTION: RELEASE GATE POLICY CARD + RISK EXPOSURE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Compact Release Gate Policy Card (Item 3) */}
        <div className="lg:col-span-5 bg-white rounded-xl p-5 sm:p-6 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-1">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Release Gate Policy
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Automated pre-release security gating rules
                </p>
              </div>
              <span className="text-[11px] font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                Active policy
              </span>
            </div>

            {/* Policy Table */}
            <div className="mt-3 divide-y divide-slate-100 border border-slate-100 rounded-lg overflow-hidden">
              {policyRules.map((r) => (
                <div key={r.severity} className="flex items-center justify-between px-3.5 py-2 text-xs">
                  <span className="font-medium text-slate-700 flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        r.severity === 'Critical' ? 'bg-rose-600' :
                        r.severity === 'High' ? 'bg-orange-500' :
                        r.severity === 'Medium' ? 'bg-amber-500' :
                        r.severity === 'Low' ? 'bg-sky-500' : 'bg-slate-400'
                      }`}
                    />
                    {r.severity}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${r.color}`}>
                    {r.action}
                  </span>
                </div>
              ))}
            </div>

            {/* Clear Policy Statement */}
            <div className="mt-3 p-3 rounded-lg bg-slate-50 border border-slate-200/80 text-xs text-slate-700 leading-relaxed">
              <span className="font-semibold text-slate-900 block mb-0.5">Policy enforcement rule:</span>
              “Release is blocked if any Critical or High severity vulnerability is detected.”
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Deterministic gate logic</span>
            <span>Zero bypass allowed</span>
          </div>
        </div>

        {/* Risk Exposure Breakdown (7 cols) */}
        <div className="lg:col-span-7 bg-white rounded-xl p-5 sm:p-6 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-1">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Risk Exposure Breakdown
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Severity distribution across {totalFindingsCount} findings
                </p>
              </div>
              <span className="text-xs font-medium text-slate-600 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-md">
                {totalFindingsCount} findings
              </span>
            </div>

            {/* All 5 Severities Displayed Distinctly */}
            <div className="space-y-2.5 mt-3">
              {/* Critical */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-rose-600" />
                    Critical
                  </span>
                  <span className="font-semibold text-slate-900 tabular-nums">
                    {metrics.critical}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-rose-600 rounded-full transition-all"
                    style={{ width: metrics.critical > 0 ? `${(metrics.critical / Math.max(1, totalFindingsCount)) * 100}%` : '0%' }}
                  />
                </div>
              </div>

              {/* High */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-orange-500" />
                    High
                  </span>
                  <span className="font-semibold text-slate-900 tabular-nums">
                    {metrics.high}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full transition-all"
                    style={{ width: metrics.high > 0 ? `${(metrics.high / Math.max(1, totalFindingsCount)) * 100}%` : '0%' }}
                  />
                </div>
              </div>

              {/* Medium */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                    Medium
                  </span>
                  <span className="font-semibold text-slate-900 tabular-nums">
                    {metrics.medium}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-amber-500 rounded-full transition-all"
                    style={{ width: metrics.medium > 0 ? `${(metrics.medium / Math.max(1, totalFindingsCount)) * 100}%` : '0%' }}
                  />
                </div>
              </div>

              {/* Low */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-sky-500" />
                    Low
                  </span>
                  <span className="font-semibold text-slate-900 tabular-nums">
                    {metrics.low}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-sky-500 rounded-full transition-all"
                    style={{ width: metrics.low > 0 ? `${(metrics.low / Math.max(1, totalFindingsCount)) * 100}%` : '0%' }}
                  />
                </div>
              </div>

              {/* Informational (Strictly Distinct) */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-medium flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-slate-400" />
                    Informational
                  </span>
                  <span className="font-semibold text-slate-900 tabular-nums">
                    {metrics.informational}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-slate-400 rounded-full transition-all"
                    style={{ width: metrics.informational > 0 ? `${(metrics.informational / Math.max(1, totalFindingsCount)) * 100}%` : '0%' }}
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Score: {Math.round(security_score)} / 100</span>
            <span className="font-medium text-slate-700">Gate status: {release_gate.status}</span>
          </div>
        </div>
      </div>

      {/* 5. BOTTOM SECTION: TOP FINDINGS + SECURITY ANALYSIS ASSISTANT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Top Findings (7 cols) */}
        <div className="lg:col-span-7 bg-white rounded-xl p-5 sm:p-6 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-1">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  Top findings
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Vulnerabilities ranked by gate impact for active scan
                </p>
              </div>
              <button
                onClick={() => onNavigate('findings')}
                className="text-xs font-medium text-slate-600 hover:text-slate-900 flex items-center gap-1 transition-colors cursor-pointer"
              >
                <span>View all</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {activeFindings.length === 0 ? (
              <div className="py-10 text-center flex flex-col items-center justify-center">
                <CheckCircle2 className="w-7 h-7 text-emerald-500 mb-2" />
                <div className="text-xs font-semibold text-slate-800">
                  No active vulnerabilities detected
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5 max-w-xs">
                  This scan satisfied all gating thresholds with zero blocking findings.
                </div>
              </div>
            ) : (
              <div className="divide-y divide-slate-100 mt-3">
                {activeFindings.slice(0, 5).map((f) => (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className="py-3 px-2 -mx-2 rounded-lg hover:bg-slate-50/80 cursor-pointer transition-colors flex items-center justify-between gap-3 group"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-900 group-hover:text-emerald-700 transition-colors truncate">
                          {f.name}
                        </div>
                        <div className="text-[11px] text-slate-500 truncate mt-0.5">
                          {cleanUrl(f.url)}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[11px] text-slate-400 font-medium hidden sm:inline">
                        {f.cwe_id || 'CWE'}
                      </span>
                      <span className="text-xs text-slate-400 group-hover:text-slate-700 transition-colors">
                        &rarr;
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Showing top {Math.min(5, activeFindings.length)} of {activeFindings.length} findings</span>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs font-medium text-emerald-700 hover:text-emerald-800 cursor-pointer"
            >
              Inspect all findings &rarr;
            </button>
          </div>
        </div>

        {/* Security Analysis Assistant (5 cols) */}
        <div className="lg:col-span-5">
          <AiAssistantWidget
            activeScan={latest_scan}
            releaseGate={release_gate}
            metrics={metrics}
            securityScore={security_score}
            findings={activeFindings}
          />
        </div>
      </div>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};
