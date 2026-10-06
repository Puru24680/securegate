import React, { useState, useEffect, useMemo } from 'react';
import { DashboardData, Finding } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingDetailModal } from '../components/FindingDetailModal';
import { AiAssistantWidget } from '../components/AiAssistantWidget';
import {
  Shield,
  ChevronRight,
  CheckCircle2,
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
    }
  }, [data?.latest_scan?.id]);

  const activeFindings = liveFindings;

  // Use actual scan history from backend recent_scans if available
  const actualScanHistory = useMemo(() => {
    const scans = data?.recent_scans || [];
    if (scans.length <= 1) return [];
    // Oldest to newest
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
      <div className="space-y-6 animate-pulse">
        <div className="h-8 bg-slate-200/70 rounded-lg w-48" />
        <div className="h-28 bg-slate-200/70 rounded-xl w-full" />
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-24 bg-slate-200/70 rounded-xl" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-6 h-64 bg-slate-200/70 rounded-xl" />
          <div className="lg:col-span-6 h-64 bg-slate-200/70 rounded-xl" />
        </div>
      </div>
    );
  }

  if (!data || data.empty) {
    return (
      <div className="py-20 text-center max-w-md mx-auto space-y-4 bg-white p-8 rounded-xl border border-slate-200 shadow-xs">
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

  const { release_gate, metrics, latest_scan, security_score, project } = data;
  const isBlocked = release_gate.status === 'BLOCK';
  const isReview = release_gate.status === 'REVIEW';

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
    metrics.critical + metrics.high + metrics.medium + metrics.low ||
    4;

  return (
    <div className="space-y-6 select-none max-w-7xl">
      {/* 1. Page Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
          Dashboard
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          {project?.name || 'OWASP Juice Shop'} &bull; Last scan: {formatScanTime(latest_scan?.created_at)}
        </p>
      </div>

      {/* 2. Release Status Section (Clean, Calm, Authoritative) */}
      <div
        className={`p-6 rounded-xl bg-white border border-slate-200/90 shadow-[0_1px_2px_rgba(0,0,0,0.02)] ${
          isBlocked
            ? 'border-l-4 border-l-rose-500'
            : isReview
            ? 'border-l-4 border-l-amber-500'
            : 'border-l-4 border-l-emerald-500'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="text-xs font-medium text-slate-500">
              Release status
            </div>
            <div className="flex items-center gap-3">
              <span
                className={`text-2xl sm:text-3xl font-bold tracking-tight ${
                  isBlocked ? 'text-rose-600' : isReview ? 'text-amber-600' : 'text-emerald-600'
                }`}
              >
                {release_gate.status}
              </span>
              <span
                className={`px-2.5 py-0.5 text-xs font-medium rounded-md ${
                  isBlocked
                    ? 'bg-rose-50 text-rose-700 border border-rose-200'
                    : isReview
                    ? 'bg-amber-50 text-amber-700 border border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                }`}
              >
                {isBlocked ? 'Deployment blocked' : isReview ? 'Review required' : 'Ready for release'}
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-600 max-w-2xl leading-relaxed">
              {release_gate.reason ||
                (isBlocked
                  ? `${release_gate.blocking_findings || metrics.high} high-severity findings require attention.`
                  : 'All security gating criteria are satisfied.')}
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-shrink-0">
            <button
              onClick={() => onNavigate('findings')}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition-colors cursor-pointer shadow-xs"
            >
              View findings
            </button>
            <button
              onClick={() => onNavigate('releases')}
              className="px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs font-medium transition-colors cursor-pointer"
            >
              Release policy
            </button>
          </div>
        </div>
      </div>

      {/* 3. Security Metrics Row (Clean 5-Card Grid) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3.5 sm:gap-4">
        {/* Security Score */}
        <div className="col-span-2 sm:col-span-1 p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">
            Security score
          </div>
          <div className="text-2xl font-bold text-slate-900 tracking-tight">
            {Math.round(security_score)}{' '}
            <span className="text-xs font-normal text-slate-400">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-500">
            Threshold: 80
          </div>
        </div>

        {/* Critical */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">
            Critical
          </div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.critical > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
            {metrics.critical}
          </div>
          <div className="text-[11px] text-slate-400">
            Max allowed: 0
          </div>
        </div>

        {/* High */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">
            High
          </div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.high > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
            {metrics.high}
          </div>
          <div className="text-[11px] text-slate-400">
            Max allowed: 0
          </div>
        </div>

        {/* Medium */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">
            Medium
          </div>
          <div className={`text-2xl font-bold tracking-tight ${metrics.medium > 0 ? 'text-amber-600' : 'text-slate-900'}`}>
            {metrics.medium}
          </div>
          <div className="text-[11px] text-slate-400">
            Review recommended
          </div>
        </div>

        {/* Low */}
        <div className="p-4 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-1">
          <div className="text-xs text-slate-500 font-medium">
            Low
          </div>
          <div className="text-2xl font-bold text-slate-900 tracking-tight">
            {metrics.low + metrics.informational}
          </div>
          <div className="text-[11px] text-slate-400">
            Informational
          </div>
        </div>
      </div>

      {/* 4. Middle Section: Risk Exposure & Security Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Risk Exposure (6 cols) */}
        <div className="lg:col-span-6 bg-white rounded-xl p-5 sm:p-6 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">
                Risk exposure
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Severity breakdown across {totalFindingsCount} findings
              </p>
            </div>
            <span className="text-xs font-medium text-slate-600 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-md">
              {totalFindingsCount} findings
            </span>
          </div>

          {/* Clean Horizontal Severity Breakdown */}
          <div className="space-y-3">
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
                  className="h-full bg-rose-600 rounded-full"
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
                  className="h-full bg-orange-500 rounded-full"
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
                  className="h-full bg-amber-500 rounded-full"
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
                  {metrics.low + metrics.informational}
                </span>
              </div>
              <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-sky-500 rounded-full"
                  style={{
                    width: (metrics.low + metrics.informational) > 0
                      ? `${((metrics.low + metrics.informational) / Math.max(1, totalFindingsCount)) * 100}%`
                      : '0%',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Clean Posture Progress Bar */}
          <div className="pt-4 border-t border-slate-100 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600 font-medium">
                Overall score: {Math.round(security_score)} / 100
              </span>
              <span
                className={`font-semibold ${
                  security_score >= 80 ? 'text-emerald-700' : security_score >= 60 ? 'text-amber-700' : 'text-rose-700'
                }`}
              >
                {security_score >= 80 ? 'Pass' : security_score >= 60 ? 'Review' : 'High risk'}
              </span>
            </div>
            <div className="relative w-full h-2 rounded-full bg-slate-100 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  security_score >= 80 ? 'bg-emerald-600' : security_score >= 60 ? 'bg-amber-500' : 'bg-rose-600'
                }`}
                style={{ width: `${Math.max(4, Math.min(100, security_score))}%` }}
              />
              <div className="absolute top-0 bottom-0 left-[80%] w-0.5 bg-slate-400" title="Pass threshold: 80%" />
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>0</span>
              <span>Pass threshold: 80</span>
              <span>100</span>
            </div>
          </div>
        </div>

        {/* Security Posture History Chart (6 cols) */}
        <div className="lg:col-span-6 bg-white rounded-xl p-5 sm:p-6 border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">
                Security posture
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Scan score progression over time
              </p>
            </div>
            <span className="text-xs text-slate-500 font-medium">
              Current: {Math.round(security_score)} / 100
            </span>
          </div>

          {/* Honest Historical Chart or Polite Empty State */}
          {actualScanHistory.length > 1 ? (
            <div className="h-52 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={actualScanHistory}>
                  <XAxis
                    dataKey="date"
                    stroke="#94a3b8"
                    fontSize={11}
                    tickLine={false}
                    fontFamily="Manrope"
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="#94a3b8"
                    fontSize={11}
                    tickLine={false}
                    fontFamily="Manrope"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: '#E2E8F0',
                      borderRadius: '8px',
                      fontSize: '12px',
                      boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05)',
                      color: '#0F172A',
                      fontFamily: 'Manrope',
                    }}
                    formatter={(val: any) => [`${val} / 100`, 'Security score']}
                  />
                  <Line
                    type="monotone"
                    dataKey="security_score"
                    stroke="#059669"
                    strokeWidth={2}
                    dot={{ r: 3, fill: '#059669' }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-52 w-full flex flex-col items-center justify-center text-center p-6 rounded-lg bg-slate-50/70 border border-dashed border-slate-200">
              <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-slate-400 mb-2">
                <Shield className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-semibold text-slate-800">
                No historical scans yet
              </h4>
              <p className="text-xs text-slate-500 max-w-xs mt-1">
                Run another scan to track security posture over time.
              </p>
            </div>
          )}

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Evaluation: Deterministic gate</span>
            <span>Pass standard: &ge; 80 / 100</span>
          </div>
        </div>
      </div>

      {/* 5. Lower Section: Top Findings Table & AI Assistant */}
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
                  Vulnerabilities ranked by gate impact
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

            {/* Clean, Minimal Findings List */}
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
                        {f.cwe_id}
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

        {/* AI Security Assistant (5 cols) */}
        <div className="lg:col-span-5">
          <AiAssistantWidget
            findingId={activeFindings[0]?.id || 1}
            latestScore={security_score}
            gateStatus={release_gate.status}
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
