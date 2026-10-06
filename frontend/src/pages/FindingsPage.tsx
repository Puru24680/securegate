import React, { useState, useEffect } from 'react';
import { Finding, Severity, FindingStatus, Scan } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingDetailModal } from '../components/FindingDetailModal';
import { api } from '../services/api';
import {
  Search,
  Filter,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  CheckCircle2,
  Layers,
} from 'lucide-react';

interface FindingsPageProps {
  activeProjectId?: number;
  initialScanId?: number;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({
  activeProjectId,
  initialScanId,
}) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const perPage = 10;
  const [loading, setLoading] = useState(false);
  const [availableScans, setAvailableScans] = useState<Scan[]>([]);

  // Scan context selection: 'latest', 'all', or specific scan id string
  const [selectedScanContext, setSelectedScanContext] = useState<string>('latest');

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Load available scans for project
  useEffect(() => {
    if (activeProjectId) {
      api.getScans(activeProjectId)
        .then((scans) => setAvailableScans(scans || []))
        .catch(() => setAvailableScans([]));
    }
  }, [activeProjectId]);

  // Keep scan context synchronized when initialScanId changes from outside (e.g. preset loaded)
  useEffect(() => {
    if (initialScanId) {
      setSelectedScanContext(initialScanId.toString());
    } else {
      setSelectedScanContext('latest');
    }
  }, [initialScanId]);

  const activeScan = availableScans.find((s) => {
    if (selectedScanContext === 'all') return false;
    if (selectedScanContext === 'latest') return true;
    return s.id.toString() === selectedScanContext;
  }) || (availableScans.length > 0 ? availableScans[0] : null);

  const fetchFindings = async () => {
    try {
      setLoading(true);

      let effectiveScanId: number | undefined = undefined;
      if (selectedScanContext !== 'all') {
        if (selectedScanContext === 'latest') {
          effectiveScanId = initialScanId || (availableScans[0]?.id);
        } else {
          effectiveScanId = parseInt(selectedScanContext, 10);
        }
      }

      const res = await api.getFindings({
        project_id: effectiveScanId ? undefined : activeProjectId,
        scan_id: effectiveScanId,
        severity: severityFilter,
        status: statusFilter,
        search: search.trim() || undefined,
        page,
        per_page: perPage,
      });

      setFindings(res.findings);
      setTotal(res.total);
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [activeProjectId, selectedScanContext, initialScanId, severityFilter, statusFilter, page]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchFindings();
  };

  const totalPages = Math.ceil(total / perPage) || 1;
  const severities = ['all', 'Critical', 'High', 'Medium', 'Low', 'Informational'];

  return (
    <div className="space-y-6 select-none max-w-7xl">
      {/* Header with Scan Context Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Findings
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Normalized DAST security findings mapped to OWASP Top 10 and CWEs.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap sm:flex-nowrap">
          {/* Scan Context Dropdown */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-500 font-medium">Scan context:</span>
            <select
              value={selectedScanContext}
              onChange={(e) => {
                setSelectedScanContext(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-white border border-slate-200 text-xs text-slate-800 font-medium focus:outline-none focus:border-slate-300 cursor-pointer shadow-xs max-w-[280px] truncate"
            >
              {availableScans.map((s) => (
                <option key={s.id} value={s.id.toString()}>
                  {s.id === initialScanId ? '★ Active: ' : ''}{s.scan_identifier} ({s.release_status})
                </option>
              ))}
              <option value="all">All scans (Cumulative project view)</option>
            </select>
          </div>

          <button
            onClick={fetchFindings}
            className="px-3 py-1.5 text-xs rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 transition-colors flex items-center gap-1.5 w-max font-medium cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-slate-900' : 'text-slate-500'}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Active Scan Context Banner */}
      {selectedScanContext !== 'all' && activeScan ? (
        <div className="px-4 py-2.5 rounded-xl bg-white border border-slate-200/90 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className="font-semibold text-slate-900">
              {activeScan.scan_identifier}
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                activeScan.release_status === 'BLOCK'
                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                  : activeScan.release_status === 'REVIEW'
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}
            >
              {activeScan.release_status}
            </span>
            <span className="text-slate-500">
              Score: <strong className="text-slate-800">{Math.round(activeScan.security_score)}/100</strong> &bull;{' '}
              {total} finding{total === 1 ? '' : 's'} in this scan
            </span>
          </div>

          <button
            onClick={() => {
              setSelectedScanContext('all');
              setPage(1);
            }}
            className="text-xs text-emerald-700 hover:text-emerald-800 font-medium cursor-pointer self-start sm:self-auto"
          >
            View cumulative project history &rarr;
          </button>
        </div>
      ) : (
        <div className="px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200/80 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-700 font-medium">
              Showing cumulative findings across all scans ({total} total findings recorded)
            </span>
          </div>
          {availableScans.length > 0 && (
            <button
              onClick={() => {
                setSelectedScanContext(availableScans[0].id.toString());
                setPage(1);
              }}
              className="text-xs text-emerald-700 hover:text-emerald-800 font-medium cursor-pointer"
            >
              Filter to active scan &rarr;
            </button>
          )}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="space-y-3">
        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {severities.map((sev) => {
            const isSelected = severityFilter.toLowerCase() === sev.toLowerCase();
            return (
              <button
                key={sev}
                onClick={() => {
                  setSeverityFilter(sev);
                  setPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap cursor-pointer font-medium ${
                  isSelected
                    ? 'bg-slate-900 text-white'
                    : 'bg-white hover:bg-slate-50 text-slate-600 border border-slate-200'
                }`}
              >
                {sev === 'all' ? 'All findings' : sev}
              </button>
            );
          })}
        </div>

        {/* Search & Status Bar */}
        <div className="p-3.5 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col md:flex-row items-center gap-3">
          <form onSubmit={handleSearchSubmit} className="relative flex-1 w-full">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by vulnerability name, parameter, endpoint URL..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:border-slate-300 focus:bg-white placeholder-slate-400 transition-colors"
            />
          </form>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <span className="text-xs text-slate-500 font-medium">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 focus:outline-none focus:border-slate-300 cursor-pointer"
            >
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="reviewed">Reviewed</option>
              <option value="fixed">Fixed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/70 text-[11px] font-medium text-slate-500">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Vulnerability</th>
                <th className="py-3 px-4">OWASP 2021</th>
                <th className="py-3 px-4">CWE</th>
                <th className="py-3 px-4">Endpoint</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-400">
                    <div className="w-5 h-5 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                    Loading findings...
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                    <div className="text-sm font-semibold text-slate-900">
                      No matching findings
                    </div>
                    <div className="text-xs text-slate-500 mt-1 max-w-sm mx-auto leading-relaxed">
                      {selectedScanContext !== 'all' && activeScan?.release_status === 'PASS'
                        ? 'This release passed all gating thresholds with zero blocking vulnerabilities.'
                        : 'No security findings match your current filter criteria.'}
                    </div>
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr
                    key={f.id}
                    className="hover:bg-slate-50/70 transition-colors group cursor-pointer"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={f.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-900">
                      <div className="max-w-xs truncate group-hover:text-emerald-700 transition-colors" title={f.name}>
                        {f.name}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-600">
                      <div className="max-w-[170px] truncate" title={f.owasp_category}>
                        {f.owasp_category}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-700 font-medium">
                      {f.cwe_id}
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      <div className="max-w-xs truncate" title={f.url}>
                        <span className="font-semibold text-slate-700 mr-1 px-1 py-0.5 rounded bg-slate-100 text-[10px]">
                          {f.method}
                        </span>
                        {f.url}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {f.confidence}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-medium border capitalize ${
                          f.status === 'fixed'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : f.status === 'reviewed'
                            ? 'bg-sky-50 text-sky-700 border-sky-200'
                            : 'bg-rose-50 text-rose-700 border-rose-200'
                        }`}
                      >
                        {f.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-3.5 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 bg-slate-50/40">
          <span>
            Showing {findings.length > 0 ? (page - 1) * perPage + 1 : 0} –{' '}
            {Math.min(page * perPage, total)} of {total} findings
          </span>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1 rounded-md bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-30 text-slate-700 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="px-2">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1 rounded-md bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-30 text-slate-700 transition-colors"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusUpdated={(updated) => {
          setSelectedFinding(updated);
          fetchFindings();
        }}
      />
    </div>
  );
};

export default FindingsPage;
