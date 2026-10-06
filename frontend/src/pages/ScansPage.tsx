import React, { useState, useEffect } from 'react';
import { Scan } from '../types';
import { ReleaseGateBadge } from '../components/ReleaseGateBadge';
import { api } from '../services/api';
import {
  ScanSearch,
  UploadCloud,
  FileText,
  Trash2,
} from 'lucide-react';

interface ScansPageProps {
  activeProjectId?: number;
  onOpenNewScan: () => void;
  onNavigateToReport: (scanId: number) => void;
  onNavigateToFindings: () => void;
}

export const ScansPage: React.FC<ScansPageProps> = ({
  activeProjectId,
  onOpenNewScan,
  onNavigateToReport,
}) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const data = await api.getScans(activeProjectId);
      setScans(data);
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [activeProjectId]);

  const handleDelete = async (id: number) => {
    if (!confirm(`Are you sure you want to delete scan #${id}?`)) return;
    try {
      setDeletingId(id);
      await api.deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
    } catch (err) {
      alert(`Failed to delete scan: ${err}`);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6 select-none max-w-7xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Scans
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            History of all security scan executions, posture scores, and gating determinations.
          </p>
        </div>

        <button
          onClick={onOpenNewScan}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium cursor-pointer transition-colors shadow-xs"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Import scan</span>
        </button>
      </div>

      {/* Scans Table */}
      <div className="rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/70 text-[11px] font-medium text-slate-500">
                <th className="py-3 px-4">Scan identifier</th>
                <th className="py-3 px-4">Target URL</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Findings breakdown</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Gate status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-400">
                    <div className="w-5 h-5 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                    Loading scan history...
                  </td>
                </tr>
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-400">
                    No security scans recorded for this project.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-900">
                      <div className="flex items-center gap-2">
                        <ScanSearch className="w-4 h-4 text-slate-500" />
                        <span>{s.scan_identifier}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-600">
                      <div className="max-w-[200px] truncate" title={s.target_url}>
                        {s.target_url}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {s.created_at ? new Date(s.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-600">
                      {s.duration}s
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        {s.critical_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-medium">
                            {s.critical_count} Crit
                          </span>
                        )}
                        {s.high_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200 text-[10px] font-medium">
                            {s.high_count} High
                          </span>
                        )}
                        {s.medium_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-medium">
                            {s.medium_count} Med
                          </span>
                        )}
                        {s.low_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-sky-50 text-sky-700 border border-sky-200 text-[10px] font-medium">
                            {s.low_count} Low
                          </span>
                        )}
                        {s.total_findings === 0 && (
                          <span className="text-emerald-700 font-medium text-[11px]">Clean</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-900">
                      <span>{s.security_score}</span> <span className="text-slate-400 font-normal text-xs">/ 100</span>
                    </td>
                    <td className="py-3 px-4">
                      <ReleaseGateBadge status={s.release_status} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => onNavigateToReport(s.id)}
                          className="px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 transition-colors flex items-center gap-1 text-xs font-medium cursor-pointer"
                        >
                          <FileText className="w-3 h-3 text-slate-500" />
                          <span>Report</span>
                        </button>
                        <button
                          onClick={() => handleDelete(s.id)}
                          disabled={deletingId === s.id}
                          className="p-1 rounded-md border border-slate-200 bg-white hover:bg-rose-50 hover:border-rose-200 text-slate-400 hover:text-rose-600 transition-colors cursor-pointer"
                          title="Delete scan"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
