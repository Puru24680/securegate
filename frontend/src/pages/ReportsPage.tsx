import React, { useState, useEffect } from 'react';
import { SecurityReport, Scan } from '../types';
import { ReleaseGateBadge } from '../components/ReleaseGateBadge';
import { api } from '../services/api';
import {
  FileText,
  Printer,
  CheckCircle2,
} from 'lucide-react';

interface ReportsPageProps {
  activeProjectId?: number;
  initialScanId?: number | null;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({
  activeProjectId,
  initialScanId,
}) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(initialScanId || null);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialScanId) {
      setSelectedScanId(initialScanId);
    }
  }, [initialScanId]);

  useEffect(() => {
    const loadScans = async () => {
      try {
        setLoading(true);
        const data = await api.getScans(activeProjectId);
        setScans(data);
        if (data && data.length > 0) {
          // If initialScanId is within this project's scans, keep it; otherwise default to latest
          if (initialScanId && data.some((s) => s.id === initialScanId)) {
            setSelectedScanId(initialScanId);
          } else if (!selectedScanId || !data.some((s) => s.id === selectedScanId)) {
            setSelectedScanId(data[0].id);
          }
        } else {
          setSelectedScanId(null);
          setReport(null);
        }
      } catch (err) {
        console.error('Failed to load scans:', err);
      } finally {
        setLoading(false);
      }
    };
    loadScans();
  }, [activeProjectId]);

  useEffect(() => {
    if (selectedScanId) {
      loadReport(selectedScanId);
    }
  }, [selectedScanId]);

  const loadReport = async (scanId: number) => {
    try {
      setLoading(true);
      const data = await api.getReport(scanId);
      setReport(data);
    } catch (err) {
      console.error('Failed to load report:', err);
    } finally {
      setLoading(false);
    }
  };

  const handlePrint = () => {
    if (selectedScanId) {
      window.open(api.getReportHtmlUrl(selectedScanId), '_blank');
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto select-none">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1 no-print">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Reports
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Formal pre-release security assessment and compliance reports.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={selectedScanId || ''}
            onChange={(e) => setSelectedScanId(Number(e.target.value))}
            className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs text-slate-800 font-medium focus:outline-none cursor-pointer"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.scan_identifier} ({s.release_status})
              </option>
            ))}
          </select>

          <button
            onClick={handlePrint}
            disabled={!report}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer transition-colors shadow-xs disabled:opacity-50"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Export report</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="py-20 text-center text-slate-400 text-xs">
          <div className="w-5 h-5 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
          Compiling security assessment report...
        </div>
      ) : !report ? (
        <div className="p-8 text-center text-slate-400 text-xs bg-white border border-slate-200 rounded-xl shadow-xs">
          No scan report selected.
        </div>
      ) : (
        /* Report Paper Card (Crisp White Dossier) */
        <div className="p-6 sm:p-10 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-6">
          {/* Header */}
          <div className="border-b border-slate-100 pb-6 flex items-start justify-between gap-6 flex-wrap">
            <div className="space-y-2 max-w-xl">
              <span className="text-[11px] font-medium text-emerald-700 block">
                Security Assessment Report
              </span>
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight leading-tight">
                {report.title}
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1 text-xs text-slate-500">
                <div>
                  <span className="text-slate-400 block text-[11px]">Application</span>
                  <span className="text-slate-800 font-medium">{report.application_name}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Target URL</span>
                  <span className="text-slate-800 break-all">{report.target_url}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Scan ID</span>
                  <span className="text-slate-800">{report.scan_identifier}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Date</span>
                  <span className="text-slate-800">{new Date(report.generated_at).toLocaleDateString()}</span>
                </div>
              </div>
            </div>

            <div className="text-right flex-shrink-0 flex flex-col items-end">
              <ReleaseGateBadge status={report.release_status} size="md" />
              <div className="mt-2 text-2xl font-bold text-slate-900">
                {report.security_score}{' '}
                <span className="text-xs font-normal text-slate-400">/ 100</span>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold text-slate-700">
              1. Executive summary
            </h3>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200/70 text-xs text-slate-700 leading-relaxed">
              {report.executive_summary}
            </div>
          </div>

          {/* Metrics Summary Grid */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold text-slate-700">
              2. Findings breakdown
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
              <div className="p-3 rounded-lg bg-rose-50/70 border border-rose-100 text-center space-y-0.5">
                <span className="text-[11px] text-rose-700 block font-medium">Critical</span>
                <div className="text-xl font-bold text-rose-700">{report.metrics.critical}</div>
              </div>
              <div className="p-3 rounded-lg bg-orange-50/70 border border-orange-100 text-center space-y-0.5">
                <span className="text-[11px] text-orange-700 block font-medium">High</span>
                <div className="text-xl font-bold text-orange-700">{report.metrics.high}</div>
              </div>
              <div className="p-3 rounded-lg bg-amber-50/70 border border-amber-100 text-center space-y-0.5">
                <span className="text-[11px] text-amber-700 block font-medium">Medium</span>
                <div className="text-xl font-bold text-amber-700">{report.metrics.medium}</div>
              </div>
              <div className="p-3 rounded-lg bg-sky-50/70 border border-sky-100 text-center space-y-0.5">
                <span className="text-[11px] text-sky-700 block font-medium">Low</span>
                <div className="text-xl font-bold text-sky-700">{report.metrics.low}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-center col-span-2 sm:col-span-1 space-y-0.5">
                <span className="text-[11px] text-slate-500 block font-medium">Total</span>
                <div className="text-xl font-bold text-slate-900">{report.metrics.total_findings}</div>
              </div>
            </div>
          </div>

          {/* Strategic Recommendations */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold text-slate-700">
              3. Strategic remediation roadmap
            </h3>
            <div className="space-y-2">
              {report.strategic_recommendations.map((rec, idx) => (
                <div key={idx} className="p-3.5 rounded-lg bg-slate-50 border border-slate-200/70 space-y-1">
                  <div className="text-xs font-medium text-slate-900 flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 flex-shrink-0" />
                    <span>{rec.priority}: {rec.focus}</span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed pl-5">
                    {rec.details}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Detailed Findings List */}
          <div className="space-y-4">
            <h3 className="text-xs font-semibold text-slate-700">
              4. Detailed findings
            </h3>

            {report.metrics.total_findings === 0 ? (
              <div className="p-6 rounded-lg bg-emerald-50/60 border border-emerald-200/80 text-center space-y-1.5">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 mx-auto" />
                <div className="text-xs font-semibold text-emerald-950">Zero Security Vulnerabilities Detected</div>
                <p className="text-xs text-emerald-700">
                  All pre-release security baseline checks passed successfully with 0 defects detected.
                </p>
              </div>
            ) : (
              ['Critical', 'High', 'Medium', 'Low', 'Informational'].map((sev) => {
                const findingsList = report.findings_by_severity[sev] || [];
                if (findingsList.length === 0) return null;

              return (
                <div key={sev} className="space-y-2">
                  <h4 className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{
                      backgroundColor: sev === 'Critical' ? '#ef4444' : sev === 'High' ? '#f97316' : sev === 'Medium' ? '#f59e0b' : '#0ea5e9'
                    }} />
                    <span>{sev} findings ({findingsList.length})</span>
                  </h4>

                  <div className="space-y-2">
                    {findingsList.map((f) => (
                      <div key={f.id} className="p-4 rounded-lg bg-slate-50 border border-slate-200/70 space-y-1.5 text-xs">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="font-semibold text-slate-900 text-xs">{f.name}</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200 text-[10px]">
                              {f.owasp_category}
                            </span>
                            <span className="text-slate-700 bg-white px-2 py-0.5 rounded border border-slate-200 text-[10px] font-medium">
                              {f.cwe_id}
                            </span>
                          </div>
                        </div>

                        <div className="text-slate-500 text-[11px]">
                          <span>Endpoint: {f.method} {f.url}</span>
                          {f.parameter && <span> &bull; Param: {f.parameter}</span>}
                        </div>

                        <p className="text-slate-600 leading-relaxed">
                          {f.description}
                        </p>

                        {f.solution && (
                          <div className="p-2.5 rounded bg-emerald-50/50 border border-emerald-200 text-[11px] text-emerald-950">
                            <strong>Remediation:</strong> {f.solution}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })
          )}
          </div>

          {/* Footer */}
          <div className="pt-4 border-t border-slate-100 text-center text-[11px] text-slate-400">
            SecureGate Automated Pre-Release Security Gate &bull; Verified OWASP & CWE Analysis
          </div>
        </div>
      )}
    </div>
  );
};
