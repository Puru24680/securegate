import React, { useState, useEffect } from 'react';
import { Release } from '../types';
import { ReleaseGateBadge } from '../components/ReleaseGateBadge';
import { api } from '../services/api';
import {
  GitMerge,
  FileText,
  Clock,
  ArrowRight,
} from 'lucide-react';

interface ReleasesPageProps {
  activeProjectId?: number;
  onNavigateToReport: (scanId: number) => void;
}

export const ReleasesPage: React.FC<ReleasesPageProps> = ({
  activeProjectId,
  onNavigateToReport,
}) => {
  const [releases, setReleases] = useState<Release[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchReleases = async () => {
    try {
      setLoading(true);
      const data = await api.getReleases(activeProjectId);
      setReleases(data);
    } catch (err) {
      console.error('Failed to fetch releases:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReleases();
  }, [activeProjectId]);

  return (
    <div className="space-y-6 select-none max-w-7xl">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
          Releases
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Gating decisions and promotion history for candidate builds.
        </p>
      </div>

      {/* Release Timeline */}
      <div className="space-y-4">
        {loading ? (
          <div className="py-16 text-center text-slate-400 text-xs">
            <div className="w-5 h-5 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
            Loading release history...
          </div>
        ) : releases.length === 0 ? (
          <div className="p-8 rounded-xl bg-white border border-slate-200 text-center text-slate-400 text-xs shadow-xs">
            No release gate evaluations recorded yet. Run a scan to evaluate a candidate build.
          </div>
        ) : (
          <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-200">
            {releases.map((rel) => {
              const isBlock = rel.status === 'BLOCK';
              const isReview = rel.status === 'REVIEW';

              return (
                <div key={rel.id} className="relative group">
                  {/* Timeline node icon */}
                  <div
                    className={`absolute -left-6 top-4 w-3.5 h-3.5 rounded-full border-2 bg-white flex items-center justify-center ${
                      isBlock
                        ? 'border-rose-500'
                        : isReview
                        ? 'border-amber-500'
                        : 'border-emerald-500'
                    }`}
                  />

                  {/* Release Card */}
                  <div className="p-5 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] hover:border-slate-300 transition-colors space-y-3">
                    <div className="flex items-start justify-between gap-4 flex-wrap">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2.5">
                          <span className="text-sm font-bold text-slate-900">
                            {rel.version}
                          </span>
                          <ReleaseGateBadge status={rel.status} size="sm" />
                          {rel.security_score !== undefined && (
                            <span className="text-xs text-slate-600 bg-slate-50 px-2 py-0.5 rounded border border-slate-200 font-medium">
                              Score: {rel.security_score} / 100
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                          <Clock className="w-3.5 h-3.5 text-slate-400" />
                          <span>
                            {rel.created_at ? new Date(rel.created_at).toLocaleString() : 'N/A'}
                          </span>
                          {rel.scan_identifier && (
                            <>
                              <span>&bull;</span>
                              <span className="text-slate-600 font-medium">
                                {rel.scan_identifier}
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      {rel.scan_id && (
                        <button
                          onClick={() => onNavigateToReport(rel.scan_id)}
                          className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
                        >
                          <FileText className="w-3.5 h-3.5 text-slate-500" />
                          <span>View report</span>
                          <ArrowRight className="w-3 h-3 text-slate-400" />
                        </button>
                      )}
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/70 text-xs text-slate-700 leading-relaxed">
                      <span className="font-medium text-slate-900 block mb-0.5">
                        Gating rationale
                      </span>
                      {rel.reason}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
