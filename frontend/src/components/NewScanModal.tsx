import React, { useState, useEffect } from 'react';
import { Project, Scan } from '../types';
import { api } from '../services/api';
import {
  X,
  UploadCloud,
  FileJson,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  CheckCircle2,
  Sparkles,
} from 'lucide-react';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  projects: Project[];
  activeProjectId?: number;
  onScanCompleted: (scan: Scan) => void;
}

export const NewScanModal: React.FC<NewScanModalProps> = ({
  isOpen,
  onClose,
  projects,
  activeProjectId,
  onScanCompleted,
}) => {
  const [selectedProjectId, setSelectedProjectId] = useState<number>(
    activeProjectId || (projects[0]?.id ?? 1)
  );

  useEffect(() => {
    if (activeProjectId) {
      setSelectedProjectId(activeProjectId);
    } else if (projects.length > 0) {
      setSelectedProjectId(projects[0].id);
    }
  }, [activeProjectId, projects, isOpen]);

  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleCustomUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select an OWASP ZAP JSON report file or choose a preset below.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const scan = await api.uploadScanFile(file, selectedProjectId, targetUrl);
      onScanCompleted(scan);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to parse and upload ZAP scan.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = async (presetType: 'juiceshop' | 'clean' | 'medium') => {
    try {
      setLoading(true);
      setError(null);

      const scan = await api.simulatePreset(presetType, selectedProjectId);
      onScanCompleted(scan);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to load preset scan.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/40 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-white border border-slate-200 rounded-3xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 sm:p-8 border-b border-slate-100 bg-slate-50/50">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-emerald-700 font-bold bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200">
              DAST Ingestion
            </span>
            <h2 className="text-xl sm:text-2xl font-bold font-display text-slate-900 tracking-tight mt-2 flex items-center gap-2">
              <UploadCloud className="w-6 h-6 text-emerald-600" />
              Ingest OWASP ZAP Scan Artifact
            </h2>
            <p className="text-xs text-slate-500 mt-1 font-sans">
              Parse scan output, normalize findings, score risk, and execute pre-release gate.
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-700 rounded-full hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 sm:p-8 space-y-6">
          {error && (
            <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2.5 font-mono">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-600" />
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-700">
                Target Project
              </label>
              <select
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 focus:bg-white cursor-pointer transition-colors"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} {p.is_demo ? '(Demo)' : ''}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-700">
                Target URL
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://localhost:3000"
                className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 focus:bg-white transition-colors"
              />
            </div>
          </div>

          {/* 1-Click Simulation Scenarios */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-slate-700 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-emerald-600" /> Demo scenarios
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <button
                type="button"
                onClick={() => loadPreset('juiceshop')}
                disabled={loading}
                className="p-3 text-left rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-900">Pre-Fix Build</span>
                  <span className="text-[10px] font-medium text-rose-700 bg-rose-50 px-1.5 py-0.5 rounded border border-rose-200">
                    Block
                  </span>
                </div>
                <p className="text-[11px] text-slate-500">Raw target: SQLi & XSS</p>
              </button>

              <button
                type="button"
                onClick={() => loadPreset('medium')}
                disabled={loading}
                className="p-3 text-left rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-900">Staging Build</span>
                  <span className="text-[10px] font-medium text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
                    Review
                  </span>
                </div>
                <p className="text-[11px] text-slate-500">Partial fix: CSRF & headers</p>
              </button>

              <button
                type="button"
                onClick={() => loadPreset('clean')}
                disabled={loading}
                className="p-3 text-left rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-900">Post-Fix Build</span>
                  <span className="text-[10px] font-medium text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                    Pass
                  </span>
                </div>
                <p className="text-[11px] text-slate-500">Remediated candidate: 0 high</p>
              </button>
            </div>
          </div>

          {/* Upload Custom JSON */}
          <form onSubmit={handleCustomUpload} className="space-y-3 pt-3 border-t border-slate-100">
            <label className="text-xs font-medium text-slate-700 block">
              Or upload OWASP ZAP JSON file
            </label>
            <div className="relative border border-dashed border-slate-200 hover:border-slate-300 rounded-lg p-5 text-center cursor-pointer bg-slate-50 hover:bg-white transition-colors">
              <input
                type="file"
                accept=".json"
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <FileJson className="w-6 h-6 text-slate-500 mx-auto mb-1.5" />
              <p className="text-xs text-slate-800 font-medium">
                {file ? file.name : 'Select or drop ZAP report JSON here'}
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Supports OWASP ZAP 2.14 baseline & active scan reports
              </p>
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3.5 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || !file}
                className="px-4 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-40 cursor-pointer transition-colors shadow-xs"
              >
                {loading ? 'Evaluating...' : 'Import scan'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
