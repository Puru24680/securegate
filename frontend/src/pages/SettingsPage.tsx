import React, { useState, useEffect } from 'react';
import { AppSettings, ReleasePolicy } from '../types';
import { api } from '../services/api';
import {
  Sliders,
  ShieldCheck,
  Save,
  CheckCircle2,
  Server,
  Sparkles,
  Key,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states
  const [policy, setPolicy] = useState<ReleasePolicy>({
    critical: 'BLOCK',
    high: 'BLOCK',
    medium: 'REVIEW',
    low: 'PASS',
    informational: 'PASS',
  });
  const [environment, setEnvironment] = useState('staging');
  const [aiEnabled, setAiEnabled] = useState(true);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      const data = await api.getSettings();
      setSettings(data);
      if (data.release_policy) setPolicy(data.release_policy);
      if (data.environment) setEnvironment(data.environment);
      setAiEnabled(data.ai_analysis_enabled);
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      setSuccessMsg(null);
      const updated = await api.updateSettings({
        release_policy: policy,
        environment,
        ai_analysis_enabled: aiEnabled,
      });
      setSettings(updated);
      setSuccessMsg('Release gate policy and settings saved successfully.');
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err) {
      alert(`Failed to save settings: ${err}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto select-none">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
          Settings
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Configure release gate decision matrix, environment settings, and AI parameters.
        </p>
      </div>

      {successMsg && (
        <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {loading || !settings ? (
        <div className="py-20 text-center text-slate-400 text-xs">
          <div className="w-5 h-5 border-2 border-slate-900 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
          Loading platform configuration...
        </div>
      ) : (
        <form onSubmit={handleSave} className="space-y-5">
          {/* Release Gate Policy Card */}
          <div className="p-5 sm:p-6 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Release gate decision matrix</span>
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Determine automated gating verdicts for findings in each severity category.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-1">
              {/* Critical */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-800">
                    Critical findings
                  </label>
                  <span className="w-2 h-2 rounded-full bg-rose-600" />
                </div>
                <select
                  value={policy.critical}
                  onChange={(e) => setPolicy({ ...policy, critical: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-md bg-white border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 cursor-pointer"
                >
                  <option value="BLOCK">BLOCK (Strict default)</option>
                  <option value="REVIEW">REVIEW</option>
                  <option value="PASS">PASS</option>
                </select>
              </div>

              {/* High */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-800">
                    High findings
                  </label>
                  <span className="w-2 h-2 rounded-full bg-orange-500" />
                </div>
                <select
                  value={policy.high}
                  onChange={(e) => setPolicy({ ...policy, high: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-md bg-white border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 cursor-pointer"
                >
                  <option value="BLOCK">BLOCK (Strict default)</option>
                  <option value="REVIEW">REVIEW</option>
                  <option value="PASS">PASS</option>
                </select>
              </div>

              {/* Medium */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-800">
                    Medium findings
                  </label>
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                </div>
                <select
                  value={policy.medium}
                  onChange={(e) => setPolicy({ ...policy, medium: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-md bg-white border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 cursor-pointer"
                >
                  <option value="REVIEW">REVIEW (Standard default)</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="PASS">PASS</option>
                </select>
              </div>

              {/* Low */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-800">
                    Low findings
                  </label>
                  <span className="w-2 h-2 rounded-full bg-sky-500" />
                </div>
                <select
                  value={policy.low}
                  onChange={(e) => setPolicy({ ...policy, low: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-md bg-white border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 cursor-pointer"
                >
                  <option value="PASS">PASS (Permissive default)</option>
                  <option value="REVIEW">REVIEW</option>
                  <option value="BLOCK">BLOCK</option>
                </select>
              </div>
            </div>
          </div>

          {/* DevSecOps Tooling Runtime */}
          <div className="p-5 sm:p-6 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <Server className="w-4 h-4 text-emerald-600" />
                <span>Scanner and pipeline runtime</span>
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Integration configuration for OWASP ZAP and CI/CD workflows.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Target deployment environment
                </label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 capitalize cursor-pointer"
                >
                  <option value="development">Development</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Primary dynamic scanner
                </label>
                <div className="px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-700">
                  OWASP ZAP 2.14.0 (Baseline & Active DAST)
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  CI/CD pipeline binding
                </label>
                <div className="px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-700">
                  GitHub Actions (.github/workflows/security.yml)
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Local test target
                </label>
                <div className="px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-700">
                  OWASP Juice Shop (port 3000)
                </div>
              </div>
            </div>
          </div>

          {/* AI Advisor Settings */}
          <div className="p-5 sm:p-6 rounded-xl bg-white border border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-emerald-600" />
                  <span>AI security assistant layer</span>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Generates plain-English vulnerability explanations and developer fix items.
                </p>
              </div>

              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={aiEnabled}
                  onChange={(e) => setAiEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-10 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-slate-600">
                <Key className="w-3.5 h-3.5 text-slate-400" />
                <span>OpenAI API integration:</span>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                  settings.ai_api_key_configured
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : 'bg-slate-100 text-slate-600'
                }`}
              >
                {settings.ai_api_key_configured
                  ? 'Configured (Active)'
                  : 'Built-in local security models'}
              </span>
            </div>
          </div>

          {/* Save Action */}
          <div className="flex justify-end pt-1">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50 transition-colors shadow-xs"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? 'Saving...' : 'Save settings'}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
