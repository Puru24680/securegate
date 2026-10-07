import React, { useState, useEffect } from 'react';
import { SecurityPolicy, Project } from '../types';
import { api } from '../services/api';
import {
  Shield,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Save,
  Info,
  Check,
} from 'lucide-react';

interface PoliciesPageProps {
  activeProject?: Project;
}

export const PoliciesPage: React.FC<PoliciesPageProps> = ({ activeProject }) => {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Active form policy state
  const [currentPolicy, setCurrentPolicy] = useState<Partial<SecurityPolicy>>({
    name: 'Default Gate Policy',
    block_critical: true,
    block_high: true,
    block_medium: false,
    min_cvss_block: 7.0,
    max_critical_allowed: 0,
    max_high_allowed: 0,
    require_production_authorization: true,
  });

  useEffect(() => {
    loadPolicies();
  }, [activeProject]);

  const loadPolicies = async () => {
    try {
      setLoading(true);
      const list = await api.getSecurityPolicies(activeProject?.id);
      setPolicies(list);
      if (list.length > 0) {
        setCurrentPolicy(list[0]);
      }
    } catch (err) {
      console.error('Failed to load policies:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      if (currentPolicy.id) {
        const updated = await api.updateSecurityPolicy(currentPolicy.id, currentPolicy);
        setCurrentPolicy(updated);
      } else {
        const created = await api.createSecurityPolicy({
          ...currentPolicy,
          project_id: activeProject?.id,
        });
        setCurrentPolicy(created);
      }
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
      loadPolicies();
    } catch (err) {
      alert(`Failed to save policy: ${err}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <Shield className="w-5 h-5 text-emerald-600" />
          Release Gate Security Policies
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Define deterministic gating thresholds and automated release blockers for {activeProject?.name || 'organization'}.
        </p>
      </div>

      {loading ? (
        <div className="p-12 text-center text-xs text-slate-400">Loading security policies...</div>
      ) : (
        <form onSubmit={handleSave} className="space-y-5">
          {/* Main Policy Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-6">
            <div>
              <label className="block text-xs font-semibold text-slate-800 mb-1">Policy Name</label>
              <input
                type="text"
                value={currentPolicy.name || ''}
                onChange={(e) => setCurrentPolicy({ ...currentPolicy, name: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500 text-slate-800 font-medium"
                required
              />
            </div>

            {/* Severity Gate Blockers */}
            <div className="space-y-3">
              <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Automated Release Block Thresholds
              </h2>

              <div className="space-y-2">
                <label className="flex items-start gap-3 p-3.5 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition">
                  <input
                    type="checkbox"
                    checked={currentPolicy.block_critical || false}
                    onChange={(e) => setCurrentPolicy({ ...currentPolicy, block_critical: e.target.checked })}
                    className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500 cursor-pointer"
                  />
                  <div>
                    <div className="text-xs font-semibold text-slate-800 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-red-600" />
                      Block on Critical Vulnerabilities (CVSS 9.0 - 10.0)
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Fails CI/CD pipeline and marks Release status as BLOCK if any unaccepted Critical finding is detected.
                    </div>
                  </div>
                </label>

                <label className="flex items-start gap-3 p-3.5 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition">
                  <input
                    type="checkbox"
                    checked={currentPolicy.block_high || false}
                    onChange={(e) => setCurrentPolicy({ ...currentPolicy, block_high: e.target.checked })}
                    className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500 cursor-pointer"
                  />
                  <div>
                    <div className="text-xs font-semibold text-slate-800 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-orange-500" />
                      Block on High Vulnerabilities (CVSS 7.0 - 8.9)
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Blocks release deployment if active High vulnerabilities exceed the permitted count.
                    </div>
                  </div>
                </label>

                <label className="flex items-start gap-3 p-3.5 rounded-lg border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition">
                  <input
                    type="checkbox"
                    checked={currentPolicy.block_medium || false}
                    onChange={(e) => setCurrentPolicy({ ...currentPolicy, block_medium: e.target.checked })}
                    className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500 cursor-pointer"
                  />
                  <div>
                    <div className="text-xs font-semibold text-slate-800 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-amber-500" />
                      Block on Medium Vulnerabilities (CVSS 4.0 - 6.9)
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Strict mode: Enforces zero-tolerance or review sign-off for medium findings.
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {/* Numerical Cutoffs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Min CVSS Score to Block
                </label>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={currentPolicy.min_cvss_block || 7.0}
                  onChange={(e) =>
                    setCurrentPolicy({ ...currentPolicy, min_cvss_block: parseFloat(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                />
                <span className="text-[11px] text-slate-400 mt-0.5 block">Standard: 7.0</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Max Allowed Critical
                </label>
                <input
                  type="number"
                  min="0"
                  value={currentPolicy.max_critical_allowed ?? 0}
                  onChange={(e) =>
                    setCurrentPolicy({ ...currentPolicy, max_critical_allowed: parseInt(e.target.value, 10) })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                />
                <span className="text-[11px] text-slate-400 mt-0.5 block">Recommended: 0</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Max Allowed High
                </label>
                <input
                  type="number"
                  min="0"
                  value={currentPolicy.max_high_allowed ?? 0}
                  onChange={(e) =>
                    setCurrentPolicy({ ...currentPolicy, max_high_allowed: parseInt(e.target.value, 10) })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                />
                <span className="text-[11px] text-slate-400 mt-0.5 block">Recommended: 0</span>
              </div>
            </div>

            {/* Production Authorization */}
            <div className="pt-2">
              <label className="flex items-start gap-3 p-3.5 rounded-lg border border-amber-200 bg-amber-50/40 cursor-pointer">
                <input
                  type="checkbox"
                  checked={currentPolicy.require_production_authorization || false}
                  onChange={(e) =>
                    setCurrentPolicy({
                      ...currentPolicy,
                      require_production_authorization: e.target.checked,
                    })
                  }
                  className="mt-0.5 rounded text-amber-600 focus:ring-amber-500 cursor-pointer"
                />
                <div>
                  <div className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-amber-600" />
                    Require Explicit Production Scan Authorization
                  </div>
                  <div className="text-[11px] text-slate-600 mt-0.5">
                    Prevents automated CI/CD runners and unprivileged users from launching active penetration tests against live production targets without an authorized override.
                  </div>
                </div>
              </label>
            </div>
          </div>

          {/* Action Footer */}
          <div className="flex items-center justify-between">
            {savedSuccess ? (
              <div className="flex items-center gap-2 text-xs text-emerald-600 font-semibold">
                <Check className="w-4 h-4" />
                Security policy updated and active!
              </div>
            ) : (
              <div className="text-xs text-slate-400">All modifications are written to the audit log.</div>
            )}

            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition shadow-xs cursor-pointer disabled:opacity-50"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving...' : 'Save Gate Policy'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
