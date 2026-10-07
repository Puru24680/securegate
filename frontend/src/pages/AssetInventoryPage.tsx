import React, { useState, useEffect } from 'react';
import { Asset, Project } from '../types';
import { api } from '../services/api';
import {
  Layers,
  Search,
  Plus,
  Globe,
  Server,
  FileCode,
  ShieldAlert,
  Calendar,
  AlertCircle,
  ExternalLink,
  Filter,
} from 'lucide-react';

interface AssetInventoryPageProps {
  activeProject?: Project;
}

export const AssetInventoryPage: React.FC<AssetInventoryPageProps> = ({ activeProject }) => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [criticalityFilter, setCriticalityFilter] = useState('all');
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);

  // New asset form state
  const [newAssetName, setNewAssetName] = useState('');
  const [newAssetUrl, setNewAssetUrl] = useState('');
  const [newHttpMethod, setNewHttpMethod] = useState('GET');
  const [newAssetType, setNewAssetType] = useState('endpoint');
  const [newCriticality, setNewCriticality] = useState('Medium');
  const [newTechnology, setNewTechnology] = useState('');
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadAssets();
  }, [activeProject]);

  const loadAssets = async () => {
    try {
      setLoading(true);
      const res = await api.getAssets({
        project_id: activeProject?.id,
        asset_type: typeFilter !== 'all' ? typeFilter : undefined,
        criticality: criticalityFilter !== 'all' ? criticalityFilter : undefined,
        search: searchTerm || undefined,
      });
      setAssets(res.assets);
    } catch (err) {
      console.error('Failed to load assets:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeProject) {
      setFormError('Please select or create a project first');
      return;
    }
    if (!newAssetName.trim()) {
      setFormError('Asset endpoint name is required');
      return;
    }

    try {
      setSubmitting(true);
      setFormError('');
      await api.createAsset({
        project_id: activeProject.id,
        name: newAssetName.trim(),
        url: newAssetUrl.trim() || undefined,
        http_method: newHttpMethod,
        asset_type: newAssetType,
        criticality: newCriticality,
        technology: newTechnology.trim() || undefined,
      });
      setIsRegisterOpen(false);
      setNewAssetName('');
      setNewAssetUrl('');
      loadAssets();
    } catch (err: any) {
      setFormError(err.message || 'Failed to register asset');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredAssets = assets.filter((a) => {
    const matchSearch =
      a.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (a.url && a.url.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (a.technology && a.technology.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchType = typeFilter === 'all' || a.asset_type === typeFilter;
    const matchCrit = criticalityFilter === 'all' || a.criticality.toLowerCase() === criticalityFilter.toLowerCase();
    return matchSearch && matchType && matchCrit;
  });

  const getCriticalityBadge = (crit: string) => {
    switch (crit.toLowerCase()) {
      case 'critical':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'high':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'medium':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      default:
        return 'bg-slate-50 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-600" />
            Asset & Attack Surface Inventory
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Discovered domains, HTTP endpoints, and API surfaces for {activeProject?.name || 'all projects'}.
          </p>
        </div>
        <button
          onClick={() => setIsRegisterOpen(true)}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-600 text-white text-xs font-semibold hover:bg-emerald-700 transition shadow-xs cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          Register Endpoint
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-xs font-medium text-slate-500">Total Assets</div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{assets.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">Endpoints & Domains</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-xs font-medium text-slate-500">API Routes</div>
          <div className="text-2xl font-bold text-indigo-600 mt-1">
            {assets.filter((a) => a.asset_type === 'api_endpoint').length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">REST / GraphQL services</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-xs font-medium text-slate-500">Critical Surface</div>
          <div className="text-2xl font-bold text-red-600 mt-1">
            {assets.filter((a) => a.criticality === 'Critical' || a.criticality === 'High').length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">High exposure targets</div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-xs font-medium text-slate-500">With Active Findings</div>
          <div className="text-2xl font-bold text-amber-600 mt-1">
            {assets.filter((a) => (a.finding_count || 0) > 0).length}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Endpoints needing fixes</div>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs flex flex-col md:flex-row md:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search endpoint path, URL, or technology..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-emerald-500 text-slate-800"
          />
        </div>
        <div className="flex items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none"
          >
            <option value="all">All Asset Types</option>
            <option value="endpoint">Web Endpoints</option>
            <option value="api_endpoint">API Endpoints</option>
            <option value="domain">Domains</option>
          </select>
          <select
            value={criticalityFilter}
            onChange={(e) => setCriticalityFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none"
          >
            <option value="all">All Criticalities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Asset List Table */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">Loading asset inventory...</div>
        ) : filteredAssets.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No assets match current filters. Trigger a scan or register an endpoint manually.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-medium">
                  <th className="py-3 px-4">Method & Endpoint</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Criticality</th>
                  <th className="py-3 px-4">Active Findings</th>
                  <th className="py-3 px-4">Technology</th>
                  <th className="py-3 px-4">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2 font-mono">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            asset.http_method === 'POST'
                              ? 'bg-blue-100 text-blue-800'
                              : asset.http_method === 'DELETE'
                              ? 'bg-red-100 text-red-800'
                              : asset.http_method === 'PUT' || asset.http_method === 'PATCH'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-emerald-100 text-emerald-800'
                          }`}
                        >
                          {asset.http_method || 'GET'}
                        </span>
                        <span className="font-medium text-slate-900 truncate max-w-xs">{asset.name}</span>
                      </div>
                      {asset.url && asset.url !== asset.name && (
                        <div className="text-[11px] text-slate-400 font-sans truncate max-w-xs mt-0.5">
                          {asset.url}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="capitalize text-slate-600 bg-slate-100 px-2 py-0.5 rounded text-[11px]">
                        {asset.asset_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getCriticalityBadge(
                          asset.criticality
                        )}`}
                      >
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {(asset.finding_count || 0) > 0 ? (
                        <span className="inline-flex items-center gap-1 text-red-600 font-bold bg-red-50 border border-red-200 px-2 py-0.5 rounded text-[11px]">
                          <ShieldAlert className="w-3 h-3" />
                          {asset.finding_count} vulnerabilities
                        </span>
                      ) : (
                        <span className="text-slate-400 font-medium">Clean (0)</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-slate-500">{asset.technology || 'Web Application'}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Register Asset Modal */}
      {isRegisterOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/30 backdrop-blur-xs">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden p-6 space-y-4">
            <h2 className="text-base font-bold text-slate-900">Register Target Asset / API Endpoint</h2>
            <p className="text-xs text-slate-500">
              Track newly exposed endpoints, internal microservices, or APIs in the attack surface inventory.
            </p>

            {formError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                {formError}
              </div>
            )}

            <form onSubmit={handleRegisterAsset} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Endpoint Path or Route <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="/api/v1/auth/tokens"
                  value={newAssetName}
                  onChange={(e) => setNewAssetName(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:ring-1 focus:ring-emerald-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">HTTP Method</label>
                  <select
                    value={newHttpMethod}
                    onChange={(e) => setNewHttpMethod(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="PATCH">PATCH</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Asset Type</label>
                  <select
                    value={newAssetType}
                    onChange={(e) => setNewAssetType(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  >
                    <option value="endpoint">Web Endpoint</option>
                    <option value="api_endpoint">API Endpoint</option>
                    <option value="domain">Domain / Host</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Criticality</label>
                  <select
                    value={newCriticality}
                    onChange={(e) => setNewCriticality(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  >
                    <option value="Critical">Critical (Blocks Gating)</option>
                    <option value="High">High Exposure</option>
                    <option value="Medium">Medium (Standard)</option>
                    <option value="Low">Low / Internal</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Technology Stack</label>
                  <input
                    type="text"
                    placeholder="Express / Node.js"
                    value={newTechnology}
                    onChange={(e) => setNewTechnology(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Full URL (Optional)</label>
                <input
                  type="text"
                  placeholder="https://app.securegate.io/api/v1/tokens"
                  value={newAssetUrl}
                  onChange={(e) => setNewAssetUrl(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsRegisterOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded-lg font-medium cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg font-semibold shadow-xs cursor-pointer disabled:opacity-50"
                >
                  {submitting ? 'Registering...' : 'Save Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
