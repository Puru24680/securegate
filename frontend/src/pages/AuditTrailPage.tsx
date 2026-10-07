import React, { useState, useEffect } from 'react';
import { AuditLog } from '../types';
import { api } from '../services/api';
import {
  FileText,
  Search,
  Filter,
  Shield,
  Clock,
  User,
  Activity,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
} from 'lucide-react';

export const AuditTrailPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [expandedRowId, setExpandedRowId] = useState<number | null>(null);

  useEffect(() => {
    loadLogs();
  }, []);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs({
        action: actionFilter !== 'all' ? actionFilter : undefined,
      });
      setLogs(res.audit_logs);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const matchSearch =
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.user_email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.resource_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.resource_id && log.resource_id.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchAction = actionFilter === 'all' || log.action.includes(actionFilter);
    return matchSearch && matchAction;
  });

  const getActionBadgeColor = (action: string) => {
    if (action.includes('risk_accepted')) return 'bg-amber-50 text-amber-700 border-amber-200';
    if (action.includes('false_positive')) return 'bg-blue-50 text-blue-700 border-blue-200';
    if (action.includes('scan')) return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    if (action.includes('policy')) return 'bg-purple-50 text-purple-700 border-purple-200';
    if (action.includes('delete')) return 'bg-red-50 text-red-700 border-red-200';
    return 'bg-slate-50 text-slate-700 border-slate-200';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <Activity className="w-5 h-5 text-emerald-600" />
          Immutable Audit Trail
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Tamper-evident, chronological compliance record of all security scans, policy changes, and risk acceptance sign-offs.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-xs flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search audit trail by actor, action, or resource..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-emerald-500 text-slate-800"
          />
        </div>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="px-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 focus:outline-none"
        >
          <option value="all">All Actions</option>
          <option value="scan">Scans & Jobs</option>
          <option value="finding">Finding Governance (Risk / FP)</option>
          <option value="policy">Policy Updates</option>
          <option value="project">Project Events</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400">Loading immutable audit logs...</div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No audit log entries found matching criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-medium">
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Resource</th>
                  <th className="py-3 px-4">Client IP</th>
                  <th className="py-3 px-4">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {filteredLogs.map((log) => {
                  const isExpanded = expandedRowId === log.id;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedRowId(isExpanded ? null : log.id)}
                        className="hover:bg-slate-50/80 transition-colors cursor-pointer"
                      >
                        <td className="py-3 px-4 text-slate-500 font-mono text-[11px] whitespace-nowrap">
                          {log.created_at ? new Date(log.created_at).toLocaleString() : 'N/A'}
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-medium text-slate-900 flex items-center gap-1.5">
                            <User className="w-3.5 h-3.5 text-slate-400" />
                            {log.user_email}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getActionBadgeColor(
                              log.action
                            )}`}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-600">
                          {log.resource_type} {log.resource_id ? `#${log.resource_id}` : ''}
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                          {log.ip_address || '127.0.0.1'}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-slate-600" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50/60">
                          <td colSpan={6} className="px-6 py-4">
                            <div className="text-[11px] font-semibold text-slate-700 mb-1.5">
                              Audit Event Metadata:
                            </div>
                            <pre className="p-3 bg-slate-900 text-slate-200 rounded-lg text-[11px] font-mono overflow-x-auto leading-relaxed">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
