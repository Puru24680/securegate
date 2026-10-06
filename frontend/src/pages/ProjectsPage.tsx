import React, { useState } from 'react';
import { Project } from '../types';
import { api } from '../services/api';
import {
  FolderGit2,
  Plus,
  ArrowRight,
  X,
} from 'lucide-react';

interface ProjectsPageProps {
  projects: Project[];
  activeProjectId?: number;
  onSelectProject: (id: number) => void;
  onRefreshProjects: () => void;
}

export const ProjectsPage: React.FC<ProjectsPageProps> = ({
  projects,
  activeProjectId,
  onSelectProject,
  onRefreshProjects,
}) => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('https://demo.owasp-juice.shop');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      setCreating(true);
      await api.createProject({
        name: name.trim(),
        target_url: targetUrl.trim(),
        description: description.trim(),
      });
      setName('');
      setDescription('');
      setShowCreateModal(false);
      onRefreshProjects();
    } catch (err) {
      alert(`Failed to register project: ${err}`);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6 select-none max-w-7xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            Projects
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Target web applications evaluated by the SecureGate security engine.
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium cursor-pointer transition-colors shadow-xs"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New project</span>
        </button>
      </div>

      {/* Projects Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {projects.map((p) => {
          const isActive = p.id === activeProjectId;

          return (
            <div
              key={p.id}
              onClick={() => onSelectProject(p.id)}
              className={`p-5 rounded-xl transition-colors cursor-pointer relative flex flex-col justify-between border ${
                isActive
                  ? 'bg-white border-emerald-600 shadow-[0_1px_3px_rgba(0,0,0,0.05)] ring-1 ring-emerald-600'
                  : 'bg-white border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)] hover:border-slate-300'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-slate-700 flex-shrink-0">
                      <FolderGit2 className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-slate-900">
                        {p.name}
                      </h3>
                      {p.is_demo && (
                        <span className="text-[10px] text-emerald-700 font-medium">
                          Demo project
                        </span>
                      )}
                    </div>
                  </div>

                  {isActive && (
                    <span className="text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded">
                      Active
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-600 line-clamp-2 leading-relaxed">
                  {p.description || 'Target web application evaluated under automated pre-release security verification.'}
                </p>

                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/70 text-xs text-slate-600 break-all space-y-0.5">
                  <span className="text-slate-400 block text-[10px]">URL</span>
                  <span className="text-slate-800 font-medium">{p.target_url}</span>
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                <span>Created {new Date(p.created_at).toLocaleDateString()}</span>
                <span className="text-slate-700 font-medium flex items-center gap-1 group-hover:text-emerald-700 transition-colors">
                  <span>{isActive ? 'Current' : 'Select'}</span>
                  <ArrowRight className="w-3 h-3" />
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/30 backdrop-blur-xs">
          <div className="relative w-full max-w-md bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-slate-100">
              <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <FolderGit2 className="w-4 h-4 text-emerald-600" />
                <span>Register new project</span>
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 text-slate-400 hover:text-slate-700 rounded-md hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="p-5 space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Project name
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Payments Microservice"
                  className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 focus:bg-white transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Target URL
                </label>
                <input
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://demo.owasp-juice.shop"
                  className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 focus:bg-white transition-colors"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-700">
                  Description (optional)
                </label>
                <textarea
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief overview of application purpose..."
                  className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-slate-300 focus:bg-white resize-none transition-colors"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 text-xs rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium cursor-pointer transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-40 cursor-pointer transition-colors shadow-xs"
                >
                  {creating ? 'Saving...' : 'Create project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
