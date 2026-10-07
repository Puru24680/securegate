import React from 'react';
import {
  LayoutDashboard,
  FolderGit2,
  ScanSearch,
  ShieldAlert,
  GitMerge,
  FileText,
  Sliders,
  RotateCcw,
  Shield,
  Layers,
  Zap,
  GitBranch,
} from 'lucide-react';
import { cn } from '../utils/cn';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  onResetDemo: () => void;
  resettingDemo: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  onResetDemo,
  resettingDemo,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'scans', label: 'Scans', icon: ScanSearch },
    { id: 'zap-scanner', label: 'ZAP Scanner', icon: Zap },
    { id: 'ci-cd', label: 'CI/CD & Actions', icon: GitBranch },
    { id: 'releases', label: 'Releases', icon: GitMerge },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'projects', label: 'Projects', icon: FolderGit2 },
    { id: 'settings', label: 'Settings', icon: Sliders },
  ];

  return (
    <aside className="w-60 bg-white border-r border-slate-200 flex flex-col justify-between min-h-screen text-slate-700 select-none flex-shrink-0 z-30">
      <div>
        {/* Clean Minimal Brand */}
        <div className="px-5 py-5 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-emerald-600 flex items-center justify-center text-white shadow-xs">
            <Shield className="w-4 h-4 fill-current" />
          </div>
          <div>
            <div className="font-semibold text-sm text-slate-900">
              SecureGate
            </div>
            <div className="text-xs text-slate-500">
              Pre-release security
            </div>
          </div>
        </div>

        {/* Quiet Project Indicator */}
        <div className="px-4 pb-2">
          <a
            href="http://localhost:3000"
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-2 rounded-lg bg-slate-50 hover:bg-slate-100/90 border border-slate-200/80 flex items-center justify-between transition-colors group cursor-pointer block"
            title="Open live OWASP Juice Shop instance in new tab"
          >
            <div className="flex items-center justify-between w-full">
              <div className="min-w-0 pr-2">
                <div className="text-xs font-semibold text-slate-800 truncate group-hover:text-emerald-700 transition-colors">
                  OWASP Juice Shop
                </div>
                <div className="text-[11px] text-slate-500 truncate font-mono">
                  localhost:3000
                </div>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-500 flex-shrink-0" title="Active Target" />
            </div>
          </a>
        </div>

        {/* Navigation */}
        <nav className="px-3 py-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={cn(
                  'w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-colors cursor-pointer text-left',
                  isActive
                    ? 'bg-slate-100 text-slate-900 font-medium'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-normal'
                )}
              >
                <Icon
                  className={cn(
                    'w-4 h-4 flex-shrink-0',
                    isActive ? 'text-slate-900' : 'text-slate-400'
                  )}
                />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Quiet Bottom Action */}
      <div className="p-4 border-t border-slate-100">
        <button
          onClick={onResetDemo}
          disabled={resettingDemo}
          className="w-full py-2 px-3 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 text-xs font-medium flex items-center justify-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
        >
          <RotateCcw className={cn('w-3.5 h-3.5', resettingDemo && 'animate-spin text-slate-800')} />
          <span>{resettingDemo ? 'Resetting...' : 'Reset demo scan'}</span>
        </button>
      </div>
    </aside>
  );
};
