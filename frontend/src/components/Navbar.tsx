import React from 'react';
import { Project, Scan } from '../types';
import {
  UploadCloud,
  Shield,
  Layers,
  Sparkles,
  Play,
  RotateCcw,
  Sliders,
  FileText,
  GitMerge,
  ScanSearch,
  ShieldAlert,
  LayoutDashboard,
} from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  projects: Project[];
  activeProject?: Project;
  onSelectProject: (projectId: number) => void;
  onOpenNewScan: () => void;
  onTriggerPreset: (preset: 'juiceshop' | 'clean' | 'medium') => void;
  onResetDemo: () => void;
  resettingDemo: boolean;
  apiConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  projects,
  activeProject,
  onSelectProject,
  onOpenNewScan,
  onTriggerPreset,
  onResetDemo,
  resettingDemo,
  apiConnected,
}) => {
  const navTabs = [
    { id: 'dashboard', label: 'Console', icon: LayoutDashboard },
    { id: 'findings', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'scans', label: 'Scan Audit', icon: ScanSearch },
    { id: 'releases', label: 'Releases', icon: GitMerge },
    { id: 'reports', label: 'Dossier', icon: FileText },
    { id: 'settings', label: 'Policy', icon: Sliders },
  ];

  return (
    <header className="sticky top-4 z-50 px-4 sm:px-8 max-w-[1440px] mx-auto select-none">
      <div className="rounded-3xl glass-panel-elevated px-5 py-3 flex items-center justify-between gap-4 border border-white/10 shadow-2xl backdrop-blur-3xl">
        {/* Left: Brand Identity */}
        <div
          onClick={() => onSelectTab('dashboard')}
          className="flex items-center gap-3 cursor-pointer group flex-shrink-0"
        >
          <div className="relative w-9 h-9 rounded-2xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/30 border border-white/20 group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5 text-white" />
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-[#050814]" />
          </div>
          <div>
            <div className="text-base font-black font-display tracking-tight text-white flex items-center gap-1">
              SECURE<span className="text-blue-400">GATE</span>
            </div>
            <span className="text-[9px] font-mono tracking-widest text-slate-400 uppercase block -mt-1">
              DevSecOps Gating
            </span>
          </div>
        </div>

        {/* Center: Segmented Navigation Pills */}
        <nav className="hidden md:flex items-center gap-1 bg-white/[0.03] p-1.5 rounded-full border border-white/5">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onSelectTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-mono transition-all duration-200 ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-semibold shadow-glow-blue'
                    : 'text-slate-400 hover:text-white hover:bg-white/5'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Right: Quick Action Controls */}
        <div className="flex items-center gap-2.5 flex-shrink-0">
          {/* Target Selector Capsule */}
          <div className="hidden xl:flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.03] border border-white/10 text-xs font-mono">
            <span className="text-slate-500 text-[10px] uppercase">Node:</span>
            <select
              value={activeProject?.id || ''}
              onChange={(e) => onSelectProject(Number(e.target.value))}
              className="bg-transparent text-white font-medium focus:outline-none cursor-pointer text-xs"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id} className="bg-[#0b0f19] text-white">
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          {/* 1-Click Fast Scenarios Dropdown / Quick Buttons */}
          <div className="hidden lg:flex items-center gap-1.5">
            <button
              onClick={() => onTriggerPreset('juiceshop')}
              className="px-2.5 py-1 text-[11px] font-mono rounded-full bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/25 transition-all flex items-center gap-1"
              title="Test High/Critical findings causing BLOCK"
            >
              <Play className="w-2.5 h-2.5 fill-current" />
              <span>Simulate Block</span>
            </button>
            <button
              onClick={() => onTriggerPreset('clean')}
              className="px-2.5 py-1 text-[11px] font-mono rounded-full bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/25 transition-all flex items-center gap-1"
              title="Test hardened scan causing PASS"
            >
              <Play className="w-2.5 h-2.5 fill-current" />
              <span>Simulate Pass</span>
            </button>
          </div>

          {/* Primary Import ZAP Button */}
          <button
            onClick={onOpenNewScan}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-mono font-semibold shadow-glow-blue transition-all border border-white/15"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Import ZAP</span>
          </button>
        </div>
      </div>
    </header>
  );
};
