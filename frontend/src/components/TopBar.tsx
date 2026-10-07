import React, { useState, useEffect, useRef } from 'react';
import { Project, Scan } from '../types';
import {
  UploadCloud,
  Search,
  ChevronDown,
  ChevronRight,
  User,
  SlidersHorizontal,
  CheckCircle2,
  XCircle,
  Zap,
  GitBranch,
} from 'lucide-react';

interface TopBarProps {
  projects: Project[];
  activeProject?: Project;
  onSelectProject: (projectId: number) => void;
  latestScan?: Scan;
  onOpenNewScan: () => void;
  apiConnected: boolean;
  onTriggerPreset?: (preset: 'juiceshop' | 'clean' | 'medium') => void;
  onNavigateTab?: (tab: string) => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  projects,
  activeProject,
  onSelectProject,
  latestScan,
  onOpenNewScan,
  apiConnected,
  onTriggerPreset,
  onNavigateTab,
}) => {
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [showDemoMenu, setShowDemoMenu] = useState(false);
  const demoMenuRef = useRef<HTMLDivElement>(null);

  // Close demo controls popover on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (demoMenuRef.current && !demoMenuRef.current.contains(event.target as Node)) {
        setShowDemoMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Keyboard shortcut listener for fast testing
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement).tagName)) {
        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key.toLowerCase() === 'b' && onTriggerPreset) {
        onTriggerPreset('juiceshop');
      } else if (e.key.toLowerCase() === 'p' && onTriggerPreset) {
        onTriggerPreset('clean');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onTriggerPreset]);

  return (
    <header className="h-14 px-6 sm:px-8 bg-white border-b border-slate-200 flex items-center justify-between sticky top-0 z-20 select-none">
      {/* Left: Minimal Linear/Stripe Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs text-slate-500 font-medium">
        <span>Workspace</span>
        <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
        <span className="text-slate-900 font-semibold">
          {activeProject?.name || 'OWASP Juice Shop'}
        </span>
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 ml-1" title="Target connected" />
      </div>

      {/* Right: Search, Demo Controls, Import Scan, User Avatar */}
      <div className="flex items-center gap-2.5">
        {/* Subtle Search Input */}
        <div className="relative hidden md:flex items-center">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 pointer-events-none" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search findings, CWEs..."
            className="w-52 lg:w-64 pl-8 pr-10 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-300 transition-colors"
          />
          <kbd className="absolute right-2 px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-400 font-medium">
            ⌘K
          </kbd>
        </div>

        {/* Demo Controls Dropdown */}
        {onTriggerPreset && (
          <div className="relative" ref={demoMenuRef}>
            <button
              onClick={() => setShowDemoMenu(!showDemoMenu)}
              className="px-2.5 py-1.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Quick demo simulation presets"
            >
              <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
              <span className="hidden sm:inline">Demo Controls</span>
              <ChevronDown className="w-3 h-3 text-slate-400" />
            </button>

            {showDemoMenu && (
              <div className="absolute right-0 mt-1.5 w-52 bg-white rounded-lg border border-slate-200 shadow-lg py-1 z-30 text-xs">
                <div className="px-3 py-1 text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Simulation Presets
                </div>
                <button
                  onClick={() => {
                    onTriggerPreset('juiceshop');
                    setShowDemoMenu(false);
                  }}
                  className="w-full px-3 py-2 text-left hover:bg-rose-50 flex items-center justify-between group transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <XCircle className="w-3.5 h-3.5 text-rose-600" />
                    <span className="text-slate-800 group-hover:text-rose-900 font-medium">
                      Simulate Block
                    </span>
                  </div>
                  <kbd className="px-1.5 py-0.5 text-[10px] bg-slate-100 text-slate-600 rounded border border-slate-200">
                    B
                  </kbd>
                </button>
                <button
                  onClick={() => {
                    onTriggerPreset('clean');
                    setShowDemoMenu(false);
                  }}
                  className="w-full px-3 py-2 text-left hover:bg-emerald-50 flex items-center justify-between group transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-slate-800 group-hover:text-emerald-900 font-medium">
                      Simulate Pass
                    </span>
                  </div>
                  <kbd className="px-1.5 py-0.5 text-[10px] bg-slate-100 text-slate-600 rounded border border-slate-200">
                    P
                  </kbd>
                </button>
              </div>
            )}
          </div>
        )}

        {/* Quick Access to ZAP Live Scanner */}
        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('zap-scanner')}
            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-amber-200 bg-amber-50/70 hover:bg-amber-100 text-amber-800 text-xs font-medium transition-colors cursor-pointer"
            title="Open OWASP ZAP Live Scanner Cockpit"
          >
            <Zap className="w-3.5 h-3.5 fill-current text-amber-600" />
            <span>ZAP Scanner</span>
          </button>
        )}

        {/* Quick Access to CI/CD & GitHub Actions */}
        {onNavigateTab && (
          <button
            onClick={() => onNavigateTab('ci-cd')}
            className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-indigo-200 bg-indigo-50/70 hover:bg-indigo-100 text-indigo-800 text-xs font-medium transition-colors cursor-pointer"
            title="Open CI/CD & GitHub Actions Integration"
          >
            <GitBranch className="w-3.5 h-3.5 text-indigo-600" />
            <span>CI/CD</span>
          </button>
        )}

        {/* Primary Import Scan Button */}
        <button
          onClick={onOpenNewScan}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium transition-colors cursor-pointer shadow-xs"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Import Scan</span>
        </button>

        {/* Quiet User Menu Avatar */}
        <div className="w-7 h-7 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 cursor-pointer hover:bg-slate-200 transition-colors">
          <User className="w-3.5 h-3.5 text-slate-600" />
        </div>
      </div>
    </header>
  );
};
