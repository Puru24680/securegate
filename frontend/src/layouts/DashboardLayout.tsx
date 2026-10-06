import React, { useState } from 'react';
import { Sidebar } from '../components/Sidebar';
import { TopBar } from '../components/TopBar';
import { NewScanModal } from '../components/NewScanModal';
import { Project, Scan } from '../types';
import { api } from '../services/api';

interface DashboardLayoutProps {
  children: React.ReactNode;
  currentTab: string;
  onSelectTab: (tab: string) => void;
  projects: Project[];
  activeProject?: Project;
  onSelectProject: (id: number) => void;
  latestScan?: Scan;
  onScanCompleted: (scan: Scan) => void;
  onResetDemo: () => void;
  resettingDemo: boolean;
  apiConnected: boolean;
  onTriggerPreset?: (preset: 'juiceshop' | 'clean' | 'medium') => void;
  isNewScanOpen?: boolean;
  onOpenNewScan?: () => void;
  onCloseNewScan?: () => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  children,
  currentTab,
  onSelectTab,
  projects,
  activeProject,
  onSelectProject,
  latestScan,
  onScanCompleted,
  onResetDemo,
  resettingDemo,
  apiConnected,
  onTriggerPreset,
  isNewScanOpen: externalIsNewScanOpen,
  onOpenNewScan,
  onCloseNewScan,
}) => {
  const [internalIsNewScanOpen, setInternalIsNewScanOpen] = useState(false);
  const [presetLoading, setPresetLoading] = useState(false);

  const isModalOpen = externalIsNewScanOpen !== undefined ? externalIsNewScanOpen : internalIsNewScanOpen;
  const handleOpenModal = onOpenNewScan || (() => setInternalIsNewScanOpen(true));
  const handleCloseModal = onCloseNewScan || (() => setInternalIsNewScanOpen(false));

  const handlePreset = async (preset: 'juiceshop' | 'clean' | 'medium') => {
    if (onTriggerPreset) {
      onTriggerPreset(preset);
      return;
    }
    try {
      setPresetLoading(true);
      const scan = await api.simulatePreset(preset, activeProject?.id);
      onScanCompleted(scan);
    } catch (err) {
      console.error('Preset error:', err);
      alert(`Simulation failed: ${err}`);
    } finally {
      setPresetLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-[#F8FAFC] text-slate-800 font-sans selection:bg-emerald-500 selection:text-white">
      {/* Crisp White Sidebar (Fynix Image 1) */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={onSelectTab}
        onResetDemo={onResetDemo}
        resettingDemo={resettingDemo || presetLoading}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#F8FAFC]">
        {/* Crisp TopBar (Fynix Image 1) */}
        <TopBar
          projects={projects}
          activeProject={activeProject}
          onSelectProject={onSelectProject}
          latestScan={latestScan}
          onOpenNewScan={handleOpenModal}
          apiConnected={apiConnected}
          onTriggerPreset={handlePreset}
        />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto px-6 sm:px-10 py-8 max-w-[1500px] w-full">
          {children}
        </main>
      </div>

      {/* Global New Scan / Upload ZAP Modal */}
      <NewScanModal
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        projects={projects}
        activeProjectId={activeProject?.id}
        onScanCompleted={(scan) => {
          onScanCompleted(scan);
          handleCloseModal();
        }}
      />
    </div>
  );
};
