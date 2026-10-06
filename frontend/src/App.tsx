import React, { useState, useEffect } from 'react';
import { DashboardLayout } from './layouts/DashboardLayout';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { ScansPage } from './pages/ScansPage';
import { ReleasesPage } from './pages/ReleasesPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ProjectsPage } from './pages/ProjectsPage';
import { Project, Scan, DashboardData } from './types';
import { api } from './services/api';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<number | undefined>(undefined);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loadingDashboard, setLoadingDashboard] = useState(true);
  const [reportScanId, setReportScanId] = useState<number | null>(null);
  const [resettingDemo, setResettingDemo] = useState(false);
  const [apiConnected, setApiConnected] = useState(false);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);

  // Initial load
  useEffect(() => {
    checkHealth();
    loadProjects();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await api.checkHealth();
      setApiConnected(res.status === 'healthy');
    } catch {
      setApiConnected(false);
    }
  };

  const loadProjects = async () => {
    try {
      const projs = await api.getProjects();
      setProjects(projs);
      if (projs.length > 0 && !activeProjectId) {
        setActiveProjectId(projs[0].id);
      }
    } catch (err) {
      console.error('Failed to load projects:', err);
    }
  };

  // Load dashboard data when active project changes
  useEffect(() => {
    if (activeProjectId) {
      loadDashboard(activeProjectId);
    }
  }, [activeProjectId]);

  const loadDashboard = async (projId: number) => {
    try {
      setLoadingDashboard(true);
      const data = await api.getDashboard(projId);
      setDashboardData(data);
      if (data.latest_scan) {
        setReportScanId(data.latest_scan.id);
      }
    } catch (err) {
      console.error('Failed to load dashboard:', err);
    } finally {
      setLoadingDashboard(false);
    }
  };

  const handleResetDemo = async () => {
    try {
      setResettingDemo(true);
      await api.seedDemoProject();
      const projs = await api.getProjects();
      setProjects(projs);
      if (projs.length > 0) {
        setActiveProjectId(projs[0].id);
        await loadDashboard(projs[0].id);
      }
      setCurrentTab('dashboard');
    } catch (err) {
      alert(`Failed to reset demo: ${err}`);
    } finally {
      setResettingDemo(false);
    }
  };

  const handleScanCompleted = async (scan: Scan) => {
    if (activeProjectId) {
      await loadDashboard(activeProjectId);
    }
    setReportScanId(scan.id);
    setCurrentTab('dashboard');
  };

  const handleTriggerPreset = async (preset: 'juiceshop' | 'clean' | 'medium') => {
    try {
      setLoadingDashboard(true);
      const scan = await api.simulatePreset(preset, activeProjectId);
      await handleScanCompleted(scan);
    } catch (err) {
      alert(`Simulation failed: ${err}`);
      setLoadingDashboard(false);
    }
  };

  const activeProject = projects.find((p) => p.id === activeProjectId);

  return (
    <DashboardLayout
      currentTab={currentTab}
      onSelectTab={setCurrentTab}
      projects={projects}
      activeProject={activeProject}
      onSelectProject={(id) => setActiveProjectId(id)}
      latestScan={dashboardData?.latest_scan}
      onScanCompleted={handleScanCompleted}
      onResetDemo={handleResetDemo}
      resettingDemo={resettingDemo}
      apiConnected={apiConnected}
      onTriggerPreset={handleTriggerPreset}
      isNewScanOpen={isNewScanOpen}
      onOpenNewScan={() => setIsNewScanOpen(true)}
      onCloseNewScan={() => setIsNewScanOpen(false)}
    >
      {currentTab === 'dashboard' && (
        <DashboardPage
          data={dashboardData}
          loading={loadingDashboard}
          onNavigate={(tab) => setCurrentTab(tab)}
          onOpenNewScan={() => setIsNewScanOpen(true)}
        />
      )}

      {currentTab === 'findings' && (
        <FindingsPage
          activeProjectId={activeProjectId}
          initialScanId={dashboardData?.latest_scan?.id}
        />
      )}

      {currentTab === 'scans' && (
        <ScansPage
          activeProjectId={activeProjectId}
          onOpenNewScan={() => setIsNewScanOpen(true)}
          onNavigateToReport={(scanId) => {
            setReportScanId(scanId);
            setCurrentTab('reports');
          }}
          onNavigateToFindings={() => setCurrentTab('findings')}
        />
      )}

      {currentTab === 'releases' && (
        <ReleasesPage
          activeProjectId={activeProjectId}
          onNavigateToReport={(scanId) => {
            setReportScanId(scanId);
            setCurrentTab('reports');
          }}
        />
      )}

      {currentTab === 'reports' && (
        <ReportsPage
          activeProjectId={activeProjectId}
          initialScanId={reportScanId}
        />
      )}

      {currentTab === 'projects' && (
        <ProjectsPage
          projects={projects}
          activeProjectId={activeProjectId}
          onSelectProject={(id) => {
            setActiveProjectId(id);
            setCurrentTab('dashboard');
          }}
          onRefreshProjects={loadProjects}
        />
      )}

      {currentTab === 'settings' && <SettingsPage />}
    </DashboardLayout>
  );
}

export default App;
