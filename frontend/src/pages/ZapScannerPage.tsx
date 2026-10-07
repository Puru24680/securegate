import React, { useState, useEffect, useRef } from 'react';
import { Project, Scan } from '../types';
import { api } from '../services/api';
import {
  Zap,
  Globe,
  Play,
  RotateCw,
  Terminal,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Server,
  Copy,
  Check,
  ArrowRight,
  Sliders,
  ExternalLink,
} from 'lucide-react';

interface ZapScannerPageProps {
  projects: Project[];
  activeProject?: Project;
  onScanCompleted: (scan: Scan) => void;
}

export const ZapScannerPage: React.FC<ZapScannerPageProps> = ({
  projects,
  activeProject,
  onScanCompleted,
}) => {
  const [targetUrl, setTargetUrl] = useState<string>(
    activeProject?.target_url || 'https://pentest-ground.com:4280'
  );
  const [selectedProjectId, setSelectedProjectId] = useState<number>(
    activeProject?.id || (projects[0]?.id ?? 1)
  );
  const [scanType, setScanType] = useState<'full' | 'spider' | 'active'>('full');
  const [forceSimulate, setForceSimulate] = useState<boolean>(false);

  // Daemon health state
  const [daemonHealth, setDaemonHealth] = useState<{
    connected: boolean;
    version: string | null;
    url: string;
    latency_ms: number | null;
    error: string | null;
  } | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);

  // Quickstart command state
  const [dockerCmd, setDockerCmd] = useState(
    'docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true'
  );
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Scan execution state
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const [taskData, setTaskData] = useState<{
    id: string;
    target_url: string;
    stage: string;
    progress: number;
    status: string;
    logs: string[];
    scan_id: number | null;
    error: string | null;
    scan?: Scan;
  } | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const logBottomRef = useRef<HTMLDivElement>(null);

  // Check health on mount
  useEffect(() => {
    checkDaemon();
    loadQuickstart();
  }, []);

  const checkDaemon = async () => {
    try {
      setCheckingHealth(true);
      const res = await api.getZapHealth();
      setDaemonHealth(res.daemon);
      if (!res.daemon.connected) {
        setForceSimulate(true);
      }
    } catch {
      setDaemonHealth({
        connected: false,
        version: null,
        url: 'http://localhost:8080',
        latency_ms: null,
        error: 'Connection refused',
      });
      setForceSimulate(true);
    } finally {
      setCheckingHealth(false);
    }
  };

  const loadQuickstart = async () => {
    try {
      const res = await api.getZapQuickstart();
      if (res.docker_command) setDockerCmd(res.docker_command);
    } catch {}
  };

  // Poll active task status
  useEffect(() => {
    let interval: any;
    if (activeTaskId && isScanning) {
      interval = setInterval(async () => {
        try {
          const res = await api.getZapTaskStatus(activeTaskId);
          setTaskData(res.task);
          if (res.task.status === 'COMPLETED' || res.task.status === 'FAILED') {
            setIsScanning(false);
          }
        } catch (err) {
          console.error('Error polling ZAP task:', err);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [activeTaskId, isScanning]);

  // Auto-scroll logs
  useEffect(() => {
    if (logBottomRef.current) {
      logBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [taskData?.logs]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    try {
      setIsScanning(true);
      setTaskData(null);
      const res = await api.startZapScan({
        target_url: targetUrl.trim(),
        project_id: selectedProjectId,
        scan_type: scanType,
        simulate: forceSimulate || !daemonHealth?.connected,
      });
      setActiveTaskId(res.task_id);
    } catch (err: any) {
      alert(`Failed to start ZAP scan: ${err.message}`);
      setIsScanning(false);
    }
  };

  const copyDockerCommand = () => {
    navigator.clipboard.writeText(dockerCmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 select-none">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-amber-50 text-amber-600 border border-amber-200">
              <Zap className="w-5 h-5 fill-current" />
            </span>
            <h1 className="text-xl font-bold text-slate-900">
              OWASP ZAP Live Scanner
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Trigger dynamic web vulnerability scans directly via the OWASP ZAP REST API daemon.
          </p>
        </div>

        {/* Daemon Connection Badge */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-slate-200 shadow-2xs">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                daemonHealth?.connected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'
              }`}
            />
            <span className="text-xs font-medium text-slate-700">
              {daemonHealth?.connected
                ? `ZAP v${daemonHealth.version || '2.16.0'} Online (${daemonHealth.latency_ms}ms)`
                : 'ZAP Daemon Offline'}
            </span>
          </div>

          <button
            onClick={checkDaemon}
            disabled={checkingHealth}
            className="p-2 rounded-lg bg-white border border-slate-200 text-slate-600 hover:bg-slate-50 transition-colors shadow-2xs cursor-pointer"
            title="Refresh Daemon Status"
          >
            <RotateCw className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Scan Trigger + Quickstart Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Scan Trigger Form */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-5">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Globe className="w-4 h-4 text-slate-700" />
              Target Scan Configuration
            </h2>
            <span className="text-[11px] text-slate-500 font-mono">
              API Mode: {forceSimulate || !daemonHealth?.connected ? 'Diagnostic Runner' : 'Live Daemon'}
            </span>
          </div>

          <form onSubmit={handleStartScan} className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-700 block mb-1.5">
                Target Website URL
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://pentest-ground.com:4280 or http://localhost:3000"
                  className="w-full text-xs font-mono px-3 py-2 rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none focus:border-slate-400 transition-colors"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1.5">
                  Record into Project
                </label>
                <select
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(Number(e.target.value))}
                  className="w-full text-xs px-2.5 py-2 rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      #{p.id} - {p.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 block mb-1.5">
                  Scan Profile
                </label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value as any)}
                  className="w-full text-xs px-2.5 py-2 rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none"
                >
                  <option value="full">Full Scan (Spider + Active Scan)</option>
                  <option value="spider">Spider Crawl Only</option>
                  <option value="active">Active Vulnerability Scan Only</option>
                </select>
              </div>
            </div>

            {/* Simulation Mode Toggle */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs">
              <div>
                <span className="font-semibold text-slate-800">Runner Mode</span>
                <p className="text-[11px] text-slate-500">
                  {forceSimulate || !daemonHealth?.connected
                    ? 'Runs asynchronous vulnerability engine on target URL with simulated ZAP API lifecycle.'
                    : 'Dispatches live commands to the local ZAP daemon at http://localhost:8080.'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setForceSimulate(!forceSimulate)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                  forceSimulate || !daemonHealth?.connected
                    ? 'bg-amber-100 text-amber-800 border border-amber-300'
                    : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                }`}
              >
                {forceSimulate || !daemonHealth?.connected ? 'Runner Mode' : 'Live Daemon'}
              </button>
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className={`w-full py-2.5 rounded-lg text-xs font-semibold text-white flex items-center justify-center gap-2 transition-all shadow-xs cursor-pointer ${
                isScanning
                  ? 'bg-slate-400 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-700 active:scale-[0.99]'
              }`}
            >
              {isScanning ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Running ZAP Dynamic Analysis...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Launch ZAP Scan on Target
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right: ZAP Daemon Quickstart */}
        <div className="p-5 rounded-xl bg-slate-900 text-slate-200 border border-slate-800 shadow-xs space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Server className="w-4 h-4 text-amber-400" />
                Live ZAP Daemon
              </span>
              <span className="text-[10px] text-slate-400 font-mono">Port 8080</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Want to connect your real local OWASP ZAP scanner? Start the official Docker daemon container:
            </p>
            <div className="relative group">
              <pre className="p-3 rounded-lg bg-slate-950 text-amber-300 text-[11px] font-mono overflow-x-auto leading-relaxed border border-slate-800">
                {dockerCmd}
              </pre>
              <button
                onClick={copyDockerCommand}
                className="absolute top-2 right-2 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
                title="Copy Docker command"
              >
                {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Daemon default: <code className="text-slate-300">http://localhost:8080</code></span>
            <a
              href="https://www.zaproxy.org/docs/api/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline flex items-center gap-1"
            >
              Docs <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Real-time Progress & Execution Terminal */}
      {(isScanning || taskData) && (
        <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-lg space-y-0">
          {/* Terminal Header */}
          <div className="px-5 py-3.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-3 h-3 rounded-full bg-rose-500 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block" />
              <span className="text-xs font-mono text-slate-300 ml-2 font-medium">
                ZAP Engine Execution — {taskData?.stage || 'INITIALIZING'}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-emerald-400 font-semibold">
                {taskData?.progress || 0}%
              </span>
              <span
                className={`text-[11px] px-2 py-0.5 rounded font-medium ${
                  taskData?.status === 'COMPLETED'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : taskData?.status === 'FAILED'
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : 'bg-amber-950 text-amber-400 border border-amber-800'
                }`}
              >
                {taskData?.status || 'RUNNING'}
              </span>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-slate-800 h-1.5 overflow-hidden">
            <div
              className="bg-emerald-500 h-full transition-all duration-300 ease-out"
              style={{ width: `${taskData?.progress || 0}%` }}
            />
          </div>

          {/* Terminal Console Logs */}
          <div className="p-4 font-mono text-xs text-slate-300 max-h-72 overflow-y-auto space-y-1.5">
            {taskData?.logs.map((line, idx) => (
              <div
                key={idx}
                className={
                  line.includes('ERROR')
                    ? 'text-rose-400'
                    : line.includes('Gate') || line.includes('Release')
                    ? 'text-emerald-400 font-bold'
                    : 'text-slate-300'
                }
              >
                {line}
              </div>
            ))}
            <div ref={logBottomRef} />
          </div>

          {/* Completion Banner */}
          {taskData?.status === 'COMPLETED' && taskData.scan && (
            <div className="p-4 bg-slate-900 border-t border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span
                  className={`px-2.5 py-1 rounded text-xs font-bold ${
                    taskData.scan.release_status === 'BLOCK'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : taskData.scan.release_status === 'REVIEW'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  GATE: {taskData.scan.release_status}
                </span>
                <span className="text-xs text-slate-300">
                  Target: <strong className="text-white">{taskData.scan.target_url}</strong> | Score: {taskData.scan.security_score}/100 | Findings: {taskData.scan.total_findings}
                </span>
              </div>

              <button
                onClick={() => {
                  if (taskData.scan) {
                    onScanCompleted(taskData.scan);
                  }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors cursor-pointer"
              >
                View Full Audit Report <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
