import React, { useState } from 'react';
import { Project } from '../types';
import {
  GitBranch,
  Terminal,
  Copy,
  Check,
  Download,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  ExternalLink,
  Code2,
  FileCode,
  CheckCircle2,
} from 'lucide-react';

interface CiCdPageProps {
  projects: Project[];
  activeProject?: Project;
}

export const CiCdPage: React.FC<CiCdPageProps> = ({ projects, activeProject }) => {
  const [selectedProjectId, setSelectedProjectId] = useState<number>(
    activeProject?.id || (projects[0]?.id ?? 1)
  );
  const [targetUrl, setTargetUrl] = useState<string>(
    activeProject?.target_url || 'https://pentest-ground.com:4280'
  );
  const [failOn, setFailOn] = useState<'BLOCK' | 'REVIEW'>('BLOCK');
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const selectedProj = projects.find((p) => p.id === selectedProjectId) || activeProject;

  const yamlContent = `name: SecureGate Pre-Release Quality Gate

on:
  push:
    branches: [ main, master, 'release/**' ]
  pull_request:
    branches: [ main, master ]
  workflow_dispatch:
    inputs:
      target_url:
        description: 'Target Application URL to Scan'
        required: true
        default: '${targetUrl}'
      fail_on:
        description: 'Gate Failure Threshold'
        required: true
        default: '${failOn}'
        type: choice
        options:
          - BLOCK
          - REVIEW

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  security-gate:
    name: OWASP ZAP Dynamic Scan & SecureGate Quality Gate
    runs-on: ubuntu-latest

    steps:
      - name: 📥 Checkout Code
        uses: actions/checkout@v4

      - name: 🐍 Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: ⚡ Execute OWASP ZAP Baseline Security Scan
        uses: zaproxy/action-baseline@v0.14.0
        with:
          token: \${{ secrets.GITHUB_TOKEN }}
          docker_name: 'ghcr.io/zaproxy/zaproxy:stable'
          target: '\${{ github.event.inputs.target_url || '${targetUrl}' }}'
          cmd_options: '-a -j'
          allow_issue_writing: false
        continue-on-error: true

      - name: 🛡️ Enforce SecureGate Pre-Release Quality Gate
        env:
          SECUREGATE_API_URL: \${{ secrets.SECUREGATE_API_URL || 'https://securegate-ebon.vercel.app' }}
          SECUREGATE_PROJECT_ID: '${selectedProjectId}'
          FAIL_ON: '${failOn}'
        run: |
          REPORT="zap_report.json"
          [ ! -f "$REPORT" ] && REPORT="report.json"
          python scripts/securegate-gate.py \\
            --report "$REPORT" \\
            --api-url "\$SECUREGATE_API_URL" \\
            --project-id "\$SECUREGATE_PROJECT_ID" \\
            --fail-on "\$FAIL_ON" \\
            --github-summary

      - name: 📦 Archive Security Scan Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securegate-audit-artifacts
          path: |
            *.json
            *.html
          retention-days: 14`;

  const cliSnippet = `python scripts/securegate-gate.py \\
  --report zap_report.json \\
  --api-url https://securegate-ebon.vercel.app \\
  --project-id ${selectedProjectId} \\
  --fail-on ${failOn} \\
  --github-summary`;

  const curlSnippet = `curl -X POST https://securegate-ebon.vercel.app/api/scans/upload \\
  -H "Content-Type: application/json" \\
  -d '{
    "project_id": ${selectedProjectId},
    "target_url": "${targetUrl}",
    "report": $(cat zap_report.json)
  }'`;

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadYamlFile = () => {
    const blob = new Blob([yamlContent], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'securegate-ci.yml';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 select-none">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-indigo-50 text-indigo-600 border border-indigo-200">
              <GitBranch className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold text-slate-900">
              CI/CD & GitHub Actions Integration
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Automate dynamic security testing on every push and PR. Block vulnerable releases before production.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => copyToClipboard(yamlContent, setCopiedYaml)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs cursor-pointer"
          >
            {copiedYaml ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedYaml ? 'Copied YAML!' : 'Copy Workflow'}
          </button>
          <button
            onClick={downloadYamlFile}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium transition-colors shadow-2xs cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Download .yml
          </button>
        </div>
      </div>

      {/* Interactive Configurator */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2">
          <label className="text-xs font-semibold text-slate-700 block">Target Project</label>
          <select
            value={selectedProjectId}
            onChange={(e) => {
              const pid = Number(e.target.value);
              setSelectedProjectId(pid);
              const p = projects.find((x) => x.id === pid);
              if (p) setTargetUrl(p.target_url);
            }}
            className="w-full text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                #{p.id} - {p.name}
              </option>
            ))}
          </select>
          <p className="text-[11px] text-slate-400">
            Select which SecureGate project records these scan results.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2">
          <label className="text-xs font-semibold text-slate-700 block">Scanned Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 focus:bg-white focus:outline-none font-mono"
            placeholder="https://example.com"
          />
          <p className="text-[11px] text-slate-400">
            Target application to scan in the GitHub Actions runner.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2">
          <label className="text-xs font-semibold text-slate-700 block">Gate Failure Threshold</label>
          <div className="grid grid-cols-2 gap-2 pt-0.5">
            <button
              type="button"
              onClick={() => setFailOn('BLOCK')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border text-center transition-all cursor-pointer ${
                failOn === 'BLOCK'
                  ? 'bg-rose-50 border-rose-300 text-rose-700 font-semibold'
                  : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
              }`}
            >
              Fail on BLOCK
            </button>
            <button
              type="button"
              onClick={() => setFailOn('REVIEW')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border text-center transition-all cursor-pointer ${
                failOn === 'REVIEW'
                  ? 'bg-amber-50 border-amber-300 text-amber-700 font-semibold'
                  : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
              }`}
            >
              Fail on REVIEW
            </button>
          </div>
          <p className="text-[11px] text-slate-400">
            {failOn === 'BLOCK'
              ? 'Blocks pipeline if any Critical or High severity findings exist.'
              : 'Strict: Blocks pipeline if Medium, High, or Critical findings exist.'}
          </p>
        </div>
      </div>

      {/* GitHub Actions YAML Preview */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-xs">
        <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
            <FileCode className="w-4 h-4 text-emerald-400" />
            <span>.github/workflows/securegate-ci.yml</span>
          </div>
          <button
            onClick={() => copyToClipboard(yamlContent, setCopiedYaml)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors cursor-pointer"
          >
            {copiedYaml ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedYaml ? 'Copied' : 'Copy'}
          </button>
        </div>
        <pre className="p-4 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed max-h-96">
          {yamlContent}
        </pre>
      </div>

      {/* Alternative Integration Methods */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* CLI Runner */}
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-700" />
              <h3 className="text-xs font-bold text-slate-900">Standalone CLI / Docker Runner</h3>
            </div>
            <button
              onClick={() => copyToClipboard(cliSnippet, setCopiedCli)}
              className="p-1.5 rounded hover:bg-slate-100 text-slate-500 cursor-pointer"
              title="Copy CLI command"
            >
              {copiedCli ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <p className="text-xs text-slate-500">
            Run the evaluator locally or inside any CI environment (GitLab CI, Bitbucket, CircleCI, Jenkins).
          </p>
          <pre className="p-3 rounded-lg bg-slate-900 text-slate-200 text-[11px] font-mono overflow-x-auto leading-normal">
            {cliSnippet}
          </pre>
        </div>

        {/* Direct cURL API */}
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-slate-700" />
              <h3 className="text-xs font-bold text-slate-900">Direct cURL API Upload</h3>
            </div>
            <button
              onClick={() => copyToClipboard(curlSnippet, setCopiedCurl)}
              className="p-1.5 rounded hover:bg-slate-100 text-slate-500 cursor-pointer"
              title="Copy cURL snippet"
            >
              {copiedCurl ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <p className="text-xs text-slate-500">
            Submit existing ZAP JSON reports directly from any deployment step using HTTP POST.
          </p>
          <pre className="p-3 rounded-lg bg-slate-900 text-slate-200 text-[11px] font-mono overflow-x-auto leading-normal">
            {curlSnippet}
          </pre>
        </div>
      </div>

      {/* Setup Guide Cards */}
      <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
        <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
          Quick Setup Steps for Your GitHub Repository
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3.5 rounded-lg bg-white border border-slate-200 space-y-1">
            <div className="w-5 h-5 rounded-full bg-slate-900 text-white text-[11px] font-bold flex items-center justify-center">
              1
            </div>
            <div className="text-xs font-semibold text-slate-800">Add Workflow File</div>
            <p className="text-[11px] text-slate-500">
              Save as <code className="text-emerald-700 font-mono">.github/workflows/securegate.yml</code> in your repository.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-white border border-slate-200 space-y-1">
            <div className="w-5 h-5 rounded-full bg-slate-900 text-white text-[11px] font-bold flex items-center justify-center">
              2
            </div>
            <div className="text-xs font-semibold text-slate-800">Add CLI Script</div>
            <p className="text-[11px] text-slate-500">
              Keep <code className="text-emerald-700 font-mono">scripts/securegate-gate.py</code> committed in your repository.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-white border border-slate-200 space-y-1">
            <div className="w-5 h-5 rounded-full bg-slate-900 text-white text-[11px] font-bold flex items-center justify-center">
              3
            </div>
            <div className="text-xs font-semibold text-slate-800">Configure Secrets</div>
            <p className="text-[11px] text-slate-500">
              Optionally set <code className="text-slate-700 font-mono">SECUREGATE_API_URL</code> in GitHub Repo Secrets.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
