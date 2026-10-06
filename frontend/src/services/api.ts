import {
  Project,
  Scan,
  Finding,
  Release,
  AppSettings,
  DashboardData,
  SecurityReport,
  AIAnalysisResult,
  FindingStatus,
} from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errorData = await response.json();
      if (errorData.message) {
        errorMsg = errorData.message;
      }
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }

  return response.json();
}

export const api = {
  // Health
  checkHealth: async () => {
    return request<{ status: string; database: string }>('/health');
  },

  // Projects
  getProjects: async () => {
    const res = await request<{ projects: Project[] }>('/projects');
    return res.projects;
  },

  createProject: async (data: { name: string; target_url: string; description?: string }) => {
    const res = await request<{ project: Project }>('/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return res.project;
  },

  seedDemoProject: async () => {
    const res = await request<{ project: Project }>('/projects/seed-demo', {
      method: 'POST',
    });
    return res.project;
  },

  // Dashboard
  getDashboard: async (projectId?: number, scanId?: number) => {
    const params = new URLSearchParams();
    if (projectId) params.append('project_id', projectId.toString());
    if (scanId) params.append('scan_id', scanId.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    return request<DashboardData>(`/dashboard${query}`);
  },

  // Scans
  getScans: async (projectId?: number) => {
    const query = projectId ? `?project_id=${projectId}` : '';
    const res = await request<{ scans: Scan[] }>(`/scans${query}`);
    return res.scans;
  },

  getScan: async (scanId: number, includeFindings = false) => {
    const res = await request<{ scan: Scan }>(`/scans/${scanId}?include_findings=${includeFindings}`);
    return res.scan;
  },

  uploadScanReport: async (payload: {
    project_id: number;
    report: any;
    target_url?: string;
    scan_identifier?: string;
  }) => {
    const res = await request<{ scan: Scan }>('/scans/upload', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return res.scan;
  },

  uploadScanFile: async (file: File, projectId: number, targetUrl?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('project_id', projectId.toString());
    if (targetUrl) formData.append('target_url', targetUrl);

    const response = await fetch(`${API_BASE}/scans/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.message || 'File upload failed');
    }
    const data = await response.json();
    return data.scan as Scan;
  },

  deleteScan: async (scanId: number) => {
    return request<{ message: string }>(`/scans/${scanId}`, {
      method: 'DELETE',
    });
  },

  simulatePreset: async (preset: 'juiceshop' | 'clean' | 'medium', projectId?: number) => {
    const res = await request<{ scan: Scan }>('/scans/simulate-preset', {
      method: 'POST',
      body: JSON.stringify({ preset, project_id: projectId }),
    });
    return res.scan;
  },

  // Findings
  getFindings: async (params?: {
    project_id?: number;
    scan_id?: number;
    severity?: string;
    owasp_category?: string;
    cwe_id?: string;
    status?: string;
    search?: string;
    page?: number;
    per_page?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.project_id) searchParams.append('project_id', params.project_id.toString());
    if (params?.scan_id) searchParams.append('scan_id', params.scan_id.toString());
    if (params?.severity) searchParams.append('severity', params.severity);
    if (params?.owasp_category) searchParams.append('owasp_category', params.owasp_category);
    if (params?.cwe_id) searchParams.append('cwe_id', params.cwe_id);
    if (params?.status) searchParams.append('status', params.status);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.per_page) searchParams.append('per_page', params.per_page.toString());

    return request<{
      findings: Finding[];
      total: number;
      page: number;
      per_page: number;
    }>(`/findings?${searchParams.toString()}`);
  },

  getFinding: async (findingId: number) => {
    const res = await request<{ finding: Finding }>(`/findings/${findingId}`);
    return res.finding;
  },

  updateFindingStatus: async (findingId: number, status: FindingStatus) => {
    const res = await request<{ finding: Finding }>(`/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    return res.finding;
  },

  // Releases
  getReleases: async (projectId?: number) => {
    const query = projectId ? `?project_id=${projectId}` : '';
    const res = await request<{ releases: Release[] }>(`/releases${query}`);
    return res.releases;
  },

  // Reports
  getReport: async (scanId: number) => {
    const res = await request<{ report: SecurityReport }>(`/reports/${scanId}`);
    return res.report;
  },

  getReportHtmlUrl: (scanId: number) => {
    return `${API_BASE}/reports/${scanId}/html`;
  },

  // Settings
  getSettings: async () => {
    const res = await request<{ settings: AppSettings }>('/settings');
    return res.settings;
  },

  updateSettings: async (settings: Partial<AppSettings>) => {
    const res = await request<{ settings: AppSettings }>('/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
    return res.settings;
  },

  // AI Security Analyst
  explainFinding: async (findingId: number) => {
    const res = await request<{ result: AIAnalysisResult }>('/ai/explain', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId }),
    });
    return res.result;
  },
};
