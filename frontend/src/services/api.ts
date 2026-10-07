import {
  Project,
  Scan,
  Finding,
  FindingStatus,
  Release,
  AppSettings,
  DashboardData,
  SecurityReport,
  AIAnalysisResult,
  Asset,
  ScanJob,
  AuditLog,
  SecurityPolicy,
  Organization,
  User,
  FindingOccurrence,
  RiskAcceptance,
  FalsePositive,
} from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

export function getAuthToken(): string | null {
  return localStorage.getItem('securegate_token');
}

export function setAuthToken(token: string | null): void {
  if (token) {
    localStorage.setItem('securegate_token', token);
  } else {
    localStorage.removeItem('securegate_token');
  }
}

export function getActiveOrgId(): number | null {
  const val = localStorage.getItem('securegate_org_id');
  return val ? parseInt(val, 10) : null;
}

export function setActiveOrgId(orgId: number | null): void {
  if (orgId) {
    localStorage.setItem('securegate_org_id', orgId.toString());
  } else {
    localStorage.removeItem('securegate_org_id');
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const token = getAuthToken();
  const orgId = getActiveOrgId();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (orgId) {
    headers['X-Organization-ID'] = orgId.toString();
  }

  const response = await fetch(url, {
    headers,
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

  // Authentication
  login: async (email: string, password: string) => {
    const res = await request<{ status: string; access_token: string; user: User }>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setAuthToken(res.access_token);
    return res;
  },

  register: async (email: string, password: string, fullName: string) => {
    const res = await request<{ status: string; access_token: string; user: User }>('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    setAuthToken(res.access_token);
    return res;
  },

  getMe: async () => {
    return request<{ status: string; user: User }>('/v1/auth/me');
  },

  logout: () => {
    setAuthToken(null);
  },

  // Organizations
  getOrganizations: async () => {
    const res = await request<{ organizations: Organization[] }>('/v1/organizations');
    return res.organizations;
  },

  createOrganization: async (name: string) => {
    const res = await request<{ organization: Organization }>('/v1/organizations', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
    return res.organization;
  },

  // Projects
  getProjects: async () => {
    const res = await request<{ projects: Project[] }>('/projects');
    return res.projects;
  },

  createProject: async (data: {
    name: string;
    target_url: string;
    description?: string;
    environment?: string;
    repository_url?: string;
  }) => {
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
    formData.append('project_id', (projectId || 1).toString());
    if (targetUrl) formData.append('target_url', targetUrl);

    const token = getAuthToken();
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const response = await fetch(`${API_BASE}/scans/upload`, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      let errorMsg = `File upload failed (HTTP ${response.status})`;
      try {
        const err = await response.json();
        if (err.message) errorMsg = err.message;
      } catch {
        try {
          const txt = await response.text();
          if (txt.includes('FUNCTION_PAYLOAD_TOO_LARGE') || response.status === 413) {
            errorMsg = 'Scan file exceeds server upload size limit (max 4.5MB).';
          } else if (txt) {
            errorMsg = txt.slice(0, 120);
          }
        } catch {}
      }
      throw new Error(errorMsg);
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

  // Findings & Lifecycle Governance
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

  acceptRisk: async (
    findingId: number,
    data: { justification: string; approved_by?: string; days_valid?: number }
  ) => {
    const res = await request<{ finding: Finding; risk_acceptance: RiskAcceptance }>(
      `/v1/findings/${findingId}/accept-risk`,
      {
        method: 'POST',
        body: JSON.stringify(data),
      }
    );
    return res;
  },

  markFalsePositive: async (findingId: number, data: { reason: string }) => {
    const res = await request<{ finding: Finding; false_positive: FalsePositive }>(
      `/v1/findings/${findingId}/false-positive`,
      {
        method: 'POST',
        body: JSON.stringify(data),
      }
    );
    return res;
  },

  getFindingOccurrences: async (findingId: number) => {
    return request<{ occurrences: FindingOccurrence[] }>(`/v1/findings/${findingId}/occurrences`);
  },

  // Asset Inventory & Attack Surface
  getAssets: async (params?: {
    project_id?: number;
    asset_type?: string;
    criticality?: string;
    search?: string;
    page?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.project_id) searchParams.append('project_id', params.project_id.toString());
    if (params?.asset_type) searchParams.append('asset_type', params.asset_type);
    if (params?.criticality) searchParams.append('criticality', params.criticality);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.page) searchParams.append('page', params.page.toString());

    return request<{
      assets: Asset[];
      total: number;
      page: number;
    }>(`/v1/assets?${searchParams.toString()}`);
  },

  createAsset: async (data: {
    project_id: number;
    name: string;
    url?: string;
    http_method?: string;
    asset_type?: string;
    criticality?: string;
    technology?: string;
    parameters?: string;
  }) => {
    const res = await request<{ asset: Asset }>('/v1/assets', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return res.asset;
  },

  // Scan Jobs & Orchestration
  getScanJobs: async (params?: { project_id?: number; status?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.project_id) searchParams.append('project_id', params.project_id.toString());
    if (params?.status) searchParams.append('status', params.status);

    const res = await request<{ jobs: ScanJob[] }>(`/v1/scan-jobs?${searchParams.toString()}`);
    return res.jobs;
  },

  triggerScanJob: async (data: {
    target_url: string;
    project_id?: number;
    scan_type?: string;
    production_authorized?: boolean;
  }) => {
    const res = await request<{ job: ScanJob; message: string }>('/v1/scan-jobs', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return res;
  },

  getScanJob: async (jobIdentifier: string) => {
    const res = await request<{ job: ScanJob }>(`/v1/scan-jobs/${jobIdentifier}`);
    return res.job;
  },

  cancelScanJob: async (jobIdentifier: string) => {
    return request<{ message: string }>(`/v1/scan-jobs/${jobIdentifier}/cancel`, {
      method: 'POST',
    });
  },

  // Security Policies & Gate Rules
  getSecurityPolicies: async (projectId?: number) => {
    const query = projectId ? `?project_id=${projectId}` : '';
    const res = await request<{ policies: SecurityPolicy[] }>(`/v1/policies${query}`);
    return res.policies;
  },

  createSecurityPolicy: async (data: Partial<SecurityPolicy>) => {
    const res = await request<{ policy: SecurityPolicy }>('/v1/policies', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return res.policy;
  },

  updateSecurityPolicy: async (policyId: number, data: Partial<SecurityPolicy>) => {
    const res = await request<{ policy: SecurityPolicy }>(`/v1/policies/${policyId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
    return res.policy;
  },

  // Audit Logs
  getAuditLogs: async (params?: { action?: string; resource_type?: string; page?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.action) searchParams.append('action', params.action);
    if (params?.resource_type) searchParams.append('resource_type', params.resource_type);
    if (params?.page) searchParams.append('page', params.page.toString());

    return request<{
      audit_logs: AuditLog[];
      total: number;
      page: number;
    }>(`/v1/audit-logs?${searchParams.toString()}`);
  },

  // Releases
  getReleases: async (projectId?: number) => {
    const query = projectId ? `?project_id=${projectId}` : '';
    const res = await request<{ releases: Release[] }>(`/releases${query}`);
    return res.releases;
  },

  // Reports
  getReport: async (scanId: number) => {
    return request<SecurityReport>(`/reports/${scanId}`);
  },

  exportReport: async (scanId: number, format: 'json' | 'html' | 'markdown' | 'sarif') => {
    const token = getAuthToken();
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/reports/${scanId}/export?format=${format}`, {
      headers,
    });
    if (!res.ok) throw new Error('Failed to export report');
    return res.blob();
  },

  // Settings
  getSettings: async () => {
    return request<AppSettings>('/settings');
  },

  updateSettings: async (settings: Partial<AppSettings>) => {
    return request<AppSettings>('/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  // AI Security Copilot
  explainFinding: async (findingId: number) => {
    return request<AIAnalysisResult>(`/ai/explain/${findingId}`, {
      method: 'POST',
    });
  },

  // ZAP API Daemon
  getZapHealth: async (zapUrl?: string, apiKey?: string) => {
    const params = new URLSearchParams();
    if (zapUrl) params.append('zap_url', zapUrl);
    if (apiKey) params.append('api_key', apiKey);
    const query = params.toString() ? `?${params.toString()}` : '';
    return request<{
      daemon: {
        connected: boolean;
        version: string | null;
        url: string;
        latency_ms: number | null;
        error: string | null;
      };
    }>(`/zap/health${query}`);
  },

  startZapScan: async (payload: {
    target_url: string;
    project_id?: number;
    scan_type?: 'full' | 'spider' | 'active';
    zap_url?: string;
    api_key?: string;
    simulate?: boolean;
  }) => {
    return request<{
      task_id: string;
      target_url: string;
    }>('/zap/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getReportHtmlUrl: (scanId: number) => {
    return `${API_BASE}/reports/${scanId}/export?format=html`;
  },

  getZapTaskStatus: async (taskId: string) => {
    return request<{
      task: {
        id: string;
        target_url: string;
        stage: string;
        progress: number;
        status: string;
        logs: string[];
        scan_id: number | null;
        error: string | null;
        scan?: Scan;
      };
    }>(`/zap/tasks/${taskId}`);
  },

  getZapQuickstart: async () => {
    return request<{
      docker_command: string;
      cli_command: string;
      default_url: string;
      documentation: string;
    }>('/zap/quickstart');
  },
};
