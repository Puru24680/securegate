export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type ReleaseStatus = 'PASS' | 'REVIEW' | 'BLOCK' | 'PENDING';
export type FindingStatus =
  | 'open'
  | 'confirmed'
  | 'in_progress'
  | 'resolved'
  | 'accepted'
  | 'false_positive'
  | 'reopened'
  | 'reviewed'
  | 'fixed';

export interface User {
  id: number;
  email: string;
  full_name: string;
  is_active?: boolean;
  role?: string;
}

export interface Organization {
  id: number;
  name: string;
  slug: string;
  created_at: string;
  project_count: number;
  member_count: number;
  members?: Array<{
    id: number;
    user_id: number;
    role: string;
    user: User;
  }>;
}

export interface Project {
  id: number;
  organization_id?: number;
  name: string;
  description: string;
  target_url: string;
  environment?: string;
  repository_url?: string;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
  scan_count: number;
  asset_count?: number;
  latest_scan?: Scan;
}

export interface Asset {
  id: number;
  organization_id: number;
  project_id: number;
  asset_type: 'domain' | 'url' | 'endpoint' | 'api_endpoint' | 'technology';
  name: string;
  url: string;
  http_method: string;
  parameters?: string;
  technology?: string;
  criticality: 'Critical' | 'High' | 'Medium' | 'Low';
  status: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  finding_count?: number;
  findings?: Finding[];
}

export interface ScanJob {
  id: number;
  job_identifier: string;
  organization_id: number;
  project_id: number;
  target_url: string;
  scan_type: string;
  status: 'QUEUED' | 'INITIALIZING' | 'RUNNING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'TIMEOUT';
  progress: number;
  stage_message: string;
  logs: string[];
  error_message?: string;
  triggered_by?: string;
  scan_id?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  scan?: Scan;
}

export interface FindingOccurrence {
  id: number;
  finding_id: number;
  scan_id: number;
  url: string;
  method: string;
  parameter?: string;
  evidence?: string;
  attack_payload?: string;
  created_at: string;
}

export interface RiskAcceptance {
  id: number;
  finding_id: number;
  organization_id: number;
  user_id: number;
  justification: string;
  approved_by: string;
  expires_at: string;
  status: string;
  created_at: string;
}

export interface FalsePositive {
  id: number;
  finding_id: number;
  organization_id: number;
  user_id: number;
  reason: string;
  created_at: string;
}

export interface AuditLog {
  id: number;
  organization_id: number;
  user_id?: number;
  user_email: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details: any;
  ip_address: string;
  created_at: string;
}

export interface SecurityPolicy {
  id: number;
  organization_id: number;
  project_id?: number;
  name: string;
  block_critical: boolean;
  block_high: boolean;
  block_medium: boolean;
  min_cvss_block: number;
  max_critical_allowed: number;
  max_high_allowed: number;
  require_production_authorization: boolean;
  created_at: string;
  updated_at?: string;
}

export interface Scan {
  id: number;
  organization_id?: number;
  project_id: number;
  scan_identifier: string;
  target_url: string;
  started_at: string;
  completed_at: string;
  duration: number;
  security_score: number;
  release_status: ReleaseStatus;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count: number;
  scanner: string;
  created_at: string;
  findings?: Finding[];
}

export interface Finding {
  id: number;
  fingerprint?: string;
  organization_id?: number;
  project_id?: number;
  scan_id: number;
  asset_id?: number;
  name: string;
  description: string;
  severity: Severity;
  confidence: string;
  cvss_score?: number;
  risk_score: number;
  cwe_id: string;
  owasp_category: string;
  owasp_year: string;
  url: string;
  endpoint?: string;
  method: string;
  parameter: string;
  evidence: string;
  solution: string;
  reference: string;
  plugin_id: string;
  alert_ref: string;
  status: FindingStatus;
  first_seen?: string;
  last_seen?: string;
  resolved_at?: string;
  created_at: string;
  risk_acceptance?: RiskAcceptance;
  false_positive?: FalsePositive;
  occurrence_count?: number;
}

export interface Release {
  id: number;
  organization_id?: number;
  project_id: number;
  scan_id?: number;
  version: string;
  status: ReleaseStatus;
  reason: string;
  blocking_findings: number;
  review_findings: number;
  created_at: string;
  scan_identifier?: string;
  security_score?: number;
  project_name?: string;
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

export interface ReleasePolicy {
  critical: string;
  high: string;
  medium: string;
  low: string;
  informational: string;
}

export interface AppSettings {
  id: number;
  release_policy: ReleasePolicy;
  ai_analysis_enabled: boolean;
  ai_api_key_configured: boolean;
  environment: string;
  ci_cd_provider: string;
  scanner: string;
  supported_environments: string[];
  supported_ci_cd: string[];
}

export interface DashboardData {
  empty: boolean;
  active_scan_id?: number;
  project?: Project;
  latest_scan?: Scan;
  security_score: number;
  release_gate: {
    status: ReleaseStatus;
    reason: string;
    version: string;
    blocking_findings: number;
    review_findings: number;
  };
  metrics: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    total_findings: number;
  };
  charts: {
    severity_distribution: Array<{ severity: Severity; count: number }>;
    risk_over_time: Array<{
      scan_id: number;
      scan_identifier: string;
      date: string;
      security_score: number;
      release_status: ReleaseStatus;
      total_findings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    }>;
    owasp_coverage: Array<{ category: string; fullName: string; count: number }>;
  };
  recent_scans: Scan[];
  recent_releases: Release[];
  release_policy: ReleasePolicy;
}

export interface SecurityReport {
  title: string;
  generated_at: string;
  scan_id: number;
  scan_identifier: string;
  application_name: string;
  target_url: string;
  scanner: string;
  security_score: number;
  release_status: ReleaseStatus;
  executive_summary: string;
  release_policy_applied: ReleasePolicy;
  metrics: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  severity_distribution: Record<string, number>;
  owasp_coverage: Record<string, number>;
  cwe_coverage: Record<string, number>;
  findings_by_severity: Record<string, Finding[]>;
  strategic_recommendations: Array<{
    priority: string;
    focus: string;
    details: string;
  }>;
}

export interface AIAnalysisResult {
  available: boolean;
  provider: string;
  model?: string;
  message?: string;
  analysis: {
    plain_english_explanation: string;
    business_impact: string;
    technical_impact: string;
    recommended_remediation: string;
    developer_action_items: string[];
  };
}
