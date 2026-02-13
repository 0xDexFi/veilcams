// ─── Target & Discovery ───────────────────────────────────────────

export interface TargetSpec {
  range?: string;
  host?: string;
  ports: number[];
}

export interface DiscoveredHost {
  ip: string;
  port: number;
  service: string;
  banner: string;
  state: 'open' | 'filtered';
}

export interface DiscoveryResult {
  hosts: DiscoveredHost[];
  scanDurationMs: number;
  targetsScanned: number;
}

// ─── Fingerprinting ──────────────────────────────────────────────

export type CameraVendor =
  | 'hikvision'
  | 'dahua'
  | 'axis'
  | 'reolink'
  | 'amcrest'
  | 'foscam'
  | 'tp-link'
  | 'uniview'
  | 'vivotek'
  | 'hanwha'
  | 'bosch'
  | 'unknown';

export interface FingerprintResult {
  ip: string;
  port: number;
  vendor: CameraVendor;
  model: string;
  firmware: string;
  protocols: ProtocolType[];
  serverHeader: string;
  authType: AuthType;
  webInterface: boolean;
  onvifSupported: boolean;
  rawHeaders: Record<string, string>;
}

export type ProtocolType = 'http' | 'https' | 'rtsp' | 'onvif' | 'telnet' | 'ssh';
export type AuthType = 'none' | 'basic' | 'digest' | 'form' | 'bearer' | 'unknown';

// ─── Credential Testing ─────────────────────────────────────────

export interface Credential {
  username: string;
  password: string;
}

export interface CredentialTestResult {
  ip: string;
  port: number;
  vendor: CameraVendor;
  protocol: ProtocolType;
  credential: Credential;
  success: boolean;
  responseCode?: number;
  evidence: string;
  timestamp: string;
}

export interface CredentialModuleResult {
  results: CredentialTestResult[];
  totalAttempts: number;
  successfulLogins: number;
  hostsCompromised: number;
  durationMs: number;
}

// ─── CVE Scanning ────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CveCheck {
  cveId: string;
  vendor: CameraVendor | 'generic';
  title: string;
  severity: Severity;
  description: string;
  affectedModels: string[];
  affectedFirmware: string[];
  check: (target: FingerprintResult) => Promise<CveTestResult>;
}

export interface CveTestResult {
  cveId: string;
  ip: string;
  port: number;
  vendor: CameraVendor;
  title: string;
  severity: Severity;
  vulnerable: boolean;
  evidence: string;
  poc: string;
  remediation: string;
  timestamp: string;
}

export interface CveModuleResult {
  results: CveTestResult[];
  totalChecks: number;
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  durationMs: number;
  aiResults?: AiCveResult[];
}

// ─── AI CVE Engine ──────────────────────────────────────────────

export interface AiExploitProbe {
  cveId: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS';
  path: string;
  headers: Record<string, string>;
  body?: string;
  expectedVulnerablePattern: string;
  expectedSafePattern: string;
  timeout: number;
}

export interface AiResponseAnalysis {
  cveId: string;
  vulnerable: boolean;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
  reasoning: string;
  poc: string;
  remediation: string;
  falsePositiveRisk: 'low' | 'medium' | 'high';
}

export interface AiCveResult {
  cveId: string;
  ip: string;
  port: number;
  vendor: CameraVendor;
  title: string;
  severity: Severity;
  cvssScore: number;
  vulnerable: boolean;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
  reasoning: string;
  poc: string;
  remediation: string;
  source: 'ai';
  timestamp: string;
}

// ─── Protocol Fuzzing ────────────────────────────────────────────

export type ProtocolFindingType =
  | 'rtsp_stream'
  | 'snapshot_endpoint'
  | 'config_disclosure'
  | 'directory_traversal'
  | 'unauthenticated_access'
  | 'info_disclosure';

export interface ProtocolFinding {
  ip: string;
  port: number;
  type: ProtocolFindingType;
  protocol: ProtocolType;
  path: string;
  severity: Severity;
  description: string;
  evidence: string;
  authenticated: boolean;
  timestamp: string;
}

export interface ProtocolModuleResult {
  findings: ProtocolFinding[];
  pathsTested: number;
  findingsCount: number;
  durationMs: number;
}

// ─── Configuration ───────────────────────────────────────────────

export interface VeilcamsConfig {
  targets: TargetSpec[];
  credentials: CredentialConfig;
  cve_testing: CveTestingConfig;
  protocols: ProtocolConfig;
  reporting: ReportingConfig;
  rate_limiting?: RateLimitConfig;
}

export interface CredentialConfig {
  use_defaults: boolean;
  custom: Credential[];
  max_attempts_per_host: number;
  delay_ms: number;
}

export interface CveTestingConfig {
  enabled: boolean;
  safe_mode: boolean;
  categories: CveCategory[];
  ai_enabled: boolean;
  ai_model: string;
  ai_max_cves_per_host: number;
}

export type CveCategory = 'auth_bypass' | 'info_disclosure' | 'command_injection' | 'buffer_overflow' | 'path_traversal';

export interface ProtocolConfig {
  rtsp: boolean;
  onvif: boolean;
  http: boolean;
  telnet: boolean;
  ssh: boolean;
}

export interface ReportingConfig {
  format: 'markdown' | 'json';
  include_poc: boolean;
  severity_threshold: Severity;
}

export interface RateLimitConfig {
  max_concurrent_hosts: number;
  requests_per_second: number;
  timeout_ms: number;
}

// ─── Audit & Metrics ─────────────────────────────────────────────

export type ModuleName = 'discovery' | 'fingerprint' | 'credential-tester' | 'cve-scanner' | 'protocol-fuzzer' | 'report';

export type PhaseName = 'discovery' | 'fingerprinting' | 'testing' | 'reporting';

export type ModuleStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

export interface ModuleMetrics {
  name: ModuleName;
  phase: PhaseName;
  status: ModuleStatus;
  startTime?: string;
  endTime?: string;
  durationMs?: number;
  attempt: number;
  error?: string;
}

export interface SessionMetrics {
  sessionId: string;
  startTime: string;
  endTime?: string;
  status: 'running' | 'completed' | 'failed';
  error?: string;
  totalDurationMs?: number;
  config: Partial<VeilcamsConfig>;
  modules: Record<ModuleName, ModuleMetrics>;
  summary?: {
    hostsScanned: number;
    hostsIdentified: number;
    credentialsFound: number;
    vulnerabilitiesFound: number;
    protocolFindings: number;
  };
}

export interface AuditEvent {
  timestamp: string;
  module: ModuleName;
  event: string;
  data: Record<string, unknown>;
}

// ─── Temporal ────────────────────────────────────────────────────

export interface WorkflowInput {
  targets: TargetSpec[];
  configPath?: string;
  outputPath: string;
  pipelineTestingMode: boolean;
}

export interface WorkflowProgress {
  currentPhase: PhaseName;
  currentModule: ModuleName | null;
  completedModules: ModuleName[];
  failedModules: ModuleName[];
  startTime: string;
  elapsedMs: number;
}

export interface ActivityInput {
  sessionId: string;
  outputPath: string;
  configPath?: string;
  pipelineTestingMode: boolean;
  discoveryResults?: DiscoveryResult;
  fingerprintResults?: FingerprintResult[];
}
