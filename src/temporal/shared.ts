import type {
  TargetSpec,
  DiscoveryResult,
  FingerprintResult,
  CredentialModuleResult,
  CveModuleResult,
  ProtocolModuleResult,
  ModuleName,
  PhaseName,
  ModuleStatus,
} from '../types/index.js';

// ─── Workflow Input ─────────────────────────────────────────────

export interface PipelineInput {
  targets: TargetSpec[];
  configPath?: string;
  outputPath: string;
  pipelineTestingMode: boolean;
}

// ─── Activity Input/Output ──────────────────────────────────────

export interface ActivityInput {
  sessionId: string;
  outputPath: string;
  configPath?: string;
  pipelineTestingMode: boolean;
}

export interface DiscoveryActivityInput extends ActivityInput {
  targets: TargetSpec[];
}

export interface FingerprintActivityInput extends ActivityInput {
  discoveryResult: DiscoveryResult;
}

export interface TestingActivityInput extends ActivityInput {
  fingerprints: FingerprintResult[];
}

export interface ReportActivityInput extends ActivityInput {
  discoveryResult: DiscoveryResult;
  fingerprints: FingerprintResult[];
  credentialResult: CredentialModuleResult;
  cveResult: CveModuleResult;
  protocolResult: ProtocolModuleResult;
  startTime: string;
  totalDurationMs: number;
}

// ─── Workflow State & Progress ──────────────────────────────────

export interface WorkflowState {
  currentPhase: PhaseName;
  currentModule: ModuleName | null;
  completedModules: ModuleName[];
  failedModules: ModuleName[];
  moduleStatuses: Record<string, ModuleStatus>;
  startTime: string;
}

export interface WorkflowProgress {
  currentPhase: PhaseName;
  currentModule: ModuleName | null;
  completedModules: ModuleName[];
  failedModules: ModuleName[];
  startTime: string;
  elapsedMs: number;
}

// ─── Query Definitions ──────────────────────────────────────────

export const PROGRESS_QUERY_NAME = 'getProgress';

// ─── Constants ──────────────────────────────────────────────────

export const TASK_QUEUE = 'veilcams-pipeline';
