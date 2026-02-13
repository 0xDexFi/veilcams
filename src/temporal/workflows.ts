import {
  proxyActivities,
  defineQuery,
  setHandler,
  ApplicationFailure,
} from '@temporalio/workflow';

import type {
  DiscoveryResult,
  FingerprintResult,
  CredentialModuleResult,
  CveModuleResult,
  ProtocolModuleResult,
  ExploitationModuleResult,
} from '../types/index.js';

import {
  type PipelineInput,
  type WorkflowState,
  type WorkflowProgress,
  PROGRESS_QUERY_NAME,
} from './shared.js';

const getProgressQuery = defineQuery<WorkflowProgress>(PROGRESS_QUERY_NAME);

import type * as activityTypes from './activities.js';

// ─── Activity Proxies ───────────────────────────────────────────

const {
  runDiscoveryActivity,
  runFingerprintActivity,
  runCredentialTesterActivity,
  runCveScannerActivity,
  runProtocolFuzzerActivity,
  runExploitationActivity,
  runReportActivity,
} = proxyActivities<typeof activityTypes>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '60 seconds',
  retry: {
    initialInterval: '5 minutes',
    backoffCoefficient: 2,
    maximumInterval: '30 minutes',
    maximumAttempts: 10,
    nonRetryableErrorTypes: [
      'ConfigurationError',
      'PermissionError',
      'InvalidTargetError',
    ],
  },
});

// ─── Pipeline Workflow ──────────────────────────────────────────

export async function veilcamsPipelineWorkflow(input: PipelineInput): Promise<void> {
  const sessionId = `veilcams-${Date.now()}`;
  const startTime = new Date().toISOString();

  // Initialize workflow state
  const state: WorkflowState = {
    currentPhase: 'discovery',
    currentModule: null,
    completedModules: [],
    failedModules: [],
    moduleStatuses: {},
    startTime,
  };

  // Register progress query
  setHandler(getProgressQuery, (): WorkflowProgress => ({
    currentPhase: state.currentPhase,
    currentModule: state.currentModule,
    completedModules: [...state.completedModules],
    failedModules: [...state.failedModules],
    startTime: state.startTime,
    elapsedMs: Date.now() - new Date(state.startTime).getTime(),
  }));

  const baseInput = {
    sessionId,
    outputPath: input.outputPath,
    configPath: input.configPath,
    pipelineTestingMode: input.pipelineTestingMode,
  };

  // ── Phase 1: Discovery (Sequential) ──────────────────────────

  state.currentPhase = 'discovery';
  state.currentModule = 'discovery';
  state.moduleStatuses['discovery'] = 'running';

  let discoveryResult: DiscoveryResult;
  try {
    discoveryResult = await runDiscoveryActivity({
      ...baseInput,
      targets: input.targets,
    });
    state.completedModules.push('discovery');
    state.moduleStatuses['discovery'] = 'completed';
  } catch (error) {
    state.failedModules.push('discovery');
    state.moduleStatuses['discovery'] = 'failed';
    throw ApplicationFailure.nonRetryable(
      `Discovery phase failed: ${(error as Error).message}`,
      'DiscoveryError'
    );
  }

  if (discoveryResult.hosts.length === 0) {
    state.currentPhase = 'reporting';
    state.currentModule = 'report';
    // No hosts found — generate empty report and exit
    await runReportActivity({
      ...baseInput,
      discoveryResult,
      fingerprints: [],
      credentialResult: { results: [], totalAttempts: 0, successfulLogins: 0, hostsCompromised: 0, durationMs: 0 },
      cveResult: { results: [], totalChecks: 0, vulnerabilitiesFound: 0, criticalCount: 0, highCount: 0, durationMs: 0 },
      protocolResult: { findings: [], pathsTested: 0, findingsCount: 0, durationMs: 0 },
      startTime,
      totalDurationMs: Date.now() - new Date(startTime).getTime(),
    });
    return;
  }

  // ── Phase 2: Fingerprinting (Sequential) ─────────────────────

  state.currentPhase = 'fingerprinting';
  state.currentModule = 'fingerprint';
  state.moduleStatuses['fingerprint'] = 'running';

  let fingerprints: FingerprintResult[];
  try {
    fingerprints = await runFingerprintActivity({
      ...baseInput,
      discoveryResult,
    });
    state.completedModules.push('fingerprint');
    state.moduleStatuses['fingerprint'] = 'completed';
  } catch (error) {
    state.failedModules.push('fingerprint');
    state.moduleStatuses['fingerprint'] = 'failed';
    throw ApplicationFailure.nonRetryable(
      `Fingerprinting phase failed: ${(error as Error).message}`,
      'FingerprintError'
    );
  }

  // ── Phase 3: Testing (3 modules in parallel) ─────────────────

  state.currentPhase = 'testing';
  state.currentModule = null;

  const testingInput = { ...baseInput, fingerprints };

  state.moduleStatuses['credential-tester'] = 'running';
  state.moduleStatuses['cve-scanner'] = 'running';
  state.moduleStatuses['protocol-fuzzer'] = 'running';

  const [credentialSettled, cveSettled, protocolSettled] = await Promise.allSettled([
    runCredentialTesterActivity(testingInput),
    runCveScannerActivity(testingInput),
    runProtocolFuzzerActivity(testingInput),
  ]);

  // Process credential results
  let credentialResult: CredentialModuleResult;
  if (credentialSettled.status === 'fulfilled') {
    credentialResult = credentialSettled.value;
    state.completedModules.push('credential-tester');
    state.moduleStatuses['credential-tester'] = 'completed';
  } else {
    credentialResult = { results: [], totalAttempts: 0, successfulLogins: 0, hostsCompromised: 0, durationMs: 0 };
    state.failedModules.push('credential-tester');
    state.moduleStatuses['credential-tester'] = 'failed';
  }

  // Process CVE results
  let cveResult: CveModuleResult;
  if (cveSettled.status === 'fulfilled') {
    cveResult = cveSettled.value;
    state.completedModules.push('cve-scanner');
    state.moduleStatuses['cve-scanner'] = 'completed';
  } else {
    cveResult = { results: [], totalChecks: 0, vulnerabilitiesFound: 0, criticalCount: 0, highCount: 0, durationMs: 0 };
    state.failedModules.push('cve-scanner');
    state.moduleStatuses['cve-scanner'] = 'failed';
  }

  // Process protocol results
  let protocolResult: ProtocolModuleResult;
  if (protocolSettled.status === 'fulfilled') {
    protocolResult = protocolSettled.value;
    state.completedModules.push('protocol-fuzzer');
    state.moduleStatuses['protocol-fuzzer'] = 'completed';
  } else {
    protocolResult = { findings: [], pathsTested: 0, findingsCount: 0, durationMs: 0 };
    state.failedModules.push('protocol-fuzzer');
    state.moduleStatuses['protocol-fuzzer'] = 'failed';
  }

  // ── Phase 3.5: Exploitation (Sequential, after CVE results) ──

  let exploitationResult: ExploitationModuleResult | undefined;

  if (cveResult.vulnerabilitiesFound > 0) {
    state.currentPhase = 'exploitation';
    state.currentModule = 'exploitation';
    state.moduleStatuses['exploitation'] = 'running';

    try {
      exploitationResult = await runExploitationActivity({
        ...baseInput,
        fingerprints,
        cveResult,
      });
      state.completedModules.push('exploitation');
      state.moduleStatuses['exploitation'] = 'completed';
    } catch {
      exploitationResult = {
        results: [],
        totalAttempts: 0,
        successfulExploits: 0,
        failedExploits: 0,
        skippedNoModule: 0,
        durationMs: 0,
      };
      state.failedModules.push('exploitation');
      state.moduleStatuses['exploitation'] = 'failed';
    }
  } else {
    state.moduleStatuses['exploitation'] = 'skipped';
  }

  // ── Phase 4: Reporting (Sequential) ──────────────────────────

  state.currentPhase = 'reporting';
  state.currentModule = 'report';
  state.moduleStatuses['report'] = 'running';

  try {
    await runReportActivity({
      ...baseInput,
      discoveryResult,
      fingerprints,
      credentialResult,
      cveResult,
      protocolResult,
      exploitationResult,
      startTime,
      totalDurationMs: Date.now() - new Date(startTime).getTime(),
    });
    state.completedModules.push('report');
    state.moduleStatuses['report'] = 'completed';
  } catch (error) {
    state.failedModules.push('report');
    state.moduleStatuses['report'] = 'failed';
    throw ApplicationFailure.nonRetryable(
      `Report generation failed: ${(error as Error).message}`,
      'ReportError'
    );
  }
}
