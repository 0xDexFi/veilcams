import { heartbeat } from '@temporalio/activity';
import type {
  DiscoveryResult,
  FingerprintResult,
  CredentialModuleResult,
  CveModuleResult,
  ProtocolModuleResult,
  ExploitationModuleResult,
} from '../types/index.js';
import type {
  DiscoveryActivityInput,
  FingerprintActivityInput,
  TestingActivityInput,
  ExploitationActivityInput,
  ReportActivityInput,
} from './shared.js';
import { parseConfig, getDefaultConfig } from '../config-parser.js';
import { AuditSession } from '../audit/index.js';
import { runDiscovery } from '../modules/discovery.js';
import { runFingerprinting } from '../modules/fingerprint.js';
import { runCredentialTester } from '../modules/credential-tester.js';
import { runCveScanner } from '../modules/cve-scanner.js';
import { runProtocolFuzzer } from '../modules/protocol-fuzzer.js';
import { runExploitation } from '../modules/exploitation.js';
import { generateReport } from '../report-generator.js';

// ─── Heartbeat Helper ───────────────────────────────────────────

function startHeartbeat(moduleName: string): NodeJS.Timeout {
  const startTime = Date.now();
  return setInterval(() => {
    heartbeat({
      module: moduleName,
      elapsedSeconds: Math.floor((Date.now() - startTime) / 1000),
    });
  }, 2000);
}

// ─── Discovery Activity ─────────────────────────────────────────

export async function runDiscoveryActivity(
  input: DiscoveryActivityInput
): Promise<DiscoveryResult> {
  const hb = startHeartbeat('discovery');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('discovery', 1);
    console.log(`[discovery] Scanning ${input.targets.length} target(s)...`);

    const result = await runDiscovery(input.targets, input.outputPath);

    console.log(`[discovery] Found ${result.hosts.length} hosts in ${result.scanDurationMs}ms`);
    await audit.endModule('discovery', true);
    return result;
  } catch (error) {
    await audit.endModule('discovery', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── Fingerprint Activity ───────────────────────────────────────

export async function runFingerprintActivity(
  input: FingerprintActivityInput
): Promise<FingerprintResult[]> {
  const hb = startHeartbeat('fingerprint');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('fingerprint', 1);
    console.log(`[fingerprint] Profiling ${input.discoveryResult.hosts.length} hosts...`);

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const concurrency = config.rate_limiting?.max_concurrent_hosts ?? 10;
    const results = await runFingerprinting(input.discoveryResult.hosts, input.outputPath, concurrency);

    const vendorCounts = results.reduce((acc, r) => {
      acc[r.vendor] = (acc[r.vendor] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    console.log(`[fingerprint] Identified ${results.length} cameras:`, vendorCounts);
    await audit.endModule('fingerprint', true);
    return results;
  } catch (error) {
    await audit.endModule('fingerprint', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── Credential Tester Activity ─────────────────────────────────

export async function runCredentialTesterActivity(
  input: TestingActivityInput
): Promise<CredentialModuleResult> {
  const hb = startHeartbeat('credential-tester');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('credential-tester', 1);
    console.log(`[credential-tester] Testing ${input.fingerprints.length} hosts...`);

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const result = await runCredentialTester(input.fingerprints, config, input.outputPath);

    console.log(`[credential-tester] ${result.successfulLogins}/${result.totalAttempts} successful (${result.hostsCompromised} hosts compromised)`);
    await audit.endModule('credential-tester', true);
    return result;
  } catch (error) {
    await audit.endModule('credential-tester', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── CVE Scanner Activity ───────────────────────────────────────

export async function runCveScannerActivity(
  input: TestingActivityInput
): Promise<CveModuleResult> {
  const hb = startHeartbeat('cve-scanner');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('cve-scanner', 1);
    console.log(`[cve-scanner] Scanning ${input.fingerprints.length} hosts for known CVEs...`);

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const result = await runCveScanner(input.fingerprints, config, input.outputPath);

    console.log(`[cve-scanner] ${result.vulnerabilitiesFound}/${result.totalChecks} vulnerabilities confirmed (${result.criticalCount} critical, ${result.highCount} high)`);
    await audit.endModule('cve-scanner', true);
    return result;
  } catch (error) {
    await audit.endModule('cve-scanner', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── Protocol Fuzzer Activity ───────────────────────────────────

export async function runProtocolFuzzerActivity(
  input: TestingActivityInput
): Promise<ProtocolModuleResult> {
  const hb = startHeartbeat('protocol-fuzzer');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('protocol-fuzzer', 1);
    console.log(`[protocol-fuzzer] Fuzzing ${input.fingerprints.length} hosts...`);

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const result = await runProtocolFuzzer(input.fingerprints, config, input.outputPath);

    console.log(`[protocol-fuzzer] ${result.findingsCount} findings across ${result.pathsTested} paths tested`);
    await audit.endModule('protocol-fuzzer', true);
    return result;
  } catch (error) {
    await audit.endModule('protocol-fuzzer', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── Exploitation Activity ──────────────────────────────────────

export async function runExploitationActivity(
  input: ExploitationActivityInput
): Promise<ExploitationModuleResult> {
  const hb = startHeartbeat('exploitation');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('exploitation', 1);
    const confirmedCount = input.cveResult.results.filter((r) => r.vulnerable).length;
    console.log(`[exploitation] Auto-exploiting ${confirmedCount} confirmed CVEs...`);

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const result = await runExploitation(input.fingerprints, input.cveResult, config, input.outputPath);

    console.log(`[exploitation] ${result.successfulExploits}/${result.totalAttempts} exploits successful`);
    await audit.endModule('exploitation', true);
    return result;
  } catch (error) {
    await audit.endModule('exploitation', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}

// ─── Report Activity ────────────────────────────────────────────

export async function runReportActivity(
  input: ReportActivityInput
): Promise<string> {
  const hb = startHeartbeat('report');
  const audit = new AuditSession({ sessionId: input.sessionId, outputDir: input.outputPath });
  await audit.initialize();

  try {
    await audit.startModule('report', 1);
    console.log('[report] Generating security assessment report...');

    const config = input.configPath
      ? await parseConfig(input.configPath)
      : getDefaultConfig();

    const report = await generateReport(
      {
        discovery: input.discoveryResult,
        fingerprints: input.fingerprints,
        credentials: input.credentialResult,
        cve: input.cveResult,
        protocol: input.protocolResult,
        exploitation: input.exploitationResult,
        config,
        sessionId: input.sessionId,
        startTime: input.startTime,
        totalDurationMs: input.totalDurationMs,
      },
      input.outputPath
    );

    console.log('[report] Report generated successfully');
    await audit.endModule('report', true);

    // Finalize audit session (after all modules are done)
    await audit.finalize({
      hostsScanned: input.discoveryResult.hosts.length,
      hostsIdentified: input.fingerprints.length,
      credentialsFound: input.credentialResult.successfulLogins,
      vulnerabilitiesFound: input.cveResult.vulnerabilitiesFound,
      protocolFindings: input.protocolResult.findingsCount,
      exploitsSuccessful: input.exploitationResult?.successfulExploits ?? 0,
    });
    return report;
  } catch (error) {
    await audit.endModule('report', false, (error as Error).message);
    throw error;
  } finally {
    clearInterval(hb);
  }
}
