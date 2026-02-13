import { promises as fs } from 'node:fs';
import path from 'node:path';
import type {
  DiscoveryResult,
  FingerprintResult,
  CredentialModuleResult,
  CveModuleResult,
  ProtocolModuleResult,
  ExploitationModuleResult,
  Severity,
  VeilcamsConfig,
} from './types/index.js';

interface ReportData {
  discovery: DiscoveryResult;
  fingerprints: FingerprintResult[];
  credentials: CredentialModuleResult;
  cve: CveModuleResult;
  protocol: ProtocolModuleResult;
  exploitation?: ExploitationModuleResult;
  config: VeilcamsConfig;
  sessionId: string;
  startTime: string;
  totalDurationMs: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Phase 4: Report Generator
 * Compiles all module results into a structured Markdown report.
 */
export async function generateReport(
  data: ReportData,
  outputDir: string
): Promise<string> {
  const threshold = data.config.reporting.severity_threshold;
  const includePoc = data.config.reporting.include_poc;

  const lines: string[] = [];

  // ─── Header ───────────────────────────────────────────────
  lines.push('# VeilCams Security Assessment Report');
  lines.push('');
  lines.push(`**Session ID:** ${data.sessionId}`);
  lines.push(`**Date:** ${new Date(data.startTime).toUTCString()}`);
  lines.push(`**Duration:** ${formatDuration(data.totalDurationMs)}`);
  lines.push(`**Severity Threshold:** ${threshold}`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // ─── Executive Summary ────────────────────────────────────
  lines.push('## Executive Summary');
  lines.push('');

  const totalVulns =
    data.credentials.successfulLogins +
    data.cve.vulnerabilitiesFound +
    data.protocol.findings.filter((f) => !f.authenticated).length;

  const criticalCount =
    data.cve.criticalCount +
    data.credentials.successfulLogins +
    data.protocol.findings.filter((f) => f.severity === 'critical').length;

  const highCount =
    data.cve.highCount +
    data.protocol.findings.filter((f) => f.severity === 'high').length;

  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Hosts Scanned | ${data.discovery.hosts.length} |`);
  lines.push(`| Cameras Identified | ${data.fingerprints.length} |`);
  lines.push(`| Total Findings | ${totalVulns} |`);
  lines.push(`| Critical | ${criticalCount} |`);
  lines.push(`| High | ${highCount} |`);
  lines.push(`| Credentials Compromised | ${data.credentials.successfulLogins} |`);
  lines.push(`| CVEs Confirmed | ${data.cve.vulnerabilitiesFound} |`);
  lines.push(`| Exploits Successful | ${data.exploitation?.successfulExploits ?? 0} |`);
  lines.push(`| Protocol Issues | ${data.protocol.findingsCount} |`);
  lines.push('');

  if (criticalCount > 0) {
    lines.push('> **CRITICAL RISK**: This assessment found critical vulnerabilities requiring immediate remediation.');
  } else if (highCount > 0) {
    lines.push('> **HIGH RISK**: This assessment found high-severity vulnerabilities that should be addressed promptly.');
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  // ─── Discovery & Fingerprinting ───────────────────────────
  lines.push('## 1. Discovery & Fingerprinting');
  lines.push('');
  lines.push(`**${data.discovery.hosts.length}** hosts discovered with open camera-related ports across **${data.discovery.targetsScanned}** target(s).`);
  lines.push('');

  if (data.fingerprints.length > 0) {
    lines.push('| IP | Port | Vendor | Model | Firmware | Auth | Protocols |');
    lines.push('|----|------|--------|-------|----------|------|-----------|');
    for (const fp of data.fingerprints) {
      lines.push(
        `| ${fp.ip} | ${fp.port} | ${fp.vendor} | ${fp.model || '-'} | ${fp.firmware || '-'} | ${fp.authType} | ${fp.protocols.join(', ')} |`
      );
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  // ─── Credential Testing Results ───────────────────────────
  lines.push('## 2. Credential Testing');
  lines.push('');
  lines.push(`**${data.credentials.totalAttempts}** credential combinations tested against **${data.fingerprints.length}** hosts.`);
  lines.push('');

  const successfulCreds = data.credentials.results.filter((r) => r.success);
  if (successfulCreds.length > 0) {
    lines.push(`### Compromised Credentials (${successfulCreds.length})`);
    lines.push('');
    lines.push('| Severity | IP | Port | Vendor | Protocol | Username | Password | Evidence |');
    lines.push('|----------|----|------|--------|----------|----------|----------|----------|');
    // Credentials are always treated as critical severity
    const showCredentials = SEVERITY_ORDER['critical'] <= SEVERITY_ORDER[threshold];
    for (const cred of showCredentials ? successfulCreds : []) {
      lines.push(
        `| CRITICAL | ${cred.ip} | ${cred.port} | ${cred.vendor} | ${cred.protocol} | \`${cred.credential.username}\` | \`${cred.credential.password || '(empty)'}\` | ${cred.evidence} |`
      );
    }
    lines.push('');

    if (includePoc) {
      lines.push('#### Proof of Concept');
      lines.push('');
      for (const cred of successfulCreds) {
        if (cred.protocol === 'rtsp') {
          const rtspUrl = `rtsp://${cred.credential.username}:${cred.credential.password}@${cred.ip}:${cred.port}/`;
          lines.push(`\`\`\`bash`);
          lines.push(`# ${cred.ip}:${cred.port} (${cred.vendor})`);
          lines.push(`# VLC: ${rtspUrl}`);
          lines.push(`vlc "${rtspUrl}"`);
          lines.push(`# or: ffplay "${rtspUrl}"`);
          lines.push(`\`\`\``);
        } else {
          lines.push(`\`\`\`bash`);
          lines.push(`# ${cred.ip}:${cred.port} (${cred.vendor})`);
          lines.push(`curl -u "${cred.credential.username}:${cred.credential.password}" http://${cred.ip}:${cred.port}/`);
          lines.push(`\`\`\``);
        }
        lines.push('');
      }
    }
  } else {
    lines.push('No default or custom credentials were accepted by any tested host.');
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  // ─── CVE Results ──────────────────────────────────────────
  lines.push('## 3. CVE Vulnerability Scan');
  lines.push('');

  const hardcodedCount = data.cve.results.length - (data.cve.aiResults?.length || 0);
  const aiCount = data.cve.aiResults?.length || 0;
  lines.push(`**${data.cve.totalChecks}** CVE checks executed (**${hardcodedCount}** hardcoded + **${aiCount}** AI-powered). **${data.cve.vulnerabilitiesFound}** vulnerabilities confirmed.`);
  lines.push('');

  const vulnerableCves = data.cve.results
    .filter((r) => r.vulnerable)
    .filter((r) => SEVERITY_ORDER[r.severity] <= SEVERITY_ORDER[threshold])
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  // Hardcoded CVE findings
  if (vulnerableCves.length > 0) {
    for (const cve of vulnerableCves) {
      lines.push(`### ${cve.severity.toUpperCase()}: ${cve.cveId} — ${cve.title}`);
      lines.push('');
      lines.push(`- **Host:** ${cve.ip}:${cve.port} (${cve.vendor})`);
      lines.push(`- **Severity:** ${cve.severity.toUpperCase()}`);
      lines.push(`- **Evidence:** ${cve.evidence}`);
      lines.push(`- **Remediation:** ${cve.remediation}`);
      lines.push('');

      if (includePoc && cve.poc) {
        lines.push('**Proof of Concept:**');
        lines.push('```bash');
        lines.push(cve.poc);
        lines.push('```');
        lines.push('');
      }
    }
  }

  // AI CVE findings (separate section with confidence and reasoning)
  const vulnerableAi = (data.cve.aiResults || [])
    .filter((r) => r.vulnerable)
    .filter((r) => SEVERITY_ORDER[r.severity] <= SEVERITY_ORDER[threshold])
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  if (vulnerableAi.length > 0) {
    lines.push('### AI-Discovered Vulnerabilities');
    lines.push('');
    lines.push('> The following vulnerabilities were discovered by the AI CVE engine (Claude). Each includes a confidence rating and analysis reasoning.');
    lines.push('');

    for (const ai of vulnerableAi) {
      const confidenceBadge = ai.confidence === 'high' ? '**HIGH CONFIDENCE**'
        : ai.confidence === 'medium' ? '*MEDIUM CONFIDENCE*'
        : '_LOW CONFIDENCE_';

      lines.push(`#### ${ai.severity.toUpperCase()}: ${ai.cveId} (CVSS ${ai.cvssScore}) — ${confidenceBadge}`);
      lines.push('');
      lines.push(`- **Host:** ${ai.ip}:${ai.port} (${ai.vendor})`);
      lines.push(`- **Severity:** ${ai.severity.toUpperCase()} (CVSS ${ai.cvssScore})`);
      lines.push(`- **Confidence:** ${ai.confidence}`);
      lines.push(`- **Evidence:** ${ai.evidence}`);
      lines.push(`- **Reasoning:** ${ai.reasoning}`);
      lines.push(`- **Remediation:** ${ai.remediation}`);
      lines.push('');

      if (includePoc && ai.poc) {
        lines.push('**Proof of Concept:**');
        lines.push('```bash');
        lines.push(ai.poc);
        lines.push('```');
        lines.push('');
      }
    }
  }

  if (vulnerableCves.length === 0 && vulnerableAi.length === 0) {
    lines.push('No CVE vulnerabilities were confirmed on the tested devices.');
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  // ─── Exploitation Results ────────────────────────────────
  if (data.exploitation && data.exploitation.results.length > 0) {
    lines.push('## 4. Exploitation Results');
    lines.push('');
    lines.push(`**${data.exploitation.totalAttempts}** exploit(s) attempted. **${data.exploitation.successfulExploits}** successful, **${data.exploitation.failedExploits}** failed, **${data.exploitation.skippedNoModule}** skipped (no Metasploit module).`);
    lines.push('');

    const successfulExploits = data.exploitation.results.filter((r) => r.success);
    const failedExploits = data.exploitation.results.filter((r) => !r.success);

    if (successfulExploits.length > 0) {
      lines.push('### Successful Exploits');
      lines.push('');
      for (const exploit of successfulExploits) {
        lines.push(`#### ${exploit.cveId} — ${exploit.ip}:${exploit.port} (${exploit.vendor})`);
        lines.push('');
        lines.push(`- **Metasploit Module:** \`${exploit.msfModule}\``);
        lines.push(`- **Module Type:** ${exploit.msfModuleType}`);
        lines.push(`- **Session Created:** ${exploit.sessionCreated ? `Yes (${exploit.sessionType})` : 'No (auxiliary success)'}`);
        lines.push(`- **Duration:** ${formatDuration(exploit.durationMs)}`);
        if (exploit.screenshotPath) {
          lines.push(`- **Screenshot Evidence:** \`${exploit.screenshotPath}\``);
        }
        lines.push('');
        lines.push('**Metasploit Output:**');
        lines.push('```');
        lines.push(exploit.output.trim());
        lines.push('```');
        lines.push('');
      }
    }

    if (failedExploits.length > 0) {
      lines.push('### Failed Exploits');
      lines.push('');
      lines.push('| CVE | Host | Module | Reason |');
      lines.push('|-----|------|--------|--------|');
      for (const exploit of failedExploits) {
        const reason = exploit.error || 'No session created / module did not confirm exploitation';
        lines.push(`| ${exploit.cveId} | ${exploit.ip}:${exploit.port} | \`${exploit.msfModule}\` | ${reason} |`);
      }
      lines.push('');
    }

    lines.push('---');
    lines.push('');
  }

  // ─── Protocol Fuzzing Results ─────────────────────────────
  lines.push('## 5. Protocol & Endpoint Analysis');
  lines.push('');
  lines.push(`**${data.protocol.pathsTested}** paths tested. **${data.protocol.findingsCount}** findings.`);
  lines.push('');

  const filteredFindings = data.protocol.findings
    .filter((f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[threshold])
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  if (filteredFindings.length > 0) {
    lines.push('| Severity | Type | URL | Auth Required | Evidence |');
    lines.push('|----------|------|-----|--------------|----------|');
    for (const finding of filteredFindings) {
      const scheme = finding.protocol === 'rtsp' ? 'rtsp'
        : finding.protocol === 'https' ? 'https' : 'http';
      const fullUrl = `${scheme}://${finding.ip}:${finding.port}${finding.path}`;
      const source = finding.source === 'ai' ? ' (AI)' : '';
      lines.push(
        `| ${finding.severity.toUpperCase()}${source} | ${finding.type} | \`${fullUrl}\` | ${finding.authenticated ? 'Yes' : '**No**'} | ${finding.evidence} |`
      );
    }
    lines.push('');

    // VLC-ready URLs section — copy-paste directly into VLC / browser
    const unauthFindings = filteredFindings.filter((f) => !f.authenticated && f.severity !== 'info');
    if (unauthFindings.length > 0) {
      lines.push('#### Verification URLs');
      lines.push('');
      lines.push('> Copy-paste these URLs directly into VLC (Media > Open Network Stream) or a browser to verify findings.');
      lines.push('');
      for (const finding of unauthFindings) {
        const scheme = finding.protocol === 'rtsp' ? 'rtsp'
          : finding.protocol === 'https' ? 'https' : 'http';
        const fullUrl = `${scheme}://${finding.ip}:${finding.port}${finding.path}`;
        lines.push(`- **${finding.type}**: \`${fullUrl}\``);
      }
      lines.push('');

      if (includePoc) {
        lines.push('#### Proof of Concept Commands');
        lines.push('');
        for (const finding of unauthFindings.slice(0, 10)) {
          const scheme = finding.protocol === 'rtsp' ? 'rtsp'
            : finding.protocol === 'https' ? 'https' : 'http';
          const fullUrl = `${scheme}://${finding.ip}:${finding.port}${finding.path}`;
          lines.push(`\`\`\`bash`);
          lines.push(`# ${finding.type} on ${finding.ip}:${finding.port}`);
          if (finding.protocol === 'rtsp') {
            lines.push(`vlc "${fullUrl}"`);
            lines.push(`# or: ffplay "${fullUrl}"`);
          } else if (finding.type === 'snapshot_endpoint') {
            lines.push(`curl -o snapshot.jpg "${fullUrl}"`);
            lines.push(`# or open in browser: ${fullUrl}`);
          } else {
            lines.push(`curl "${fullUrl}"`);
            lines.push(`# or open in browser: ${fullUrl}`);
          }
          lines.push(`\`\`\``);
          lines.push('');
        }
      }
    }
  } else {
    lines.push('No protocol-level findings at the configured severity threshold.');
    lines.push('');
  }

  lines.push('---');
  lines.push('');

  // ─── Recommendations ──────────────────────────────────────
  lines.push('## 6. Recommendations');
  lines.push('');

  const recommendations: string[] = [];

  if (successfulCreds.length > 0) {
    recommendations.push('**[CRITICAL] Change Default Credentials:** Multiple cameras are using factory-default credentials. Change all passwords immediately and enforce strong password policies.');
  }

  if (vulnerableCves.some((v) => v.severity === 'critical')) {
    recommendations.push('**[CRITICAL] Apply Firmware Updates:** Critical CVEs confirmed. Update affected devices to the latest firmware version from the manufacturer.');
  }

  const unauthRtsp = data.protocol.findings.filter((f) => f.type === 'rtsp_stream' && !f.authenticated);
  if (unauthRtsp.length > 0) {
    recommendations.push('**[HIGH] Enable RTSP Authentication:** RTSP streams are accessible without credentials. Enable authentication on all camera RTSP services.');
  }

  const configDisclosure = data.protocol.findings.filter((f) => f.type === 'config_disclosure');
  if (configDisclosure.length > 0) {
    recommendations.push('**[HIGH] Restrict Configuration Access:** Configuration files are exposed. Ensure all management endpoints require authentication.');
  }

  recommendations.push('**[MEDIUM] Network Segmentation:** Place all cameras on a dedicated VLAN with firewall rules restricting access to authorized management hosts only.');
  recommendations.push('**[MEDIUM] Disable Unnecessary Services:** Disable Telnet, SSH, and other services not actively used for camera management.');
  recommendations.push('**[LOW] Monitor Camera Access Logs:** Implement centralized logging for camera access to detect unauthorized access attempts.');

  for (const rec of recommendations) {
    lines.push(`- ${rec}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  // ─── Footer ───────────────────────────────────────────────
  lines.push('## Appendix');
  lines.push('');
  lines.push(`- **Tool:** VeilCams v1.0.0`);
  lines.push(`- **Scan Duration:** ${formatDuration(data.totalDurationMs)}`);
  lines.push(`- **Discovery Duration:** ${formatDuration(data.discovery.scanDurationMs)}`);
  lines.push(`- **Credential Testing Duration:** ${formatDuration(data.credentials.durationMs)}`);
  lines.push(`- **CVE Scanning Duration:** ${formatDuration(data.cve.durationMs)}`);
  if (data.exploitation && data.exploitation.results.length > 0) {
    lines.push(`- **Exploitation Duration:** ${formatDuration(data.exploitation.durationMs)}`);
  }
  lines.push(`- **Protocol Fuzzing Duration:** ${formatDuration(data.protocol.durationMs)}`);
  lines.push('');
  lines.push('> This report was generated by VeilCams, an automated webcam security testing framework.');
  lines.push('> All findings should be verified manually before taking remediation actions.');
  lines.push('> Only test systems you own or have explicit written authorization to test.');

  const report = lines.join('\n');

  // Save deliverable
  const deliverablePath = path.join(outputDir, 'deliverables', 'security_assessment_report.md');
  await fs.mkdir(path.dirname(deliverablePath), { recursive: true });
  await fs.writeFile(deliverablePath, report);

  // Also save JSON version
  if (data.config.reporting.format === 'json') {
    const jsonPath = path.join(outputDir, 'deliverables', 'security_assessment_report.json');
    await fs.writeFile(jsonPath, JSON.stringify(data, null, 2));
  }

  return report;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}
