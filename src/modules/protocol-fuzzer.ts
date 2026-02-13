import { promises as fs } from 'node:fs';
import path from 'node:path';
import type {
  FingerprintResult,
  ProtocolFinding,
  ProtocolModuleResult,
  VeilcamsConfig,
} from '../types/index.js';
import { RTSP_PATHS, SNAPSHOT_ENDPOINTS, CONFIG_DISCLOSURE_PATHS } from '../constants.js';
import { httpGet, rtspDescribe } from '../utils/network.js';
import { parallelLimit, RateLimiter } from '../utils/concurrency.js';

/**
 * Phase 3c: Protocol Fuzzer
 * Discovers RTSP streams, snapshot endpoints, config files, and
 * other interesting paths on camera web interfaces.
 */
export async function runProtocolFuzzer(
  targets: FingerprintResult[],
  config: VeilcamsConfig,
  outputDir: string
): Promise<ProtocolModuleResult> {
  const startTime = Date.now();
  const allFindings: ProtocolFinding[] = [];
  let totalPathsTested = 0;

  const concurrency = config.rate_limiting?.max_concurrent_hosts ?? 10;

  // Pre-determine which target "owns" RTSP fuzzing for each IP.
  // This prevents duplicate findings when both an RTSP-port target (:554) and
  // an HTTP-port target (:80, which also detects RTSP) exist for the same IP.
  // Prefer the dedicated RTSP-port target since it was discovered directly.
  const rtspFuzzOwner = new Map<string, string>();
  for (const target of targets) {
    if (config.protocols.rtsp && target.protocols.includes('rtsp')) {
      const ownerKey = target.ip;
      const targetKey = `${target.ip}:${target.port}`;
      const existingOwner = rtspFuzzOwner.get(ownerKey);
      if (!existingOwner) {
        rtspFuzzOwner.set(ownerKey, targetKey);
      } else {
        // Prefer the target that's on a known RTSP port (554, 8554, etc.)
        const rtspPorts = [554, 8554, 8555, 10554];
        if (rtspPorts.includes(target.port) && !rtspPorts.includes(parseInt(existingOwner.split(':')[1]))) {
          rtspFuzzOwner.set(ownerKey, targetKey);
        }
      }
    }
  }

  const tasks = targets.map((target) => async () => {
    const targetKey = `${target.ip}:${target.port}`;
    const skipRtsp = rtspFuzzOwner.get(target.ip) !== targetKey;
    const result = await fuzzHost(target, config, skipRtsp);
    allFindings.push(...result.findings);
    totalPathsTested += result.pathsTested;
  });

  await parallelLimit(tasks, concurrency);

  const moduleResult: ProtocolModuleResult = {
    findings: allFindings,
    pathsTested: totalPathsTested,
    findingsCount: allFindings.length,
    durationMs: Date.now() - startTime,
  };

  // Save deliverable
  const deliverablePath = path.join(outputDir, 'deliverables', 'protocol_results.json');
  await fs.mkdir(path.dirname(deliverablePath), { recursive: true });
  await fs.writeFile(deliverablePath, JSON.stringify(moduleResult, null, 2));

  return moduleResult;
}

interface HostFuzzResult {
  findings: ProtocolFinding[];
  pathsTested: number;
}

async function fuzzHost(
  target: FingerprintResult,
  config: VeilcamsConfig,
  skipRtsp: boolean = false
): Promise<HostFuzzResult> {
  const findings: ProtocolFinding[] = [];
  let pathsTested = 0;
  const rateLimiter = new RateLimiter(config.rate_limiting?.requests_per_second ?? 5);

  // 1. RTSP path discovery (skip if another target for the same IP already handles it)
  if (config.protocols.rtsp && target.protocols.includes('rtsp') && !skipRtsp) {
    const rtspFindings = await fuzzRtspPaths(target, rateLimiter);
    findings.push(...rtspFindings.findings);
    pathsTested += rtspFindings.pathsTested;
  }

  // 2. Snapshot endpoint discovery
  if (config.protocols.http) {
    const snapFindings = await fuzzSnapshotEndpoints(target, rateLimiter);
    findings.push(...snapFindings.findings);
    pathsTested += snapFindings.pathsTested;
  }

  // 3. Config file disclosure
  if (config.protocols.http) {
    const configFindings = await fuzzConfigPaths(target, rateLimiter);
    findings.push(...configFindings.findings);
    pathsTested += configFindings.pathsTested;
  }

  // 4. Common admin/debug endpoints
  if (config.protocols.http) {
    const adminFindings = await fuzzAdminEndpoints(target, rateLimiter);
    findings.push(...adminFindings.findings);
    pathsTested += adminFindings.pathsTested;
  }

  return { findings, pathsTested };
}

async function fuzzRtspPaths(
  target: FingerprintResult,
  rateLimiter: RateLimiter
): Promise<HostFuzzResult> {
  const findings: ProtocolFinding[] = [];
  const rtspPort = 554;

  const paths = [
    ...(RTSP_PATHS[target.vendor] || []),
    ...RTSP_PATHS.unknown,
  ];
  const uniquePaths = [...new Set(paths)];

  for (const streamPath of uniquePaths) {
    await rateLimiter.acquire();
    try {
      const result = await rtspDescribe(target.ip, rtspPort, streamPath, undefined, 5000);

      if (result.statusCode === 200) {
        findings.push({
          ip: target.ip,
          port: rtspPort,
          type: 'rtsp_stream',
          protocol: 'rtsp',
          path: streamPath,
          severity: 'high',
          description: 'RTSP stream accessible without authentication',
          evidence: `RTSP DESCRIBE returned ${result.statusCode} for path ${streamPath}`,
          authenticated: false,
          timestamp: new Date().toISOString(),
        });
      } else if (result.statusCode === 401) {
        // Stream exists but requires auth — still useful info
        findings.push({
          ip: target.ip,
          port: rtspPort,
          type: 'rtsp_stream',
          protocol: 'rtsp',
          path: streamPath,
          severity: 'info',
          description: 'RTSP stream found (requires authentication)',
          evidence: `RTSP DESCRIBE returned ${result.statusCode} — stream exists at ${streamPath}`,
          authenticated: true,
          timestamp: new Date().toISOString(),
        });
      }
    } catch { /* path not responding */ }
  }

  return { findings, pathsTested: uniquePaths.length };
}

async function fuzzSnapshotEndpoints(
  target: FingerprintResult,
  rateLimiter: RateLimiter
): Promise<HostFuzzResult> {
  const findings: ProtocolFinding[] = [];
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;

  const endpoints = [
    ...(SNAPSHOT_ENDPOINTS[target.vendor] || []),
    ...SNAPSHOT_ENDPOINTS.unknown,
  ];
  const uniqueEndpoints = [...new Set(endpoints)];

  for (const endpoint of uniqueEndpoints) {
    await rateLimiter.acquire();
    try {
      const resp = await httpGet(`${baseUrl}${endpoint}`, { timeout: 5000 });
      const contentType = (resp.headers as Record<string, string>)['content-type'] || '';

      if (resp.status === 200 && (contentType.includes('image/') || contentType.includes('octet-stream'))) {
        findings.push({
          ip: target.ip,
          port: target.port,
          type: 'snapshot_endpoint',
          protocol: scheme === 'https' ? 'https' : 'http',
          path: endpoint,
          severity: 'medium',
          description: 'Camera snapshot accessible without authentication',
          evidence: `HTTP ${resp.status} at ${endpoint} (Content-Type: ${contentType})`,
          authenticated: false,
          timestamp: new Date().toISOString(),
        });
      }
    } catch { /* endpoint not accessible */ }
  }

  return { findings, pathsTested: uniqueEndpoints.length };
}

async function fuzzConfigPaths(
  target: FingerprintResult,
  rateLimiter: RateLimiter
): Promise<HostFuzzResult> {
  const findings: ProtocolFinding[] = [];
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;

  for (const configPath of CONFIG_DISCLOSURE_PATHS) {
    await rateLimiter.acquire();
    try {
      const resp = await httpGet(`${baseUrl}${configPath}`, { timeout: 5000 });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (
        resp.status === 200 &&
        body.length > 20 &&
        !body.includes('<!DOCTYPE') &&
        !body.includes('<html')
      ) {
        // Determine severity based on content
        const hasCredentials = /(password|passwd|secret|token|key)/i.test(body);
        const severity = hasCredentials ? 'critical' : 'high';

        findings.push({
          ip: target.ip,
          port: target.port,
          type: 'config_disclosure',
          protocol: scheme === 'https' ? 'https' : 'http',
          path: configPath,
          severity,
          description: hasCredentials
            ? 'Configuration file with credentials exposed'
            : 'Configuration file exposed without authentication',
          evidence: `HTTP ${resp.status} at ${configPath} (${body.length} bytes)${hasCredentials ? ' — contains credential-like data' : ''}`,
          authenticated: false,
          timestamp: new Date().toISOString(),
        });
      }
    } catch { /* path not accessible */ }
  }

  return { findings, pathsTested: CONFIG_DISCLOSURE_PATHS.length };
}

async function fuzzAdminEndpoints(
  target: FingerprintResult,
  rateLimiter: RateLimiter
): Promise<HostFuzzResult> {
  const findings: ProtocolFinding[] = [];
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;

  const adminPaths = [
    '/admin/',
    '/admin.html',
    '/cgi-bin/',
    '/debug/',
    '/test/',
    '/phpinfo.php',
    '/server-status',
    '/server-info',
    '/actuator',
    '/api/',
    '/api/v1/',
    '/swagger-ui.html',
    '/console/',
    '/shell/',
    '/telnet.cgi',
    '/system/',
    '/maintenance/',
    '/firmware/',
    '/upgrade/',
    '/backup/',
    '/restore/',
    '/reboot/',
    '/factory-reset/',
    '/diag.cgi',
    '/debug.cgi',
  ];

  for (const adminPath of adminPaths) {
    await rateLimiter.acquire();
    try {
      const resp = await httpGet(`${baseUrl}${adminPath}`, {
        timeout: 5000,
        followRedirects: false,
      });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200 && body.length > 50) {
        findings.push({
          ip: target.ip,
          port: target.port,
          type: 'unauthenticated_access',
          protocol: scheme === 'https' ? 'https' : 'http',
          path: adminPath,
          severity: 'medium',
          description: `Admin/debug endpoint accessible at ${adminPath}`,
          evidence: `HTTP ${resp.status} (${body.length} bytes)`,
          authenticated: false,
          timestamp: new Date().toISOString(),
        });
      }
    } catch { /* path not accessible */ }
  }

  return { findings, pathsTested: adminPaths.length };
}
