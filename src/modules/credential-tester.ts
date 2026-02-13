import { promises as fs } from 'node:fs';
import path from 'node:path';
import type {
  FingerprintResult,
  Credential,
  CredentialTestResult,
  CredentialModuleResult,
  VeilcamsConfig,
} from '../types/index.js';
import { DEFAULT_CREDENTIALS, RTSP_PATHS } from '../constants.js';
import {
  httpGet,
  httpPost,
  computeDigestAuth,
  parseWwwAuthenticate,
  rtspDescribe,
} from '../utils/network.js';
import { parallelLimit, RateLimiter } from '../utils/concurrency.js';

/**
 * Phase 3a: Credential Testing
 * Tests default and custom credentials against discovered cameras.
 */
export async function runCredentialTester(
  targets: FingerprintResult[],
  config: VeilcamsConfig,
  outputDir: string
): Promise<CredentialModuleResult> {
  const startTime = Date.now();
  const allResults: CredentialTestResult[] = [];
  const hostsCompromised = new Set<string>();

  const concurrency = config.rate_limiting?.max_concurrent_hosts ?? 10;

  const tasks = targets.map((target) => async () => {
    const results = await testHost(target, config);
    for (const result of results) {
      allResults.push(result);
      if (result.success) {
        hostsCompromised.add(`${result.ip}:${result.port}`);
      }
    }
  });

  await parallelLimit(tasks, concurrency);

  const moduleResult: CredentialModuleResult = {
    results: allResults,
    totalAttempts: allResults.length,
    successfulLogins: allResults.filter((r) => r.success).length,
    hostsCompromised: hostsCompromised.size,
    durationMs: Date.now() - startTime,
  };

  // Save deliverable
  const deliverablePath = path.join(outputDir, 'deliverables', 'credential_results.json');
  await fs.mkdir(path.dirname(deliverablePath), { recursive: true });
  await fs.writeFile(deliverablePath, JSON.stringify(moduleResult, null, 2));

  return moduleResult;
}

async function testHost(
  target: FingerprintResult,
  config: VeilcamsConfig
): Promise<CredentialTestResult[]> {
  const results: CredentialTestResult[] = [];
  const creds = buildCredentialList(target, config);
  const maxAttempts = config.credentials.max_attempts_per_host;
  const delayMs = config.credentials.delay_ms;
  const rateLimiter = new RateLimiter(config.rate_limiting?.requests_per_second ?? 5);

  let attempts = 0;
  let foundValid = false;

  for (const cred of creds) {
    if (attempts >= maxAttempts) break;
    if (foundValid) break; // Stop after first valid credential per host

    await rateLimiter.acquire();

    // Test HTTP auth
    if (target.protocols.includes('http') || target.protocols.includes('https')) {
      attempts++;
      const httpResult = await testHttpAuth(target, cred);
      results.push(httpResult);
      if (httpResult.success) {
        foundValid = true;
        continue;
      }
    }

    // Test RTSP auth
    if (target.protocols.includes('rtsp') && config.protocols.rtsp) {
      attempts++;
      const rtspResult = await testRtspAuth(target, cred);
      results.push(rtspResult);
      if (rtspResult.success) {
        foundValid = true;
        continue;
      }
    }

    // Delay between attempts to avoid lockout
    if (delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return results;
}

function buildCredentialList(
  target: FingerprintResult,
  config: VeilcamsConfig
): Credential[] {
  const creds: Credential[] = [];
  const seen = new Set<string>();

  const addCred = (c: Credential) => {
    const key = `${c.username}:${c.password}`;
    if (!seen.has(key)) {
      seen.add(key);
      creds.push(c);
    }
  };

  // Add vendor-specific defaults first (highest probability)
  if (config.credentials.use_defaults) {
    const vendorCreds = DEFAULT_CREDENTIALS[target.vendor] || [];
    vendorCreds.forEach(addCred);

    // Always add generic defaults too
    if (target.vendor !== 'unknown') {
      DEFAULT_CREDENTIALS.unknown.forEach(addCred);
    }
  }

  // Add custom credentials
  config.credentials.custom.forEach(addCred);

  return creds;
}

/**
 * Get a baseline (unauthenticated) response for comparison.
 * Cached per host so we only make one unauthenticated request per target.
 */
const baselineCache = new Map<string, { status: number; body: string }>();

async function getBaseline(
  baseUrl: string
): Promise<{ status: number; body: string }> {
  if (baselineCache.has(baseUrl)) {
    return baselineCache.get(baseUrl)!;
  }

  try {
    const resp = await httpGet(baseUrl, { timeout: 8000 });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    const baseline = { status: resp.status, body };
    baselineCache.set(baseUrl, baseline);
    return baseline;
  } catch {
    const baseline = { status: -1, body: '' };
    baselineCache.set(baseUrl, baseline);
    return baseline;
  }
}

/**
 * Compare an authenticated response against the unauthenticated baseline.
 * Returns true only if the credentials demonstrably changed the server's response.
 */
function isAuthenticatedResponseDifferent(
  baseline: { status: number; body: string },
  authed: { status: number; body: string }
): boolean {
  // Baseline was an auth challenge (401/403) but authed succeeded → real auth
  if ((baseline.status === 401 || baseline.status === 403) && authed.status >= 200 && authed.status < 400) {
    return true;
  }

  // Baseline failed to connect but authed succeeded → inconclusive, treat as different
  if (baseline.status === -1 && authed.status >= 200 && authed.status < 400) {
    return true;
  }

  // Both returned the same success status → compare bodies
  if (baseline.status === authed.status) {
    // Identical or near-identical bodies → credentials had no effect
    if (baseline.body === authed.body) return false;

    // Check if the body difference is meaningful (>10% size difference or different structure)
    const sizeDiff = Math.abs(baseline.body.length - authed.body.length);
    const maxSize = Math.max(baseline.body.length, authed.body.length, 1);
    if (sizeDiff / maxSize < 0.1) {
      // Bodies are very similar in size — check for auth-specific content in authed response
      // that's absent from the baseline
      const authIndicators = /(logout|sign.?out|dashboard|welcome|session|authenticated|token)/i;
      if (authIndicators.test(authed.body) && !authIndicators.test(baseline.body)) {
        return true;
      }
      return false;
    }

    return true; // Meaningfully different body size
  }

  // Different status codes where authed got a "better" response
  if (authed.status >= 200 && authed.status < 400 && baseline.status >= 400) {
    return true;
  }

  return false;
}

async function testHttpAuth(
  target: FingerprintResult,
  cred: Credential
): Promise<CredentialTestResult> {
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;
  const timestamp = new Date().toISOString();

  try {
    // Get baseline unauthenticated response for comparison
    const baseline = await getBaseline(baseUrl);

    if (target.authType === 'basic' || target.authType === 'unknown') {
      const resp = await httpGet(baseUrl, {
        auth: { username: cred.username, password: cred.password },
        timeout: 8000,
      });

      const authedBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
      const statusOk = resp.status >= 200 && resp.status < 400 && resp.status !== 401;
      const genuineAuth = statusOk && isAuthenticatedResponseDifferent(baseline, { status: resp.status, body: authedBody });

      return {
        ip: target.ip,
        port: target.port,
        vendor: target.vendor,
        protocol: scheme === 'https' ? 'https' : 'http',
        credential: cred,
        success: genuineAuth,
        responseCode: resp.status,
        evidence: genuineAuth
          ? `HTTP ${resp.status} — authenticated access granted via Basic auth (verified against unauthenticated baseline)`
          : statusOk
            ? `HTTP ${resp.status} — server responds identically with and without credentials (no auth enforced on root page)`
            : `HTTP ${resp.status} — authentication failed`,
        timestamp,
      };
    }

    if (target.authType === 'digest') {
      // First request to get challenge
      const challengeResp = await httpGet(baseUrl, { timeout: 8000 });
      const wwwAuth = (challengeResp.headers as Record<string, string>)['www-authenticate'] || '';
      const params = parseWwwAuthenticate(wwwAuth);

      const authHeader = computeDigestAuth({
        username: cred.username,
        password: cred.password,
        method: 'GET',
        uri: '/',
        realm: params.realm || '',
        nonce: params.nonce || '',
        qop: params.qop,
        algorithm: params.algorithm,
      });

      const resp = await httpGet(baseUrl, {
        headers: { Authorization: authHeader },
        timeout: 8000,
      });

      // For digest auth, the baseline should be 401 (the challenge).
      // If it was already 200 without auth, digest credentials are meaningless.
      const authedBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
      const statusOk = resp.status >= 200 && resp.status < 400;
      const genuineAuth = statusOk && isAuthenticatedResponseDifferent(
        { status: challengeResp.status, body: typeof challengeResp.data === 'string' ? challengeResp.data : '' },
        { status: resp.status, body: authedBody }
      );

      return {
        ip: target.ip,
        port: target.port,
        vendor: target.vendor,
        protocol: scheme === 'https' ? 'https' : 'http',
        credential: cred,
        success: genuineAuth,
        responseCode: resp.status,
        evidence: genuineAuth
          ? `HTTP ${resp.status} — authenticated access granted via Digest auth (challenge was ${challengeResp.status})`
          : `HTTP ${resp.status} — Digest authentication failed`,
        timestamp,
      };
    }

    if (target.authType === 'form') {
      // Try common form-based login endpoints
      const loginEndpoints = [
        '/RPC2_Login',
        '/ISAPI/Security/userCheck',
        '/cgi-bin/global.login',
        '/api.cgi?cmd=Login',
        '/login.cgi',
        '/login',
      ];

      for (const endpoint of loginEndpoints) {
        try {
          const resp = await httpPost(
            `${baseUrl}${endpoint}`,
            { userName: cred.username, password: cred.password },
            { timeout: 8000 }
          );

          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
          const success =
            resp.status === 200 &&
            !/(error|fail|invalid|wrong|denied)/i.test(body) &&
            (/(success|ok|true|token|session)/i.test(body) || body.length > 100);

          if (success) {
            return {
              ip: target.ip,
              port: target.port,
              vendor: target.vendor,
              protocol: scheme === 'https' ? 'https' : 'http',
              credential: cred,
              success: true,
              responseCode: resp.status,
              evidence: `HTTP ${resp.status} via ${endpoint} — form login successful`,
              timestamp,
            };
          }
        } catch { /* try next endpoint */ }
      }
    }

    // For authType 'none': try vendor-specific auth endpoints before falling back
    if (target.authType === 'none') {
      const vendorLoginEndpoints = getVendorLoginEndpoints(target.vendor);
      for (const endpoint of vendorLoginEndpoints) {
        try {
          const resp = await httpPost(
            `${baseUrl}${endpoint}`,
            { userName: cred.username, password: cred.password, username: cred.username },
            { timeout: 8000 }
          );

          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

          // Strict validation: must have explicit success indicators AND no error indicators
          const hasExplicitSuccess = /(\"success\"\s*:\s*true|\"statusValue\"\s*:\s*200|\"result\"\s*:\s*true|\"authorized\"\s*:\s*true|token|sessionID)/i.test(body);
          const hasErrorIndicators = /(error|fail|invalid|wrong|denied|unauthorized|\"success\"\s*:\s*false|\"statusValue\"\s*:\s*[45]\d\d)/i.test(body);

          if (resp.status === 200 && hasExplicitSuccess && !hasErrorIndicators) {
            return {
              ip: target.ip,
              port: target.port,
              vendor: target.vendor,
              protocol: scheme === 'https' ? 'https' : 'http',
              credential: cred,
              success: true,
              responseCode: resp.status,
              evidence: `HTTP ${resp.status} via ${endpoint} — vendor API login confirmed (explicit success response)`,
              timestamp,
            };
          }
        } catch { /* try next endpoint */ }
      }

      // For 'none' authType, do NOT fall through to generic Basic auth test.
      // The root page serves content without auth, so Basic auth is meaningless.
      return {
        ip: target.ip,
        port: target.port,
        vendor: target.vendor,
        protocol: scheme === 'https' ? 'https' : 'http',
        credential: cred,
        success: false,
        responseCode: baseline.status,
        evidence: `No authentication enforced on root page — tested vendor API endpoints, no valid login confirmed`,
        timestamp,
      };
    }

    // Generic fallback (only reached for authType not covered above)
    const resp = await httpGet(baseUrl, {
      auth: { username: cred.username, password: cred.password },
      timeout: 8000,
    });

    const authedBody = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
    const statusOk = resp.status >= 200 && resp.status < 400 && resp.status !== 401;
    const genuineAuth = statusOk && isAuthenticatedResponseDifferent(baseline, { status: resp.status, body: authedBody });

    return {
      ip: target.ip,
      port: target.port,
      vendor: target.vendor,
      protocol: scheme === 'https' ? 'https' : 'http',
      credential: cred,
      success: genuineAuth,
      responseCode: resp.status,
      evidence: genuineAuth
        ? `HTTP ${resp.status} — authenticated access granted (verified against unauthenticated baseline)`
        : statusOk
          ? `HTTP ${resp.status} — server responds identically with and without credentials`
          : `HTTP ${resp.status} — authentication failed`,
      timestamp,
    };
  } catch (error) {
    return {
      ip: target.ip,
      port: target.port,
      vendor: target.vendor,
      protocol: scheme === 'https' ? 'https' : 'http',
      credential: cred,
      success: false,
      evidence: `Connection error: ${(error as Error).message}`,
      timestamp,
    };
  }
}

/**
 * Get vendor-specific login API endpoints to test credentials against
 * when authType is 'none' (root page has no auth gate).
 */
function getVendorLoginEndpoints(vendor: string): string[] {
  const vendorEndpoints: Record<string, string[]> = {
    hikvision: [
      '/ISAPI/Security/userCheck',
      '/ISAPI/Security/userValidate',
    ],
    dahua: [
      '/RPC2_Login',
      '/cgi-bin/global.login',
    ],
    axis: [
      '/axis-cgi/param.cgi?action=list&group=root.Properties',
    ],
    reolink: [
      '/api.cgi?cmd=Login',
    ],
    amcrest: [
      '/RPC2_Login',
    ],
    foscam: [
      '/cgi-bin/CGIProxy.fcgi?cmd=logIn',
    ],
  };

  return vendorEndpoints[vendor] || [
    '/ISAPI/Security/userCheck',
    '/RPC2_Login',
    '/api.cgi?cmd=Login',
    '/login',
    '/cgi-bin/global.login',
  ];
}

/**
 * Cache for RTSP unauthenticated access checks.
 * Maps "ip:port:path" → true if unauthenticated DESCRIBE returned 200.
 */
const rtspUnauthCache = new Map<string, boolean>();

async function isRtspUnauthenticated(
  ip: string,
  port: number,
  streamPath: string
): Promise<boolean> {
  const key = `${ip}:${port}:${streamPath}`;
  if (rtspUnauthCache.has(key)) {
    return rtspUnauthCache.get(key)!;
  }

  try {
    const result = await rtspDescribe(ip, port, streamPath, undefined, 5000);
    const isOpen = result.statusCode === 200;
    rtspUnauthCache.set(key, isOpen);
    return isOpen;
  } catch {
    rtspUnauthCache.set(key, false);
    return false;
  }
}

async function testRtspAuth(
  target: FingerprintResult,
  cred: Credential
): Promise<CredentialTestResult> {
  const timestamp = new Date().toISOString();
  // Find an RTSP port from the known list that the host actually has open
  const rtspPort = target.protocols.includes('rtsp')
    ? ([554, 8554, 8555, 10554].find((p) => p === target.port) || 554)
    : 554;

  // Get vendor-specific RTSP paths, fallback to generic
  const paths = RTSP_PATHS[target.vendor] || RTSP_PATHS.unknown;
  const testPath = paths[0] || '/';

  try {
    // First: check if RTSP is accessible WITHOUT credentials
    const unauthOpen = await isRtspUnauthenticated(target.ip, rtspPort, testPath);

    if (unauthOpen) {
      // Stream doesn't require auth — any credential will "work", so this is not meaningful
      return {
        ip: target.ip,
        port: rtspPort,
        vendor: target.vendor,
        protocol: 'rtsp',
        credential: cred,
        success: false,
        responseCode: 200,
        evidence: `RTSP stream at ${testPath} is accessible without any credentials — credential test not applicable (unauthenticated access is the real finding)`,
        timestamp,
      };
    }

    // Stream requires auth — now test the credential
    const result = await rtspDescribe(
      target.ip,
      rtspPort,
      testPath,
      { username: cred.username, password: cred.password },
      5000
    );

    const success = result.statusCode === 200;
    return {
      ip: target.ip,
      port: rtspPort,
      vendor: target.vendor,
      protocol: 'rtsp',
      credential: cred,
      success,
      responseCode: result.statusCode,
      evidence: success
        ? `RTSP ${result.statusCode} — stream access granted at ${testPath} (unauthenticated access was denied, credential is valid)`
        : `RTSP ${result.statusCode} — authentication failed`,
      timestamp,
    };
  } catch (error) {
    return {
      ip: target.ip,
      port: rtspPort,
      vendor: target.vendor,
      protocol: 'rtsp',
      credential: cred,
      success: false,
      evidence: `RTSP error: ${(error as Error).message}`,
      timestamp,
    };
  }
}
