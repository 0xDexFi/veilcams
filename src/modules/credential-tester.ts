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

async function testHttpAuth(
  target: FingerprintResult,
  cred: Credential
): Promise<CredentialTestResult> {
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;
  const timestamp = new Date().toISOString();

  try {
    if (target.authType === 'basic' || target.authType === 'unknown') {
      const resp = await httpGet(baseUrl, {
        auth: { username: cred.username, password: cred.password },
        timeout: 8000,
      });

      const success = resp.status >= 200 && resp.status < 400 && resp.status !== 401;
      return {
        ip: target.ip,
        port: target.port,
        vendor: target.vendor,
        protocol: scheme === 'https' ? 'https' : 'http',
        credential: cred,
        success,
        responseCode: resp.status,
        evidence: success
          ? `HTTP ${resp.status} — authenticated access granted via Basic auth`
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

      const success = resp.status >= 200 && resp.status < 400;
      return {
        ip: target.ip,
        port: target.port,
        vendor: target.vendor,
        protocol: scheme === 'https' ? 'https' : 'http',
        credential: cred,
        success,
        responseCode: resp.status,
        evidence: success
          ? `HTTP ${resp.status} — authenticated access granted via Digest auth`
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

    // Generic attempt
    const resp = await httpGet(baseUrl, {
      auth: { username: cred.username, password: cred.password },
      timeout: 8000,
    });

    const success = resp.status >= 200 && resp.status < 400 && resp.status !== 401;
    return {
      ip: target.ip,
      port: target.port,
      vendor: target.vendor,
      protocol: scheme === 'https' ? 'https' : 'http',
      credential: cred,
      success,
      responseCode: resp.status,
      evidence: success
        ? `HTTP ${resp.status} — authenticated access granted`
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
        ? `RTSP ${result.statusCode} — stream access granted at ${testPath}`
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
