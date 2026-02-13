import Anthropic from '@anthropic-ai/sdk';
import type {
  FingerprintResult,
  ProtocolFinding,
  ProtocolFindingType,
  Severity,
} from '../types/index.js';
import { httpGet, httpRequest } from '../utils/network.js';

let client: Anthropic | null = null;

function getClient(): Anthropic {
  if (!client) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error('ANTHROPIC_API_KEY environment variable is required for AI protocol fuzzing');
    }
    client = new Anthropic({ apiKey });
  }
  return client;
}

// ─── Types ──────────────────────────────────────────────────────

export interface AiProtocolProbe {
  path: string;
  method: 'GET' | 'POST';
  type: ProtocolFindingType;
  severity: Severity;
  description: string;
  expectedVulnerablePattern: string;
  expectedSafePattern: string;
  reasoning: string;
}

interface AiFindingVerification {
  path: string;
  isReal: boolean;
  confidence: 'high' | 'medium' | 'low';
  falsePositiveRisk: 'low' | 'medium' | 'high';
  evidence: string;
  reasoning: string;
}

interface ProbeResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}

// ─── Call 1: Smart Path Generation ──────────────────────────────

export async function generateAiPaths(
  target: FingerprintResult,
  staticPathsTested: string[],
  options: { model: string; maxPaths: number }
): Promise<AiProtocolProbe[]> {
  const anthropic = getClient();

  console.log(`[ai-protocol] Asking Claude for additional paths for ${target.vendor} ${target.model || ''} (${target.ip}:${target.port})...`);

  const message = await anthropic.messages.create({
    model: options.model,
    max_tokens: 8192,
    messages: [{
      role: 'user',
      content: `You are a security researcher specializing in IP camera and IoT device security. Based on your knowledge of this specific vendor/model, generate additional HTTP/RTSP paths worth testing that are NOT in the static list already tested.

TARGET DEVICE:
- IP: ${target.ip}:${target.port}
- Vendor: ${target.vendor}
- Model: ${target.model || 'unknown'}
- Firmware: ${target.firmware || 'unknown'}
- Server Header: ${target.serverHeader || 'none'}
- Auth Type: ${target.authType}
- Protocols: ${target.protocols.join(', ')}
- Web Interface: ${target.webInterface}
- ONVIF: ${target.onvifSupported}

PATHS ALREADY TESTED (do NOT repeat these):
${staticPathsTested.join('\n')}

Generate up to ${options.maxPaths} additional paths that are specific to this vendor/model/firmware combination. Focus on:
1. Vendor-specific API endpoints not in the static list
2. Firmware-version-specific paths
3. Debug/diagnostic endpoints unique to this device family
4. Known configuration disclosure paths for this vendor
5. Hidden or undocumented snapshot/stream endpoints
6. Backup/export endpoints that may leak sensitive data

For each path, provide:
- The expected finding type if the path is accessible
- Regex patterns to distinguish a real finding from a false positive (generic error page, redirect, etc.)
- Why this path is relevant to this specific device

Respond with a JSON array. Each element:
{
  "path": "/the/path/to/test",
  "method": "GET" | "POST",
  "type": "rtsp_stream" | "snapshot_endpoint" | "config_disclosure" | "directory_traversal" | "unauthenticated_access" | "info_disclosure",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "description": "What this path exposes if accessible",
  "expectedVulnerablePattern": "regex that indicates a real finding in the response body/headers",
  "expectedSafePattern": "regex that indicates a false positive (error page, redirect, etc.)",
  "reasoning": "Why this path is relevant to this specific vendor/model"
}

Requirements:
- Only include paths you are confident are relevant to this vendor/device type
- Do NOT include generic paths — those are already covered by static fuzzing
- The expectedVulnerablePattern must match SPECIFIC content, not just "status 200"
- The expectedSafePattern should catch common false positives (HTML error pages, login redirects)
- Each path must be unique and not already in the tested list

Respond ONLY with the JSON array, no other text.`,
    }],
  });

  const responseText = message.content
    .filter((block): block is Anthropic.TextBlock => block.type === 'text')
    .map((block) => block.text)
    .join('');

  try {
    const parsed = JSON.parse(extractJson(responseText)) as AiProtocolProbe[];

    // Validate and filter
    const testedSet = new Set(staticPathsTested.map((p) => p.toLowerCase()));
    return parsed.filter((probe) => {
      if (!probe.path || !probe.method || !probe.type) return false;
      if (testedSet.has(probe.path.toLowerCase())) return false;
      return true;
    }).slice(0, options.maxPaths);
  } catch {
    console.error('[ai-protocol] Failed to parse path generation response from Claude');
    return [];
  }
}

// ─── Execute AI-Generated Probes ────────────────────────────────

export async function executeAiProbes(
  target: FingerprintResult,
  probes: AiProtocolProbe[],
  rateLimiterAcquire: () => Promise<void>
): Promise<ProtocolFinding[]> {
  const findings: ProtocolFinding[] = [];
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;

  for (const probe of probes) {
    await rateLimiterAcquire();
    try {
      const response = await executeProbe(baseUrl, probe);

      // Quick regex-based pre-filter before sending to AI verification
      let matchesVuln = false;
      let matchesSafe = false;

      try {
        if (probe.expectedVulnerablePattern) {
          matchesVuln = new RegExp(probe.expectedVulnerablePattern, 'i').test(response.body);
        }
      } catch { /* invalid regex */ }

      try {
        if (probe.expectedSafePattern) {
          matchesSafe = new RegExp(probe.expectedSafePattern, 'i').test(response.body);
        }
      } catch { /* invalid regex */ }

      // Only count as a finding if vuln pattern matches and safe pattern doesn't
      if (response.statusCode >= 200 && response.statusCode < 400 && matchesVuln && !matchesSafe) {
        findings.push({
          ip: target.ip,
          port: target.port,
          type: probe.type,
          protocol: scheme === 'https' ? 'https' : 'http',
          path: probe.path,
          severity: probe.severity,
          description: probe.description,
          evidence: `HTTP ${response.statusCode} at ${probe.path} (${response.body.length} bytes)`,
          authenticated: false,
          timestamp: new Date().toISOString(),
          source: 'ai',
          reasoning: probe.reasoning,
        });
      }
    } catch { /* path not accessible */ }
  }

  return findings;
}

async function executeProbe(baseUrl: string, probe: AiProtocolProbe): Promise<ProbeResponse> {
  const url = `${baseUrl}${probe.path}`;
  const timeout = 5000;

  try {
    let response;
    if (probe.method === 'GET') {
      response = await httpGet(url, { timeout, followRedirects: false });
    } else {
      response = await httpRequest(url, probe.method, undefined, { timeout });
    }

    const body = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data || '');

    return {
      statusCode: response.status,
      headers: response.headers as Record<string, string>,
      body: body.substring(0, 5000),
    };
  } catch (error) {
    return {
      statusCode: 0,
      headers: {},
      body: '',
      error: (error as Error).message,
    };
  }
}

// ─── Call 2: Finding Verification ───────────────────────────────

export async function verifyFindings(
  target: FingerprintResult,
  findings: ProtocolFinding[],
  options: { model: string }
): Promise<AiFindingVerification[]> {
  if (findings.length === 0) return [];

  const anthropic = getClient();

  console.log(`[ai-protocol] Asking Claude to verify ${findings.length} findings for ${target.ip}:${target.port}...`);

  // Collect response data for each finding to send to Claude
  const scheme = target.protocols.includes('https') ? 'https' : 'http';
  const baseUrl = `${scheme}://${target.ip}:${target.port}`;

  const findingsWithResponses = await Promise.all(
    findings.map(async (finding) => {
      if (finding.protocol === 'rtsp') {
        // For RTSP findings, we already have evidence from the DESCRIBE response
        return {
          finding,
          responseData: {
            statusCode: 0,
            headers: {} as Record<string, string>,
            body: finding.evidence,
          },
        };
      }

      try {
        const resp = await httpGet(`${baseUrl}${finding.path}`, {
          timeout: 5000,
          followRedirects: false,
        });
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
        return {
          finding,
          responseData: {
            statusCode: resp.status,
            headers: resp.headers as Record<string, string>,
            body: body.substring(0, 2000),
          },
        };
      } catch {
        return {
          finding,
          responseData: {
            statusCode: 0,
            headers: {} as Record<string, string>,
            body: finding.evidence,
          },
        };
      }
    })
  );

  const findingsSummary = findingsWithResponses.map((f, i) => `
FINDING #${i + 1}:
- Path: ${f.finding.path}
- Type: ${f.finding.type}
- Severity: ${f.finding.severity}
- Protocol: ${f.finding.protocol}
- Description: ${f.finding.description}
- Source: ${f.finding.source || 'static'}
- Response Status: ${f.responseData.statusCode}
- Response Headers: ${JSON.stringify(f.responseData.headers)}
- Response Body (first 2000 chars): ${f.responseData.body}
`).join('\n---\n');

  const message = await anthropic.messages.create({
    model: options.model,
    max_tokens: 8192,
    messages: [{
      role: 'user',
      content: `You are a security analyst reviewing protocol fuzzing results. Your job is to identify FALSE POSITIVES and confirm REAL findings. Be extremely conservative — the cost of a false positive is much higher than a false negative.

TARGET DEVICE:
- IP: ${target.ip}:${target.port}
- Vendor: ${target.vendor}
- Model: ${target.model || 'unknown'}
- Firmware: ${target.firmware || 'unknown'}
- Server Header: ${target.serverHeader || 'none'}

FINDINGS TO VERIFY:
${findingsSummary}

For each finding, analyze:
1. Does the response actually contain the type of data described? (e.g., a "config_disclosure" finding should contain actual config data, not an HTML error page)
2. Is the response a generic error page, login redirect, or default page that just happens to return HTTP 200?
3. For snapshot endpoints: does the Content-Type indicate actual image data?
4. For config files: does the response contain actual configuration, not just HTML wrapping?
5. For admin pages: is there real admin functionality, or just a generic page?
6. For RTSP streams: was the DESCRIBE response genuinely successful?

CRITICAL FALSE POSITIVE INDICATORS:
- HTML pages with "404", "not found", "error", "forbidden" in the body but HTTP 200 status
- Login/redirect pages returned for any path
- Generic "welcome" or "index" pages
- Empty or very short responses
- Responses that are identical regardless of the path requested

Respond with a JSON array with one entry per finding:
{
  "path": "/the/path",
  "isReal": true | false,
  "confidence": "high" | "medium" | "low",
  "falsePositiveRisk": "low" | "medium" | "high",
  "evidence": "What in the response confirms or denies this is a real finding",
  "reasoning": "Step-by-step analysis"
}

Respond ONLY with the JSON array, no other text.`,
    }],
  });

  const responseText = message.content
    .filter((block): block is Anthropic.TextBlock => block.type === 'text')
    .map((block) => block.text)
    .join('');

  try {
    return JSON.parse(extractJson(responseText)) as AiFindingVerification[];
  } catch {
    console.error('[ai-protocol] Failed to parse verification response from Claude');
    return [];
  }
}

// ─── Apply Verification Results ─────────────────────────────────

export function applyVerification(
  findings: ProtocolFinding[],
  verifications: AiFindingVerification[]
): ProtocolFinding[] {
  const verificationMap = new Map<string, AiFindingVerification>();
  for (const v of verifications) {
    verificationMap.set(v.path, v);
  }

  return findings.filter((finding) => {
    const verification = verificationMap.get(finding.path);
    if (!verification) return true; // No verification data — keep the finding

    // Annotate the finding with verification data
    finding.confidence = verification.confidence;
    finding.falsePositiveRisk = verification.falsePositiveRisk;
    if (verification.reasoning) {
      finding.reasoning = verification.reasoning;
    }

    // Filter out findings flagged as false positives
    if (!verification.isReal) return false;
    if (verification.falsePositiveRisk === 'high') return false;
    if (verification.falsePositiveRisk === 'medium' && verification.confidence !== 'high') return false;

    return true;
  });
}

// ─── Helpers ────────────────────────────────────────────────────

function extractJson(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) return fenceMatch[1].trim();

  const jsonMatch = text.match(/(\[[\s\S]*\]|\{[\s\S]*\})(?:\s*$)/);
  if (jsonMatch) return jsonMatch[1];

  const firstBrace = text.indexOf('{');
  const firstBracket = text.indexOf('[');
  const start = firstBrace >= 0 && (firstBracket < 0 || firstBrace < firstBracket)
    ? firstBrace : firstBracket;
  if (start >= 0) return text.substring(start).trim();

  return text.trim();
}
