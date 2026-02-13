import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import type { VeilcamsConfig } from './types/index.js';
import { DEFAULTS } from './constants.js';

const DANGEROUS_PATTERNS = [
  /\.\.\//,
  /[<>]/,
  /javascript:/i,
  /data:/i,
  /file:/i,
];

const MAX_CONFIG_SIZE = 1024 * 1024; // 1MB

export async function parseConfig(configPath: string): Promise<VeilcamsConfig> {
  const resolved = path.resolve(configPath);

  if (!fs.existsSync(resolved)) {
    throw new Error(`Configuration file not found: ${resolved}`);
  }

  const stats = fs.statSync(resolved);
  if (stats.size > MAX_CONFIG_SIZE) {
    throw new Error(`Configuration file too large (max ${MAX_CONFIG_SIZE} bytes)`);
  }

  const content = fs.readFileSync(resolved, 'utf-8');

  validateDangerousPatterns(content);

  const parsed = yaml.load(content, {
    schema: yaml.FAILSAFE_SCHEMA,
    json: false,
  }) as Record<string, unknown>;

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Configuration file is empty or invalid YAML');
  }

  validateSchema(parsed);

  return applyDefaults(coerceTypes(parsed));
}

function validateDangerousPatterns(content: string): void {
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(content)) {
      throw new Error(`Security violation: dangerous pattern detected in config (${pattern.source})`);
    }
  }
}

function validateSchema(config: Record<string, unknown>): void {
  const schemaPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'configs',
    'config-schema.json'
  );

  if (!fs.existsSync(schemaPath)) {
    console.warn('Warning: config-schema.json not found, skipping schema validation');
    return;
  }

  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf-8'));
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);

  const validate = ajv.compile(schema);
  const valid = validate(config);

  if (!valid && validate.errors) {
    const messages = validate.errors.map((e) => `  ${e.instancePath || '/'}: ${e.message}`);
    throw new Error(`Configuration validation failed:\n${messages.join('\n')}`);
  }
}

function coerceTypes(raw: Record<string, unknown>): Record<string, unknown> {
  const result = structuredClone(raw);

  // Coerce string numbers from FAILSAFE_SCHEMA
  const targets = result.targets as Array<Record<string, unknown>>;
  if (Array.isArray(targets)) {
    for (const target of targets) {
      if (target.ports && Array.isArray(target.ports)) {
        target.ports = (target.ports as string[]).map((p) => parseInt(String(p), 10));
      }
    }
  }

  const creds = result.credentials as Record<string, unknown> | undefined;
  if (creds) {
    if (creds.max_attempts_per_host) creds.max_attempts_per_host = parseInt(String(creds.max_attempts_per_host), 10);
    if (creds.delay_ms) creds.delay_ms = parseInt(String(creds.delay_ms), 10);
    if (creds.use_defaults !== undefined) creds.use_defaults = String(creds.use_defaults) === 'true';
  }

  const cve = result.cve_testing as Record<string, unknown> | undefined;
  if (cve) {
    if (cve.enabled !== undefined) cve.enabled = String(cve.enabled) === 'true';
    if (cve.safe_mode !== undefined) cve.safe_mode = String(cve.safe_mode) === 'true';
    if (cve.ai_enabled !== undefined) cve.ai_enabled = String(cve.ai_enabled) === 'true';
    if (cve.ai_max_cves_per_host) cve.ai_max_cves_per_host = parseInt(String(cve.ai_max_cves_per_host), 10);
  }

  const protocols = result.protocols as Record<string, unknown> | undefined;
  if (protocols) {
    const booleanKeys = ['rtsp', 'onvif', 'http', 'telnet', 'ssh', 'ai_enabled'];
    for (const key of booleanKeys) {
      if (protocols[key] !== undefined) {
        protocols[key] = String(protocols[key]) === 'true';
      }
    }
    if (protocols.ai_max_paths_per_host) {
      protocols.ai_max_paths_per_host = parseInt(String(protocols.ai_max_paths_per_host), 10);
    }
  }

  const exploitation = result.exploitation as Record<string, unknown> | undefined;
  if (exploitation) {
    if (exploitation.enabled !== undefined) exploitation.enabled = String(exploitation.enabled) === 'true';
    if (exploitation.auto_exploit_confirmed !== undefined) exploitation.auto_exploit_confirmed = String(exploitation.auto_exploit_confirmed) === 'true';
    if (exploitation.timeout_per_exploit) exploitation.timeout_per_exploit = parseInt(String(exploitation.timeout_per_exploit), 10);
  }

  const reporting = result.reporting as Record<string, unknown> | undefined;
  if (reporting) {
    if (reporting.include_poc !== undefined) reporting.include_poc = String(reporting.include_poc) === 'true';
  }

  const rate = result.rate_limiting as Record<string, unknown> | undefined;
  if (rate) {
    if (rate.max_concurrent_hosts) rate.max_concurrent_hosts = parseInt(String(rate.max_concurrent_hosts), 10);
    if (rate.requests_per_second) rate.requests_per_second = parseInt(String(rate.requests_per_second), 10);
    if (rate.timeout_ms) rate.timeout_ms = parseInt(String(rate.timeout_ms), 10);
  }

  return result;
}

function applyDefaults(raw: Record<string, unknown>): VeilcamsConfig {
  return {
    targets: raw.targets as VeilcamsConfig['targets'],

    credentials: {
      use_defaults: true,
      custom: [],
      max_attempts_per_host: DEFAULTS.MAX_ATTEMPTS_PER_HOST,
      delay_ms: DEFAULTS.CREDENTIAL_DELAY_MS,
      ...(raw.credentials as Partial<VeilcamsConfig['credentials']> || {}),
    },

    cve_testing: {
      enabled: true,
      safe_mode: true,
      categories: ['auth_bypass', 'info_disclosure', 'command_injection', 'path_traversal'],
      ai_enabled: true,
      ai_model: 'claude-sonnet-4-5-20250929',
      ai_max_cves_per_host: 20,
      ...(raw.cve_testing as Partial<VeilcamsConfig['cve_testing']> || {}),
    },

    protocols: {
      rtsp: true,
      onvif: true,
      http: true,
      telnet: false,
      ssh: false,
      ai_enabled: false,
      ai_model: 'claude-sonnet-4-5-20250929',
      ai_max_paths_per_host: DEFAULTS.AI_PROTOCOL_MAX_PATHS_PER_HOST,
      ...(raw.protocols as Partial<VeilcamsConfig['protocols']> || {}),
    },

    exploitation: {
      enabled: false,
      timeout_per_exploit: DEFAULTS.EXPLOITATION_TIMEOUT_MS,
      auto_exploit_confirmed: true,
      ...(raw.exploitation as Partial<VeilcamsConfig['exploitation']> || {}),
    },

    reporting: {
      format: 'markdown',
      include_poc: true,
      severity_threshold: 'low',
      ...(raw.reporting as Partial<VeilcamsConfig['reporting']> || {}),
    },

    rate_limiting: {
      max_concurrent_hosts: DEFAULTS.MAX_CONCURRENT_HOSTS,
      requests_per_second: DEFAULTS.REQUESTS_PER_SECOND,
      timeout_ms: DEFAULTS.REQUEST_TIMEOUT_MS,
      ...(raw.rate_limiting as Partial<VeilcamsConfig['rate_limiting']> || {}),
    },
  };
}

export function getDefaultConfig(): VeilcamsConfig {
  return applyDefaults({ targets: [] });
}
