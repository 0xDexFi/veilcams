import type { CameraVendor } from './types/index.js';

// ─── Metasploit Module Mapping (Fast Path) ──────────────────────
//
// Pre-configured CVE → Metasploit module mappings for known-good configs.
// These skip the AI module selection step — used as a fast path.
// Any CVE NOT in this map gets searched dynamically via msfconsole
// and configured by AI (Claude).

export interface MsfModuleConfig {
  module: string;
  type: 'exploit' | 'auxiliary';
  defaultPayload?: string;
  options: Record<string, string>;
  vendors: CameraVendor[];
  timeout: number;
}

export const CVE_MSF_MAP: Record<string, MsfModuleConfig> = {
  'CVE-2021-36260': {
    module: 'exploit/linux/http/hikvision_cve_2021_36260_blind',
    type: 'exploit',
    defaultPayload: 'cmd/unix/generic',
    options: { CMD: 'id' },
    vendors: ['hikvision'],
    timeout: 60_000,
  },
  'CVE-2017-7921': {
    module: 'auxiliary/gather/hikvision_info_disclosure',
    type: 'auxiliary',
    options: {},
    vendors: ['hikvision'],
    timeout: 60_000,
  },
  'CVE-2021-33044': {
    module: 'auxiliary/scanner/http/dahua_cve_2021_33044',
    type: 'auxiliary',
    options: {},
    vendors: ['dahua'],
    timeout: 60_000,
  },
};
