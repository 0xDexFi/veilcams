import type { CameraVendor } from './types/index.js';

// ─── Metasploit Module Mapping ───────────────────────────────────
//
// Maps confirmed CVE IDs to their corresponding Metasploit modules.
// Used by the exploitation module to auto-exploit confirmed vulns.

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
