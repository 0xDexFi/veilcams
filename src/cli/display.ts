import type { Severity } from '../types/index.js';

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
};

export function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return COLORS.bgRed + COLORS.bold;
    case 'high': return COLORS.red + COLORS.bold;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.blue;
    case 'info': return COLORS.gray;
  }
}

export function printSeverity(severity: Severity): string {
  return `${severityColor(severity)}${severity.toUpperCase()}${COLORS.reset}`;
}

export function printPhaseHeader(phase: string): void {
  console.log('');
  console.log(`${COLORS.cyan}${'─'.repeat(50)}${COLORS.reset}`);
  console.log(`${COLORS.cyan}${COLORS.bold}  Phase: ${phase.toUpperCase()}${COLORS.reset}`);
  console.log(`${COLORS.cyan}${'─'.repeat(50)}${COLORS.reset}`);
}

export function printModuleStart(module: string): void {
  console.log(`${COLORS.green}  [+]${COLORS.reset} Starting ${COLORS.bold}${module}${COLORS.reset}...`);
}

export function printModuleDone(module: string, durationMs: number): void {
  const seconds = Math.floor(durationMs / 1000);
  console.log(`${COLORS.green}  [+]${COLORS.reset} ${COLORS.bold}${module}${COLORS.reset} completed in ${seconds}s`);
}

export function printModuleFailed(module: string, error: string): void {
  console.log(`${COLORS.red}  [!]${COLORS.reset} ${COLORS.bold}${module}${COLORS.reset} FAILED: ${error}`);
}

export function printFinding(severity: Severity, message: string): void {
  console.log(`  ${printSeverity(severity)} ${message}`);
}

export function printSummary(stats: {
  hostsScanned: number;
  camerasFound: number;
  credsCompromised: number;
  cvesConfirmed: number;
  protocolFindings: number;
}): void {
  console.log('');
  console.log(`${COLORS.cyan}╔══════════════════════════════════════════╗${COLORS.reset}`);
  console.log(`${COLORS.cyan}║         Scan Summary                     ║${COLORS.reset}`);
  console.log(`${COLORS.cyan}╚══════════════════════════════════════════╝${COLORS.reset}`);
  console.log(`  Hosts Scanned:          ${stats.hostsScanned}`);
  console.log(`  Cameras Identified:     ${stats.camerasFound}`);
  console.log(`  Credentials Found:      ${COLORS.red}${stats.credsCompromised}${COLORS.reset}`);
  console.log(`  CVEs Confirmed:         ${COLORS.red}${stats.cvesConfirmed}${COLORS.reset}`);
  console.log(`  Protocol Findings:      ${stats.protocolFindings}`);
  console.log('');
}
