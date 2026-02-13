import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parseString } from 'xml2js';
import type { TargetSpec, DiscoveredHost, DiscoveryResult } from '../types/index.js';
import { ALL_CAMERA_PORTS } from '../constants.js';

/**
 * Phase 1: Network Discovery
 * Uses nmap to scan targets for open camera-related ports.
 */
export async function runDiscovery(
  targets: TargetSpec[],
  outputDir: string
): Promise<DiscoveryResult> {
  const startTime = Date.now();
  const allHosts: DiscoveredHost[] = [];
  let targetsScanned = 0;

  for (const target of targets) {
    const targetStr = target.range || target.host!;
    const ports = target.ports.length > 0 ? target.ports : ALL_CAMERA_PORTS;
    const isUserSpecifiedPorts = target.host && target.ports.length > 0 && target.ports.length <= 10;
    targetsScanned++;

    // If user specified exact ports on a single host, trust them and skip nmap
    if (isUserSpecifiedPorts) {
      console.log(`[discovery] User specified ports for ${targetStr}: ${ports.join(',')} — skipping nmap, using direct`);
      for (const port of ports) {
        allHosts.push({
          ip: target.host!,
          port,
          service: port === 554 || port === 8554 || port === 8555 || port === 10554 ? 'rtsp' : 'http',
          banner: '',
          state: 'open',
        });
      }
      continue;
    }

    try {
      const hosts = await nmapScan(targetStr, ports, outputDir);
      // If nmap returned nothing, fall back to TCP connect scan
      if (hosts.length === 0 && !targetStr.includes('/')) {
        console.log(`[discovery] nmap found no open ports on ${targetStr}, trying TCP connect fallback...`);
        const tcpHosts = await tcpConnectScan(targetStr, ports);
        allHosts.push(...tcpHosts);
      } else {
        allHosts.push(...hosts);
      }
    } catch (error) {
      console.error(`[discovery] nmap scan failed for ${targetStr}: ${error}`);
      // Fallback to TCP connect scan
      const hosts = await tcpConnectScan(targetStr, ports);
      allHosts.push(...hosts);
    }
  }

  const result: DiscoveryResult = {
    hosts: deduplicateHosts(allHosts),
    scanDurationMs: Date.now() - startTime,
    targetsScanned,
  };

  // Save deliverable
  const deliverablePath = path.join(outputDir, 'deliverables', 'discovery_results.json');
  await fs.mkdir(path.dirname(deliverablePath), { recursive: true });
  await fs.writeFile(deliverablePath, JSON.stringify(result, null, 2));

  return result;
}

async function nmapScan(target: string, ports: number[], outputDir: string): Promise<DiscoveredHost[]> {
  const xmlFile = path.join(os.tmpdir(), `veilcams-nmap-${Date.now()}.xml`);
  const portStr = ports.join(',');

  const args = [
    '-sV',                    // Service version detection
    '--version-intensity', '5',
    '-p', portStr,
    '-T4',                    // Aggressive timing
    '--open',                 // Only show open ports
    '-oX', xmlFile,           // XML output
    '--host-timeout', '60s',
    target,
  ];

  await runCommand('nmap', args);

  const xmlContent = await fs.readFile(xmlFile, 'utf-8');
  const hosts = await parseNmapXml(xmlContent);

  // Clean up
  await fs.unlink(xmlFile).catch(() => {});

  return hosts;
}

function parseNmapXml(xml: string): Promise<DiscoveredHost[]> {
  return new Promise((resolve, reject) => {
    parseString(xml, (err, result) => {
      if (err) return reject(err);

      const hosts: DiscoveredHost[] = [];
      const nmapRun = result?.nmaprun;
      if (!nmapRun?.host) return resolve(hosts);

      const hostEntries = Array.isArray(nmapRun.host) ? nmapRun.host : [nmapRun.host];

      for (const host of hostEntries) {
        const addrEntry = Array.isArray(host.address) ? host.address[0] : host.address;
        const ip = addrEntry?.$?.addr || '';
        if (!ip) continue;

        const portsSection = host.ports?.[0];
        if (!portsSection?.port) continue;

        const portEntries = Array.isArray(portsSection.port) ? portsSection.port : [portsSection.port];

        for (const port of portEntries) {
          const state = port.state?.[0]?.$?.state;
          if (state !== 'open') continue;

          const portNum = parseInt(port.$?.portid, 10);
          const service = port.service?.[0];
          const serviceName = service?.$?.name || 'unknown';
          const product = service?.$?.product || '';
          const version = service?.$?.version || '';
          const banner = [product, version].filter(Boolean).join(' ').trim() || serviceName;

          hosts.push({
            ip,
            port: portNum,
            service: serviceName,
            banner,
            state: 'open',
          });
        }
      }

      resolve(hosts);
    });
  });
}

/**
 * Fallback: raw TCP connect scan when nmap is unavailable.
 */
async function tcpConnectScan(target: string, ports: number[]): Promise<DiscoveredHost[]> {
  const { createConnection } = await import('node:net');
  const hosts: DiscoveredHost[] = [];

  // Resolve target to IPs (simple single-host case)
  const ips = target.includes('/') ? [] : [target]; // CIDR not supported in fallback
  if (ips.length === 0) {
    console.warn(`[discovery] TCP fallback does not support CIDR ranges: ${target}`);
    return hosts;
  }

  for (const ip of ips) {
    for (const port of ports) {
      try {
        await new Promise<void>((resolve, reject) => {
          const socket = createConnection({ host: ip, port, timeout: 3000 }, () => {
            hosts.push({
              ip,
              port,
              service: 'unknown',
              banner: '',
              state: 'open',
            });
            socket.destroy();
            resolve();
          });
          socket.on('error', () => {
            socket.destroy();
            reject();
          });
          socket.on('timeout', () => {
            socket.destroy();
            reject();
          });
        });
      } catch {
        // Port closed or filtered, skip
      }
    }
  }

  return hosts;
}

function runCommand(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`${command} exited with code ${code}: ${stderr}`));
      }
    });

    proc.on('error', (err) => {
      reject(new Error(`Failed to spawn ${command}: ${err.message}`));
    });
  });
}

function deduplicateHosts(hosts: DiscoveredHost[]): DiscoveredHost[] {
  const seen = new Set<string>();
  return hosts.filter((host) => {
    const key = `${host.ip}:${host.port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
