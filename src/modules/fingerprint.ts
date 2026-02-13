import { promises as fs } from 'node:fs';
import path from 'node:path';
import type {
  DiscoveredHost,
  FingerprintResult,
  CameraVendor,
  AuthType,
  ProtocolType,
} from '../types/index.js';
import { VENDOR_SIGNATURES } from '../constants.js';
import { httpGet, httpPost, rtspOptions, parseWwwAuthenticate } from '../utils/network.js';
import { parallelLimit } from '../utils/concurrency.js';

/**
 * Phase 2: Device Fingerprinting
 * Identifies camera vendor, model, firmware, and capabilities.
 */
export async function runFingerprinting(
  hosts: DiscoveredHost[],
  outputDir: string,
  concurrency: number = 10
): Promise<FingerprintResult[]> {
  const tasks = hosts.map((host) => () => fingerprintHost(host));
  const settled = await parallelLimit(tasks, concurrency);

  const results = settled
    .filter((r): r is PromiseFulfilledResult<FingerprintResult> => r.status === 'fulfilled')
    .map((r) => r.value);

  // Save deliverable
  const deliverablePath = path.join(outputDir, 'deliverables', 'fingerprint_results.json');
  await fs.mkdir(path.dirname(deliverablePath), { recursive: true });
  await fs.writeFile(deliverablePath, JSON.stringify(results, null, 2));

  return results;
}

async function fingerprintHost(host: DiscoveredHost): Promise<FingerprintResult> {
  const protocols: ProtocolType[] = [];
  let vendor: CameraVendor = 'unknown';
  let model = '';
  let firmware = '';
  let serverHeader = '';
  let authType: AuthType = 'unknown';
  let webInterface = false;
  let onvifSupported = false;
  let rawHeaders: Record<string, string> = {};

  // Determine if this is an RTSP port
  const isRtsp = [554, 8554, 8555, 10554].includes(host.port);
  const isHttp = !isRtsp;

  if (isHttp) {
    protocols.push(host.port === 443 || host.port === 8443 ? 'https' : 'http');
    const httpResult = await probeHttp(host);
    vendor = httpResult.vendor;
    model = httpResult.model;
    firmware = httpResult.firmware;
    serverHeader = httpResult.serverHeader;
    authType = httpResult.authType;
    webInterface = httpResult.webInterface;
    rawHeaders = httpResult.rawHeaders;

    // Check ONVIF on HTTP ports
    onvifSupported = await probeOnvif(host.ip, host.port);
    if (onvifSupported) protocols.push('onvif');
  }

  if (isRtsp) {
    protocols.push('rtsp');
    const rtspResult = await probeRtsp(host);
    if (vendor === 'unknown') vendor = rtspResult.vendor;
    if (!serverHeader) serverHeader = rtspResult.serverHeader;
  }

  // If we found an HTTP service, also check for RTSP on standard ports
  if (isHttp) {
    try {
      await rtspOptions(host.ip, 554, '/', undefined, 3000);
      if (!protocols.includes('rtsp')) protocols.push('rtsp');
    } catch { /* No RTSP on 554 */ }
  }

  return {
    ip: host.ip,
    port: host.port,
    vendor,
    model,
    firmware,
    protocols,
    serverHeader,
    authType,
    webInterface,
    onvifSupported,
    rawHeaders,
  };
}

interface HttpProbeResult {
  vendor: CameraVendor;
  model: string;
  firmware: string;
  serverHeader: string;
  authType: AuthType;
  webInterface: boolean;
  rawHeaders: Record<string, string>;
}

async function probeHttp(host: DiscoveredHost): Promise<HttpProbeResult> {
  const result: HttpProbeResult = {
    vendor: 'unknown',
    model: '',
    firmware: '',
    serverHeader: '',
    authType: 'unknown',
    webInterface: false,
    rawHeaders: {},
  };

  const scheme = [443, 8443].includes(host.port) ? 'https' : 'http';
  const baseUrl = `${scheme}://${host.ip}:${host.port}`;

  try {
    const response = await httpGet(baseUrl, { timeout: 8000, followRedirects: true });
    const headers = response.headers as Record<string, string>;
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');
    const status = response.status;

    result.rawHeaders = headers;
    result.serverHeader = headers['server'] || '';
    result.webInterface = status >= 200 && status < 500;

    // Determine auth type
    if (status === 401) {
      const wwwAuth = headers['www-authenticate'] || '';
      if (/digest/i.test(wwwAuth)) {
        result.authType = 'digest';
      } else if (/basic/i.test(wwwAuth)) {
        result.authType = 'basic';
      }
    } else if (status === 200) {
      if (/<form/i.test(body) && /(password|login|signin)/i.test(body)) {
        result.authType = 'form';
      } else {
        result.authType = 'none';
      }
    }

    // Match vendor from headers
    for (const sig of VENDOR_SIGNATURES) {
      for (const pattern of sig.headerPatterns) {
        if (pattern.test(result.serverHeader) || pattern.test(JSON.stringify(headers))) {
          result.vendor = sig.vendor;
          break;
        }
      }
      if (result.vendor !== 'unknown') break;
    }

    // Match vendor from body content
    if (result.vendor === 'unknown') {
      for (const sig of VENDOR_SIGNATURES) {
        for (const pattern of sig.bodyPatterns) {
          if (pattern.test(body)) {
            result.vendor = sig.vendor;
            break;
          }
        }
        if (result.vendor !== 'unknown') break;
      }
    }

    // Try vendor-specific endpoints to confirm & get model/firmware
    if (result.vendor !== 'unknown') {
      const details = await probeVendorDetails(baseUrl, result.vendor);
      if (details.model) result.model = details.model;
      if (details.firmware) result.firmware = details.firmware;
    }

    // Fallback: Try known vendor endpoints if still unknown
    if (result.vendor === 'unknown') {
      for (const sig of VENDOR_SIGNATURES) {
        for (const urlPattern of sig.urlPatterns) {
          try {
            const probeResp = await httpGet(`${baseUrl}${urlPattern}`, { timeout: 5000 });
            if (probeResp.status >= 200 && probeResp.status < 404) {
              result.vendor = sig.vendor;
              break;
            }
          } catch { /* skip */ }
        }
        if (result.vendor !== 'unknown') break;
      }
    }
  } catch (error) {
    // Host unreachable or SSL error
  }

  return result;
}

async function probeVendorDetails(
  baseUrl: string,
  vendor: CameraVendor
): Promise<{ model: string; firmware: string }> {
  const details = { model: '', firmware: '' };

  const endpoints: Record<string, string> = {
    hikvision: '/ISAPI/System/deviceInfo',
    dahua: '/cgi-bin/magicBox.cgi?action=getDeviceType',
    axis: '/axis-cgi/basicdeviceinfo.cgi',
    reolink: '/api.cgi?cmd=GetDevInfo',
    foscam: '/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo',
    uniview: '/LAPI/V1.0/System/DeviceInfo',
  };

  const endpoint = endpoints[vendor];
  if (!endpoint) return details;

  try {
    const resp = await httpGet(`${baseUrl}${endpoint}`, { timeout: 5000 });
    const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

    // Extract model
    const modelMatch = body.match(/(?:model|deviceType|DeviceType|deviceName)["\s:=]+([^"<,\n\r]+)/i);
    if (modelMatch) details.model = modelMatch[1].trim();

    // Extract firmware
    const fwMatch = body.match(/(?:firmware|firmwareVersion|version|FirmwareVersion)["\s:=]+([^"<,\n\r]+)/i);
    if (fwMatch) details.firmware = fwMatch[1].trim();
  } catch { /* endpoint not available */ }

  return details;
}

async function probeRtsp(host: DiscoveredHost): Promise<{ vendor: CameraVendor; serverHeader: string }> {
  let vendor: CameraVendor = 'unknown';
  let serverHeader = '';

  try {
    const result = await rtspOptions(host.ip, host.port);
    serverHeader = result.headers['server'] || '';

    // Match vendor from RTSP server header
    for (const sig of VENDOR_SIGNATURES) {
      for (const pattern of sig.headerPatterns) {
        if (pattern.test(serverHeader)) {
          vendor = sig.vendor;
          break;
        }
      }
      if (vendor !== 'unknown') break;
    }
  } catch { /* RTSP not responding */ }

  return { vendor, serverHeader };
}

async function probeOnvif(ip: string, port: number): Promise<boolean> {
  const soapEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>`;

  const scheme = [443, 8443].includes(port) ? 'https' : 'http';
  try {
    const resp = await httpPost(`${scheme}://${ip}:${port}/onvif/device_service`, soapEnvelope, {
      timeout: 5000,
      contentType: 'application/soap+xml',
    });
    const body = typeof resp.data === 'string' ? resp.data : '';
    return body.includes('onvif') || body.includes('GetDeviceInformationResponse') || resp.status === 401;
  } catch {
    return false;
  }
}
