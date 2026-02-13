import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import https from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { DEFAULTS } from '../constants.js';

// Camera-grade HTTPS agent: accept self-signed certificates
const permissiveAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * HTTP GET with configurable timeout. Accepts self-signed certs.
 */
export async function httpGet(
  url: string,
  options: {
    timeout?: number;
    auth?: { username: string; password: string };
    headers?: Record<string, string>;
    followRedirects?: boolean;
    validateStatus?: (status: number) => boolean;
  } = {}
): Promise<AxiosResponse> {
  const config: AxiosRequestConfig = {
    url,
    method: 'GET',
    timeout: options.timeout ?? DEFAULTS.REQUEST_TIMEOUT_MS,
    maxRedirects: options.followRedirects ? 5 : 0,
    validateStatus: options.validateStatus ?? (() => true),
    httpsAgent: permissiveAgent,
    headers: {
      'User-Agent': 'VeilCams/1.0 Security-Scanner',
      ...options.headers,
    },
  };

  if (options.auth) {
    config.auth = options.auth;
  }

  return axios(config);
}

/**
 * HTTP request with arbitrary method and body. Accepts self-signed certs.
 */
export async function httpRequest(
  url: string,
  method: string,
  body: unknown,
  options: {
    timeout?: number;
    auth?: { username: string; password: string };
    headers?: Record<string, string>;
    contentType?: string;
  } = {}
): Promise<AxiosResponse> {
  const config: AxiosRequestConfig = {
    url,
    method: method.toUpperCase(),
    timeout: options.timeout ?? DEFAULTS.REQUEST_TIMEOUT_MS,
    data: body,
    validateStatus: () => true,
    httpsAgent: permissiveAgent,
    headers: {
      'User-Agent': 'VeilCams/1.0 Security-Scanner',
      'Content-Type': options.contentType ?? 'application/json',
      ...options.headers,
    },
  };

  if (options.auth) {
    config.auth = options.auth;
  }

  return axios(config);
}

/**
 * HTTP POST — convenience wrapper around httpRequest.
 */
export async function httpPost(
  url: string,
  body: unknown,
  options: {
    timeout?: number;
    auth?: { username: string; password: string };
    headers?: Record<string, string>;
    contentType?: string;
  } = {}
): Promise<AxiosResponse> {
  return httpRequest(url, 'POST', body, options);
}

/**
 * Compute HTTP Digest auth response.
 * Handles both MD5 and MD5-sess algorithms correctly.
 */
export function computeDigestAuth(params: {
  username: string;
  password: string;
  method: string;
  uri: string;
  realm: string;
  nonce: string;
  qop?: string;
  nc?: string;
  cnonce?: string;
  algorithm?: string;
}): string {
  const { username, password, method, uri, realm, nonce, algorithm } = params;
  const qop = params.qop || '';
  const nc = params.nc || '00000001';
  const cnonce = params.cnonce || randomBytes(8).toString('hex');

  const isMd5Sess = algorithm?.toLowerCase() === 'md5-sess';

  // HA1: For MD5-sess, HA1 = MD5(MD5(user:realm:pass):nonce:cnonce)
  let ha1 = createHash('md5').update(`${username}:${realm}:${password}`).digest('hex');
  if (isMd5Sess) {
    ha1 = createHash('md5').update(`${ha1}:${nonce}:${cnonce}`).digest('hex');
  }

  const ha2 = createHash('md5').update(`${method}:${uri}`).digest('hex');

  let response: string;
  if (qop === 'auth' || qop === 'auth-int') {
    response = createHash('md5')
      .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      .digest('hex');
  } else {
    response = createHash('md5')
      .update(`${ha1}:${nonce}:${ha2}`)
      .digest('hex');
  }

  let header = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;
  if (qop) header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (algorithm) header += `, algorithm=${algorithm}`;

  return header;
}

/**
 * Parse WWW-Authenticate header for digest params.
 * Handles both quoted and unquoted values, including comma-separated qop.
 */
export function parseWwwAuthenticate(header: string): Record<string, string> {
  const params: Record<string, string> = {};
  const type = header.split(' ')[0].toLowerCase();
  params.type = type;

  const rest = header.substring(type.length).trim();
  const regex = /(\w+)=(?:"([^"]*)"|([\w.,_-]+))/g;
  let match;
  while ((match = regex.exec(rest)) !== null) {
    params[match[1]] = match[2] ?? match[3];
  }

  return params;
}

/**
 * Test RTSP connectivity with OPTIONS request.
 * Properly handles socket cleanup to prevent double-rejection and leaks.
 */
export async function rtspOptions(
  host: string,
  port: number,
  path: string = '/',
  auth?: { username: string; password: string },
  timeout: number = DEFAULTS.RTSP_TIMEOUT_MS
): Promise<{ statusCode: number; headers: Record<string, string>; raw: string }> {
  const { createConnection } = await import('node:net');

  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn: typeof resolve | typeof reject, value: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      (fn as (v: unknown) => void)(value);
    };

    const socket = createConnection({ host, port, timeout }, () => {
      let request = `OPTIONS rtsp://${host}:${port}${path} RTSP/1.0\r\nCSeq: 1\r\n`;
      if (auth) {
        const encoded = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
        request += `Authorization: Basic ${encoded}\r\n`;
      }
      request += `\r\n`;
      socket.write(request);
    });

    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (data.includes('\r\n\r\n')) {
        const lines = data.split('\r\n');
        const statusLine = lines[0] || '';
        const statusMatch = statusLine.match(/RTSP\/\d\.\d\s+(\d+)/);
        const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;

        const headers: Record<string, string> = {};
        for (let i = 1; i < lines.length; i++) {
          const colonIdx = lines[i].indexOf(':');
          if (colonIdx > 0) {
            const key = lines[i].substring(0, colonIdx).trim().toLowerCase();
            const value = lines[i].substring(colonIdx + 1).trim();
            headers[key] = value;
          }
        }

        settle(resolve, { statusCode, headers, raw: data });
      }
    });

    socket.on('timeout', () => {
      settle(reject, new Error(`RTSP timeout connecting to ${host}:${port}`));
    });

    socket.on('error', (err) => {
      settle(reject, err);
    });

    const timer = setTimeout(() => {
      settle(reject, new Error(`RTSP timeout after ${timeout}ms`));
    }, timeout);
  });
}

/**
 * Test RTSP DESCRIBE to check if a stream path is valid.
 * Properly handles socket cleanup to prevent double-rejection and leaks.
 */
export async function rtspDescribe(
  host: string,
  port: number,
  streamPath: string,
  auth?: { username: string; password: string },
  timeout: number = DEFAULTS.RTSP_TIMEOUT_MS
): Promise<{ statusCode: number; raw: string }> {
  const { createConnection } = await import('node:net');

  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn: typeof resolve | typeof reject, value: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      (fn as (v: unknown) => void)(value);
    };

    const socket = createConnection({ host, port, timeout }, () => {
      let request = `DESCRIBE rtsp://${host}:${port}${streamPath} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n`;
      if (auth) {
        const encoded = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
        request += `Authorization: Basic ${encoded}\r\n`;
      }
      request += `\r\n`;
      socket.write(request);
    });

    let data = '';
    let bodyTimer: ReturnType<typeof setTimeout> | null = null;

    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (data.includes('\r\n\r\n') && !bodyTimer) {
        // Brief wait for body data, then resolve
        bodyTimer = setTimeout(() => {
          const statusMatch = data.match(/RTSP\/\d\.\d\s+(\d+)/);
          const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : 0;
          settle(resolve, { statusCode, raw: data });
        }, 150);
      }
    });

    socket.on('timeout', () => {
      if (bodyTimer) clearTimeout(bodyTimer);
      settle(reject, new Error(`RTSP DESCRIBE timeout for ${streamPath}`));
    });

    socket.on('error', (err) => {
      if (bodyTimer) clearTimeout(bodyTimer);
      settle(reject, err);
    });

    const timer = setTimeout(() => {
      if (bodyTimer) clearTimeout(bodyTimer);
      settle(reject, new Error(`RTSP DESCRIBE timeout after ${timeout}ms`));
    }, timeout);
  });
}
