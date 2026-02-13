import type { ModuleName, PhaseName, CameraVendor, Credential } from './types/index.js';

// ─── Camera Ports ────────────────────────────────────────────────

export const CAMERA_PORTS = {
  HTTP: [80, 8080, 8081, 8888, 81, 82, 85, 9000],
  HTTPS: [443, 8443],
  RTSP: [554, 8554, 8555, 10554],
  ONVIF: [80, 8080, 2020],
  TELNET: [23],
  SSH: [22],
} as const;

export const ALL_CAMERA_PORTS = [
  ...new Set([
    ...CAMERA_PORTS.HTTP,
    ...CAMERA_PORTS.HTTPS,
    ...CAMERA_PORTS.RTSP,
    ...CAMERA_PORTS.ONVIF,
    ...CAMERA_PORTS.TELNET,
    ...CAMERA_PORTS.SSH,
  ]),
].sort((a, b) => a - b);

// ─── Module Definitions ─────────────────────────────────────────

export const MODULE_PHASE_MAP: Record<ModuleName, PhaseName> = {
  'discovery': 'discovery',
  'fingerprint': 'fingerprinting',
  'credential-tester': 'testing',
  'cve-scanner': 'testing',
  'protocol-fuzzer': 'testing',
  'exploitation': 'exploitation',
  'report': 'reporting',
};

export const MODULE_ORDER: ModuleName[] = [
  'discovery',
  'fingerprint',
  'credential-tester',
  'cve-scanner',
  'protocol-fuzzer',
  'exploitation',
  'report',
];

export const PARALLEL_MODULES: ModuleName[] = [
  'credential-tester',
  'cve-scanner',
  'protocol-fuzzer',
];

// ─── Vendor Fingerprints ────────────────────────────────────────

export interface VendorSignature {
  vendor: CameraVendor;
  headerPatterns: RegExp[];
  bodyPatterns: RegExp[];
  urlPatterns: string[];
}

export const VENDOR_SIGNATURES: VendorSignature[] = [
  {
    vendor: 'hikvision',
    headerPatterns: [
      /DNVRS-Webs/i,
      /App-webs/i,
      /DVRDVS-Webs/i,
      /Hikvision/i,
      /webserver/i,
    ],
    bodyPatterns: [
      /hikvision/i,
      /ISAPI/i,
      /doc\/page\/login\.asp/i,
      /Hik-Connect/i,
      /DS-\d+/i,
    ],
    urlPatterns: [
      '/ISAPI/System/deviceInfo',
      '/SDK/activateStatus',
      '/doc/page/login.asp',
    ],
  },
  {
    vendor: 'dahua',
    headerPatterns: [
      /DH-NVR/i,
      /DHI-/i,
      /Dahua/i,
      /DahuaRtsp/i,
    ],
    bodyPatterns: [
      /dahua/i,
      /DH-/i,
      /DHI-/i,
      /IPC-HDW/i,
      /IPC-HFW/i,
      /loginEx2/i,
    ],
    urlPatterns: [
      '/RPC2_Login',
      '/cgi-bin/magicBox.cgi?action=getDeviceType',
      '/cgi-bin/configManager.cgi',
    ],
  },
  {
    vendor: 'axis',
    headerPatterns: [
      /AXIS/i,
      /Boa\/\d/i,
    ],
    bodyPatterns: [
      /axis/i,
      /AXIS\s/i,
      /axis-cgi/i,
      /vapix/i,
    ],
    urlPatterns: [
      '/axis-cgi/param.cgi',
      '/axis-cgi/basicdeviceinfo.cgi',
      '/vapix/getStatus.cgi',
    ],
  },
  {
    vendor: 'reolink',
    headerPatterns: [
      /Reolink/i,
    ],
    bodyPatterns: [
      /reolink/i,
      /Reolink/i,
      /RLC-/i,
      /RLN-/i,
    ],
    urlPatterns: [
      '/api.cgi?cmd=Login',
      '/cgi-bin/api.cgi',
    ],
  },
  {
    vendor: 'amcrest',
    headerPatterns: [
      /Amcrest/i,
    ],
    bodyPatterns: [
      /amcrest/i,
      /Amcrest/i,
      /IP\d[A-Z]/i,
    ],
    urlPatterns: [
      '/RPC2_Login',
      '/cgi-bin/magicBox.cgi',
    ],
  },
  {
    vendor: 'foscam',
    headerPatterns: [
      /Foscam/i,
      /JAWS\/\d/i,
    ],
    bodyPatterns: [
      /foscam/i,
      /Foscam/i,
      /IPCam/i,
    ],
    urlPatterns: [
      '/cgi-bin/CGIProxy.fcgi',
      '/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo',
    ],
  },
  {
    vendor: 'tp-link',
    headerPatterns: [
      /TP-LINK/i,
    ],
    bodyPatterns: [
      /tp-link/i,
      /TP-LINK/i,
      /Tapo/i,
      /VIGI/i,
    ],
    urlPatterns: [
      '/stok=',
    ],
  },
  {
    vendor: 'uniview',
    headerPatterns: [
      /Uniview/i,
      /UNV/i,
    ],
    bodyPatterns: [
      /uniview/i,
      /UNV/i,
      /IPC-[A-Z]/i,
    ],
    urlPatterns: [
      '/LAPI/V1.0/System/DeviceInfo',
    ],
  },
  {
    vendor: 'vivotek',
    headerPatterns: [
      /Vivotek/i,
      /Boa\/0\.\d/i,
    ],
    bodyPatterns: [
      /vivotek/i,
      /VIVOTEK/i,
      /FD\d+/i,
    ],
    urlPatterns: [
      '/cgi-bin/viewer/getparam.cgi',
      '/cgi-bin/admin/getparam.cgi',
    ],
  },
  {
    vendor: 'hanwha',
    headerPatterns: [
      /Hanwha/i,
      /Samsung/i,
      /Techwin/i,
    ],
    bodyPatterns: [
      /hanwha/i,
      /Wisenet/i,
      /XNV-/i,
      /XND-/i,
    ],
    urlPatterns: [
      '/stw-cgi/',
    ],
  },
  {
    vendor: 'bosch',
    headerPatterns: [
      /Bosch/i,
    ],
    bodyPatterns: [
      /bosch/i,
      /Bosch/i,
      /DINION/i,
      /FLEXIDOME/i,
    ],
    urlPatterns: [
      '/rcp.xml',
    ],
  },
];

// ─── Default Credentials ────────────────────────────────────────

export const DEFAULT_CREDENTIALS: Record<CameraVendor, Credential[]> = {
  hikvision: [
    { username: 'admin', password: '12345' },
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'Admin12345' },
    { username: 'admin', password: 'hiklinux' },
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: 'password' },
  ],
  dahua: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: '' },
    { username: 'admin', password: '123456' },
    { username: '888888', password: '888888' },
    { username: 'default', password: 'default' },
  ],
  axis: [
    { username: 'root', password: 'root' },
    { username: 'root', password: 'pass' },
    { username: 'root', password: '' },
    { username: 'admin', password: 'admin' },
    { username: 'operator', password: 'operator' },
  ],
  reolink: [
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '123456' },
  ],
  amcrest: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: '' },
  ],
  foscam: [
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'foscam' },
  ],
  'tp-link': [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '2211' },
    { username: 'admin', password: '' },
  ],
  uniview: [
    { username: 'admin', password: '123456' },
    { username: 'admin', password: 'admin' },
  ],
  vivotek: [
    { username: 'root', password: '' },
    { username: 'root', password: 'root' },
    { username: 'admin', password: 'admin' },
  ],
  hanwha: [
    { username: 'admin', password: '4321' },
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '' },
  ],
  bosch: [
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin' },
    { username: 'service', password: 'service' },
  ],
  unknown: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '' },
    { username: 'admin', password: '12345' },
    { username: 'admin', password: '123456' },
    { username: 'admin', password: 'password' },
    { username: 'root', password: 'root' },
    { username: 'root', password: '' },
    { username: 'user', password: 'user' },
    { username: 'admin', password: '1234' },
    { username: 'admin', password: 'admin123' },
  ],
};

// ─── RTSP Paths ─────────────────────────────────────────────────

export const RTSP_PATHS: Record<CameraVendor, string[]> = {
  hikvision: [
    '/Streaming/Channels/101',
    '/Streaming/Channels/102',
    '/Streaming/Channels/201',
    '/h264/ch1/main/av_stream',
    '/h264/ch1/sub/av_stream',
    '/ISAPI/Streaming/channels/101',
  ],
  dahua: [
    '/cam/realmonitor?channel=1&subtype=0',
    '/cam/realmonitor?channel=1&subtype=1',
    '/live',
    '/MediaInput/h264',
  ],
  axis: [
    '/axis-media/media.amp',
    '/mpeg4/media.amp',
    '/mjpg/video.mjpg',
    '/axis-media/media.amp?videocodec=h264',
  ],
  reolink: [
    '/h264Preview_01_main',
    '/h264Preview_01_sub',
    '/Preview_01_main',
  ],
  amcrest: [
    '/cam/realmonitor?channel=1&subtype=0',
    '/cam/realmonitor?channel=1&subtype=1',
  ],
  foscam: [
    '/videoMain',
    '/videoSub',
    '/video1',
  ],
  'tp-link': [
    '/stream1',
    '/stream2',
  ],
  uniview: [
    '/unicast/c1/s0/live',
    '/unicast/c1/s1/live',
  ],
  vivotek: [
    '/live.sdp',
    '/live2.sdp',
    '/video.mp4',
  ],
  hanwha: [
    '/profile2/media.smp',
    '/profile1/media.smp',
  ],
  bosch: [
    '/rtsp_tunnel',
    '/video',
  ],
  unknown: [
    '/live',
    '/stream',
    '/stream1',
    '/ch1',
    '/ch01.264',
    '/0',
    '/1',
    '/video',
    '/media/video1',
    '/live/ch0',
    '/live/ch1',
    '/live.sdp',
    '/h264',
    '/mpeg4',
    '/cam1',
  ],
};

// ─── Snapshot Endpoints ─────────────────────────────────────────

export const SNAPSHOT_ENDPOINTS: Record<CameraVendor, string[]> = {
  hikvision: [
    '/ISAPI/Streaming/channels/101/picture',
    '/Streaming/channels/1/picture',
    '/cgi-bin/snapshot.cgi',
    '/snap.jpg',
  ],
  dahua: [
    '/cgi-bin/snapshot.cgi',
    '/cgi-bin/snapshot.cgi?channel=1',
    '/snap.jpg',
  ],
  axis: [
    '/axis-cgi/jpg/image.cgi',
    '/axis-cgi/bitmap/image.bmp',
    '/jpg/image.jpg',
  ],
  reolink: [
    '/cgi-bin/api.cgi?cmd=Snap&channel=0',
    '/snap.jpg',
  ],
  amcrest: [
    '/cgi-bin/snapshot.cgi',
    '/snap.jpg',
  ],
  foscam: [
    '/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2',
    '/snapshot.cgi',
  ],
  'tp-link': [
    '/snap.jpg',
    '/stream/snapshot.jpg',
  ],
  uniview: [
    '/LAPI/V1.0/Channels/0/Media/Video/Streams/0/snapshot',
    '/snap.jpg',
  ],
  vivotek: [
    '/cgi-bin/viewer/video.jpg',
    '/video.jpg',
  ],
  hanwha: [
    '/stw-cgi/video.cgi?msubmenu=snapshot',
    '/snap.jpg',
  ],
  bosch: [
    '/snap.jpg',
    '/snapshot.jpg',
  ],
  unknown: [
    '/snap.jpg',
    '/snapshot.jpg',
    '/snapshot.cgi',
    '/cgi-bin/snapshot.cgi',
    '/image.jpg',
    '/image/jpeg.cgi',
    '/tmpfs/auto.jpg',
    '/webcapture.jpg',
  ],
};

// ─── Config Disclosure Paths ────────────────────────────────────

export const CONFIG_DISCLOSURE_PATHS = [
  '/system.ini',
  '/config/overlay.xml',
  '/System/configurationFile?auth=YWRtaW46MTEK',
  '/conf/gateway',
  '/cgi-bin/configManager.cgi?action=getConfig&name=All',
  '/device.rsp?opt=user&cmd=list',
  '/goform/WEB_VMS_GET_CONFIG',
  '/config/system.ini',
  '/backup/config.bin',
  '/.htpasswd',
  '/etc/passwd',
  '/etc/shadow',
  '/proc/kcore',
  '/current_config/passwd',
  '/users.cgi',
  '/credentials.json',
  '/config/config.json',
];

// ─── Timing & Rate Limits ───────────────────────────────────────

export const DEFAULTS = {
  MAX_CONCURRENT_HOSTS: 10,
  REQUESTS_PER_SECOND: 5,
  REQUEST_TIMEOUT_MS: 10_000,
  CREDENTIAL_DELAY_MS: 1_000,
  MAX_ATTEMPTS_PER_HOST: 15,
  RTSP_TIMEOUT_MS: 5_000,
  ONVIF_TIMEOUT_MS: 8_000,
  HEARTBEAT_INTERVAL_MS: 2_000,
  TEMPORAL_RETRY_BACKOFF_MIN_MS: 300_000,
  TEMPORAL_RETRY_BACKOFF_MAX_MS: 1_800_000,
  TEMPORAL_MAX_ATTEMPTS: 30,
  TESTING_RETRY_BACKOFF_MIN_MS: 10_000,
  TESTING_RETRY_BACKOFF_MAX_MS: 30_000,
  TESTING_MAX_ATTEMPTS: 3,
  AI_PROTOCOL_MAX_PATHS_PER_HOST: 30,
  EXPLOITATION_TIMEOUT_MS: 60_000,
} as const;
