import { useEffect, useMemo, useRef, useState } from 'react';
import './index.css';

type Client = 'trusted' | 'untrusted' | 'mgmt';
type Backend = 'client' | 'lab_api';

type ResolverKind = 'valid' | 'plain';
type SectionId =
  | 'all'
  | 'overview'
  | 'topology'
  | 'dig'
  | 'output'
  | 'dnssec'
  | 'privacy'
  | 'availability'
  | 'perf'
  | 'limits'
  | 'amplification'
  | 'controls'
  | 'configs'
  | 'capture';

type DigRequest = {
  client: Client;
  resolver: ResolverKind;
  name: string;
  qtype: string;
  dnssec: boolean;
  trace: boolean;
  short: boolean;
};

type ClientDigResponse = {
  ok: boolean;
  ad: boolean;
  cmd: string[];
  output: string;
};

type LabDigResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type MaintenanceResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type OutputView = {
  ok: boolean;
  command: string;
  text: string;
};

type ConfigGroup = 'authoritative' | 'resolver';
type ConfigServer = 'child' | 'parent' | 'resolver' | 'plain';
type PrivacyTab = 'overview' | 'dot' | 'doh' | 'logs';

type ConfigFile = {
  path: string;
  size: number;
};

type ConfigListResponse = {
  ok: boolean;
  files: ConfigFile[];
};

type ConfigFileResponse = {
  ok: boolean;
  path: string;
  size: number;
  truncated: boolean;
  content: string;
};

type StartupDiagnosticsResponse = {
  ok: boolean;
  issues: string[];
  details: Record<string, string>;
};

type IndicatorState = {
  loading: boolean;
  message: string;
  nsec3Child?: boolean;
  nsec3Parent?: boolean;
  aggressiveNsec?: boolean;
  qnameMinim?: boolean;
  childDetail?: string;
  parentDetail?: string;
  aggressiveDetail?: string;
  qnameDetail?: string;
  updatedAt?: string;
};

type CaptureTarget = 'resolver' | 'authoritative';
type CaptureFilter = 'dns' | 'dns+dot' | 'all';

type CaptureFile = {
  file: string;
  size: number;
  mtime: string;
  target: CaptureTarget;
};

type CaptureListResponse = {
  ok: boolean;
  files: CaptureFile[];
  running: Record<CaptureTarget, boolean>;
};

type CaptureStartResponse = {
  ok: boolean;
  target: CaptureTarget;
  file: string;
  filter: CaptureFilter;
  command: string;
};

type CaptureStopResponse = {
  ok: boolean;
  target: CaptureTarget;
  file?: string;
};

type CaptureSummaryResponse = {
  ok: boolean;
  file: string;
  target: CaptureTarget;
  total_packets: number;
  upstream_queries: number;
  command_total: string;
  command_upstream: string;
  stdout_total: string;
  stdout_upstream: string;
  stderr_total: string;
  stderr_upstream: string;
};

type CaptureHealthResponse = {
  ok: boolean;
  target: CaptureTarget;
  running: boolean;
  pid?: number;
  detail?: string;
};

type SigningSwitchRequest = {
  mode: 'nsec' | 'nsec3';
};

type SigningStep = {
  step: string;
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type SigningSwitchResponse = {
  ok: boolean;
  mode: 'nsec' | 'nsec3';
  steps: SigningStep[];
};

type PrivacyCheckResponse = {
  ok: boolean;
  kind: 'dot' | 'doh';
  endpoint: string;
  method: string;
  name: string;
  qtype: string;
  rcode?: string;
  response_bytes: number;
  elapsed_ms: number;
  detail?: string;
};

type AvailabilityMetricsResponse = {
  ok: boolean;
  totals: {
    queries: number;
    cache_hits: number;
    cache_miss: number;
    nxdomain: number;
    servfail: number;
    ratelimited: number;
    ip_ratelimited: number;
  };
  ratios: {
    nxdomain: number;
    servfail: number;
    cache_hit: number;
    ratelimited: number;
    ip_ratelimited: number;
  };
  avg_recursion_ms: number;
  raw: string;
};

type AvailabilityProbeRequest = {
  profile: Client;
  resolver: ResolverKind;
  name: string;
  qtype: string;
  count: number;
};

type AvailabilityProbeResponse = {
  ok: boolean;
  target: string;
  name: string;
  qtype: string;
  count: number;
  min_ms: number;
  max_ms: number;
  avg_ms: number;
  p50_ms?: number;
  p95_ms?: number;
  rcode_counts: Record<string, number>;
};

type ResolverStatsResponse = {
  ok: boolean;
  resolver: ResolverKind;
  container: string;
  cpu_pct?: number;
  mem_bytes?: number;
  mem_limit_bytes?: number;
  mem_pct?: number;
};

type BaselineSummary = {
  duration_s: number;
  qps: number;
  total_queries: number;
  cache_hit_ratio: number;
  nxdomain_ratio: number;
  servfail_ratio: number;
  p50_ms: number;
  p95_ms: number;
  cpu_pct?: number;
  mem_mb?: number;
  mem_pct?: number;
  upstream_qps?: number;
  upstream_queries?: number;
  capture_file?: string;
};

type AvailabilityLoadRequest = {
  profile: Client;
  resolver: ResolverKind;
  name: string;
  qtype: string;
  count: number;
  qps: number;
};

type AvailabilityLoadResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type FloodTestRequest = {
  profile: Client;
  resolver: ResolverKind;
  name: string;
  qtype: string;
  qps_start: number;
  qps_end: number;
  qps_step: number;
  step_seconds: number;
  max_outstanding: number;
  timeout_ms: number;
  stop_loss_pct: number;
  stop_p95_ms: number;
  stop_servfail_pct: number;
  stop_cpu_pct: number;
};

type FloodStepResult = {
  step: number;
  qps: number;
  actual_qps: number;
  duration_s: number;
  sent: number;
  responses: number;
  timeouts: number;
  loss_pct: number;
  rcode_counts: Record<string, number>;
  avg_ms: number;
  p95_ms: number;
  max_ms: number;
  servfail_pct: number;
  cpu_pct?: number;
  stop_reason?: string;
};

type FloodTestResponse = {
  ok: boolean;
  target: string;
  name: string;
  qtype: string;
  steps: FloodStepResult[];
  stopped_early: boolean;
  stop_reason?: string;
};

type RrlTestRequest = {
  name: string;
  qtype: string;
  count: number;
  log_tail: number;
};

type RrlTestResponse = {
  ok: boolean;
  rrl_enabled: boolean;
  config_excerpt: string;
  log_excerpt: string;
  matches: string[];
};

type AmplificationTestRequest = {
  profile: Client;
  resolver: ResolverKind;
  name: string;
  qtypes: string[];
  edns_sizes: number[];
  count_per_qtype: number;
  dnssec: boolean;
  tcp_fallback: boolean;
};

type AmplificationResult = {
  edns_size: number;
  qtype: string;
  count: number;
  rcode_counts: Record<string, number>;
  tc_rate: number;
  tcp_rate: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  avg_udp_size: number;
  max_udp_size: number;
  avg_tcp_size: number;
  max_tcp_size: number;
};

type AmplificationTestResponse = {
  ok: boolean;
  target: string;
  name: string;
  results: AmplificationResult[];
};

type MixLoadRequest = {
  profile: Client;
  resolver: ResolverKind;
  zone: string;
  count: number;
  edns_size: number;
  dnssec: boolean;
  tcp_fallback: boolean;
};

type MixLoadResponse = {
  ok: boolean;
  target: string;
  count: number;
  edns_size: number;
  rcode_counts: Record<string, number>;
  query_mix: Record<string, number>;
  tc_rate: number;
  tcp_rate: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  avg_udp_size: number;
  max_udp_size: number;
  avg_tcp_size: number;
  max_tcp_size: number;
};

type PerfTarget =
  | 'resolver_valid'
  | 'resolver_plain'
  | 'authoritative_parent'
  | 'authoritative_child';

type DnsperfRequest = {
  target: PerfTarget;
  duration_s: number;
  qps: number;
  max_queries: number;
  threads: number;
  clients: number;
  queries?: string;
};

type DnsperfSummary = {
  queries_sent?: number;
  queries_completed?: number;
  queries_lost?: number;
  qps?: number;
  avg_latency_ms?: number;
  min_latency_ms?: number;
  max_latency_ms?: number;
};

type DnsperfResponse = {
  ok: boolean;
  target: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  summary?: DnsperfSummary | null;
};

type ResperfRequest = {
  target: PerfTarget;
  max_qps: number;
  ramp_qps: number;
  clients: number;
  queries_per_step: number;
  plot_file?: string;
  queries?: string;
};

type ResperfResponse = {
  ok: boolean;
  target: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  plot_file?: string;
};

type UnboundControls = {
  ratelimit: number;
  ip_ratelimit: number;
  unwanted_reply_threshold: number;
  serve_expired: boolean;
  serve_expired_ttl: number;
  prefetch: boolean;
  msg_cache_size: string;
  rrset_cache_size: string;
  aggressive_nsec: boolean;
};

type BindControls = {
  rrl_enabled: boolean;
  rrl_responses_per_second: number;
  rrl_window: number;
  rrl_slip: number;
  recursion: boolean;
};

type ControlsStatusResponse = {
  ok: boolean;
  unbound: UnboundControls;
  bind: BindControls;
};

type NodeHealth = 'up' | 'down' | 'unknown';

type NodeInfo = {
  name: string;
  role: string;
  ip: string;
  ports: string;
  health: NodeHealth;
  tags: string[];
  meta: string[];
};

const DEFAULT_UNBOUND_CONTROLS: UnboundControls = {
  ratelimit: 200,
  ip_ratelimit: 50,
  unwanted_reply_threshold: 0,
  serve_expired: false,
  serve_expired_ttl: 0,
  prefetch: true,
  msg_cache_size: '',
  rrset_cache_size: '',
  aggressive_nsec: true,
};

const DEFAULT_BIND_CONTROLS: BindControls = {
  rrl_enabled: true,
  rrl_responses_per_second: 20,
  rrl_window: 5,
  rrl_slip: 2,
  recursion: false,
};

const DEFAULT_REQUEST: DigRequest = {
  client: 'trusted',
  resolver: 'valid',
  name: 'www.example.test',
  qtype: 'A',
  dnssec: true,
  trace: false,
  short: false,
};

const DEFAULT_PERF_QUERIES = [
  'example.test A',
  'www.example.test A',
  'example.test AAAA',
  'www.example.test AAAA',
  'example.test NS',
  'example.test SOA',
  'example.test DNSKEY',
  'ns-child.test A',
  'nope1.example.test A',
  'nope2.example.test A',
].join('\n');

const TOPOLOGY_NODES: NodeInfo[] = [
  {
    name: 'authoritative_parent',
    role: 'authoritative parent',
    ip: '172.31.0.10',
    ports: '53/udp,tcp',
    health: 'unknown',
    tags: ['bind9', 'dnssec'],
    meta: ['image: bind9:9.18', 'network: dns_core', 'zone: test.'],
  },
  {
    name: 'authoritative_child',
    role: 'authoritative child',
    ip: '172.31.0.11',
    ports: '53/udp,tcp',
    health: 'unknown',
    tags: ['bind9', 'dnssec'],
    meta: ['image: bind9:9.18', 'network: dns_core', 'zone: example.test.'],
  },
  {
    name: 'resolver',
    role: 'validating resolver',
    ip: '172.32.0.20',
    ports: '53/udp,tcp (host 5300), 853/tcp (DoT)',
    health: 'unknown',
    tags: ['unbound', 'validator'],
    meta: ['image: mvance/unbound:1.20.0', 'network: client_net', 'trust: test.'],
  },
  {
    name: 'resolver_plain',
    role: 'non-validating resolver',
    ip: '172.32.0.21',
    ports: '53/udp,tcp (host 5301)',
    health: 'unknown',
    tags: ['unbound', 'plain'],
    meta: ['image: mvance/unbound:1.20.0', 'network: client_net', 'no trust anchor'],
  },
  {
    name: 'dot_proxy',
    role: 'DNS-over-TLS proxy',
    ip: '172.30.0.81',
    ports: '853/tcp (host 853)',
    health: 'unknown',
    tags: ['dot', 'tls'],
    meta: ['network: mgmt_net', 'upstream: 172.30.0.20:53'],
  },
  {
    name: 'doh_proxy',
    role: 'DNS-over-HTTPS proxy',
    ip: '172.30.0.80',
    ports: '443/tcp (host 8443)',
    health: 'unknown',
    tags: ['doh', 'https'],
    meta: ['network: mgmt_net', 'path: /dns-query'],
  },
  {
    name: 'lab_api',
    role: 'management API',
    ip: '172.30.0.90',
    ports: '8000/tcp (host 127.0.0.1:8000)',
    health: 'unknown',
    tags: ['api', 'control'],
    meta: ['network: mgmt_net', 'rate limit: 120/min'],
  },
  {
    name: 'client',
    role: 'trusted client API',
    ip: '172.32.0.50',
    ports: 'HTTP only',
    health: 'unknown',
    tags: ['client', 'trusted'],
    meta: ['network: client_net', 'profile: trusted'],
  },
  {
    name: 'untrusted',
    role: 'untrusted client API',
    ip: '172.33.0.50',
    ports: 'HTTP only',
    health: 'unknown',
    tags: ['client', 'untrusted'],
    meta: ['network: untrusted_net', 'profile: untrusted'],
  },
];

const MVP_UI_NOTES = [
  {
    title: 'Nodes / Topology',
    items: [
      'Role: authoritative, resolver, client, capture, signer',
      'Lab IPs + ports (53/udp,tcp; 8000; 5173)',
      'Health (up/down + uptime)',
      'Metadata: image tag, container name, networks',
    ],
  },
  {
    title: 'Configs',
    items: [
      'unbound.conf and unbound.plain.conf',
      'named.conf + zone file (authoritative)',
      'DNSSEC ON/OFF, aggressive NSEC state',
      'Read-only view with syntax highlight',
      'Export config bundle',
    ],
  },
];

const SECTION_TABS: { id: SectionId; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'overview', label: 'Overview' },
  { id: 'topology', label: 'Topology' },
  { id: 'dig', label: 'Dig' },
  { id: 'output', label: 'Output' },
  { id: 'dnssec', label: 'DNSSEC' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'availability', label: 'Availability' },
  { id: 'perf', label: 'Perf' },
  { id: 'limits', label: 'Service Limits' },
  { id: 'amplification', label: 'Amplification' },
  { id: 'controls', label: 'Controls' },
  { id: 'configs', label: 'Configs' },
  { id: 'capture', label: 'Capture' },
];

const API_BASE = (import.meta.env.VITE_API_BASE || '/api').replace(/\/+$/, '');
const LAB_API_BASE = (import.meta.env.VITE_LAB_API_BASE || '/lab-api').replace(
  /\/+$/,
  ''
);
const LAB_API_KEY = import.meta.env.VITE_LAB_API_KEY || '';
const CLIENT_API_KEY = import.meta.env.VITE_CLIENT_API_KEY || '';
const PRIVACY_EXISTING_NAME = 'www.example.test';
const PRIVACY_NONEXISTENT_NAME = 'nope1.example.test';

async function postJson<T>(
  path: string,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

async function getJson<T>(
  path: string,
  extraHeaders: Record<string, string> = {}
): Promise<T> {
  const res = await fetch(path, { headers: extraHeaders });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KB', 'MB', 'GB'];
  let size = bytes / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatPercent(value?: number): string {
  if (value === undefined || Number.isNaN(value)) {
    return 'n/a';
  }
  return `${(value * 100).toFixed(1)}%`;
}

function formatKeyValues(values: Record<string, number> | undefined): string {
  if (!values) {
    return '—';
  }
  const entries = Object.entries(values);
  if (entries.length === 0) {
    return '—';
  }
  return entries.map(([key, val]) => `${key}:${val}`).join(' ');
}

function readConfigValue(content: string, key: string): string | null {
  const regex = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'i');
  for (const line of content.split('\n')) {
    const match = line.match(regex);
    if (match) {
      return match[1].trim();
    }
  }
  return null;
}

function extractBlock(content: string, keyword: string): string {
  const regex = new RegExp(`\\n\\s*${keyword}\\s*\\{[\\s\\S]*?\\};`, 'i');
  const match = content.match(regex);
  return match ? match[0].trim() : '';
}

function ratioClass(value: number | undefined, threshold: number): string {
  if (value === undefined || Number.isNaN(value)) {
    return 'unknown';
  }
  return value >= threshold ? 'disabled' : 'enabled';
}

function parseDigRcode(output: string): string | undefined {
  for (const line of output.split('\n')) {
    if (!line.includes('status:')) {
      continue;
    }
    const match = line.match(/status:\s*([A-Z0-9_]+)/i);
    if (match) {
      return match[1].toUpperCase();
    }
  }
  return undefined;
}

function parseDigAd(output: string): boolean | undefined {
  for (const line of output.split('\n')) {
    if (!line.includes(';; flags:')) {
      continue;
    }
    const match = line.match(/;; flags:\s*([^;]+)/i);
    if (!match) {
      continue;
    }
    const flags = match[1]
      .trim()
      .split(/\s+/)
      .map((flag) => flag.toLowerCase());
    return flags.includes('ad');
  }
  return undefined;
}

function formatStatusLabel(rcode?: string, ad?: boolean): string {
  if (!rcode) {
    return ad === undefined ? 'Completed' : `Completed (AD=${ad ? 'yes' : 'no'})`;
  }
  if (rcode === 'NOERROR') {
    return `OK (${rcode}${ad === undefined ? '' : `, AD=${ad ? 'yes' : 'no'}`})`;
  }
  return `${rcode}${ad === undefined ? '' : ` (AD=${ad ? 'yes' : 'no'})`}`;
}

function formatDemoStatus(rcode?: string, ad?: boolean): string {
  if (rcode === 'NXDOMAIN') {
    return 'NXDOMAIN (expected)';
  }
  return formatStatusLabel(rcode, ad);
}

function formatIndicator(value?: boolean): string {
  if (value === undefined) {
    return 'unknown';
  }
  return value ? 'enabled' : 'not detected';
}

function configLineClass(line: string): string {
  const trimmed = line.trim();
  if (!trimmed) return 'config-line';
  if (
    trimmed.startsWith('#') ||
    trimmed.startsWith(';') ||
    trimmed.startsWith('//')
  ) {
    return 'config-line comment';
  }
  if (
    /^(options|server|zone|view|include|local-zone|local-data)\b/i.test(
      trimmed
    )
  ) {
    return 'config-line keyword';
  }
  if (
    /^(ratelimit|ip-ratelimit|aggressive-nsec|qname-minimisation)\b/i.test(
      trimmed
    )
  ) {
    return 'config-line setting';
  }
  return 'config-line';
}

function indicatorClass(value?: boolean): string {
  if (value === undefined) {
    return 'unknown';
  }
  return value ? 'enabled' : 'disabled';
}

function healthClass(health: NodeHealth): string {
  if (health === 'up') return 'up';
  if (health === 'down') return 'down';
  return 'unknown';
}

function healthLabel(health: NodeHealth): string {
  if (health === 'up') return 'Up';
  if (health === 'down') return 'Down';
  return 'Unknown';
}

function parseNsec3FromZone(content: string, sourceLabel: string) {
  const lines = content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith(';'));

  const hasNsec3 = lines.some((line) => /\bNSEC3\b/i.test(line));
  const hasNsec = lines.some((line) => /\bNSEC\b/i.test(line));
  const hasParam = lines.some((line) => /\bNSEC3PARAM\b/i.test(line));

  if (hasNsec3) {
    return { enabled: true, detail: `NSEC3 records detected (${sourceLabel})` };
  }
  if (hasNsec) {
    return { enabled: false, detail: `NSEC records detected (${sourceLabel})` };
  }
  if (hasParam) {
    return {
      enabled: false,
      detail: `NSEC3PARAM present but no NSEC3 records (${sourceLabel})`,
    };
  }
  return { enabled: false, detail: `No NSEC/NSEC3 records found (${sourceLabel})` };
}

function parseAggressiveNsec(content: string) {
  const match = content.match(/aggressive-nsec\s*:\s*(yes|no)/i);
  if (!match) {
    return { enabled: false, detail: 'setting not found' };
  }
  const enabled = match[1].toLowerCase() === 'yes';
  return { enabled, detail: `aggressive-nsec: ${match[1].toLowerCase()}` };
}

function parseQnameMinimisation(content: string) {
  const match = content.match(/qname-minimisation\s*:\s*(yes|no)/i);
  if (!match) {
    return { enabled: false, detail: 'setting not found' };
  }
  const enabled = match[1].toLowerCase() === 'yes';
  return { enabled, detail: `qname-minimisation: ${match[1].toLowerCase()}` };
}

function parseNsecInterval(output: string) {
  for (const line of output.split('\n')) {
    const match = line.match(/^(\S+)\s+\d+\s+IN\s+NSEC\s+(\S+)/i);
    if (match) {
      return { owner: match[1], next: match[2] };
    }
  }
  return null;
}

function normalizeName(name: string) {
  return name.endsWith('.') ? name.slice(0, -1) : name;
}

function splitLabels(name: string) {
  const clean = normalizeName(name).toLowerCase();
  return clean.length ? clean.split('.') : [];
}

function compareLabel(a: string, b: string) {
  if (a.length !== b.length) {
    return a.length < b.length ? -1 : 1;
  }
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function compareName(a: string, b: string) {
  const aLabels = splitLabels(a);
  const bLabels = splitLabels(b);
  let ai = aLabels.length - 1;
  let bi = bLabels.length - 1;
  while (ai >= 0 && bi >= 0) {
    const cmp = compareLabel(aLabels[ai], bLabels[bi]);
    if (cmp !== 0) {
      return cmp;
    }
    ai -= 1;
    bi -= 1;
  }
  if (ai < 0 && bi < 0) {
    return 0;
  }
  return ai < 0 ? -1 : 1;
}

function isBetween(owner: string, next: string, candidate: string) {
  const cmpOwnerNext = compareName(owner, next);
  const cmpOwnerCand = compareName(owner, candidate);
  const cmpCandNext = compareName(candidate, next);
  if (cmpOwnerNext < 0) {
    return cmpOwnerCand < 0 && cmpCandNext < 0;
  }
  return cmpOwnerCand > 0 || cmpCandNext < 0;
}

function pickLabelBetween(owner: string, next: string, zone: string) {
  const candidates = ['a', 'b', 'c', 'm', 'n', 't', 'x', 'y', 'z', 'zz', 'zzz'];
  for (const cand of candidates) {
    const full = `${cand}.${zone}`;
    if (isBetween(owner, next, full)) {
      return full;
    }
  }
  for (let i = 0; i < 20; i += 1) {
    const rand = Math.random().toString(36).slice(2, 8);
    const full = `p-${rand}.${zone}`;
    if (isBetween(owner, next, full)) {
      return full;
    }
  }
  return null;
}

export default function App() {
  const [req, setReq] = useState<DigRequest>(DEFAULT_REQUEST);
  const [backend, setBackend] = useState<Backend>('client');
  const [activeSection, setActiveSection] = useState<SectionId>('all');
  const [output, setOutput] = useState<OutputView | null>(null);
  const [status, setStatus] = useState<string>('');
  const outputRef = useRef<HTMLDivElement | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [configFiles, setConfigFiles] = useState<ConfigFile[]>([]);
  const [configPath, setConfigPath] = useState<string>('');
  const [configContent, setConfigContent] = useState<string>('');
  const [configStatus, setConfigStatus] = useState<string>('');
  const [configGroup, setConfigGroup] = useState<ConfigGroup>('authoritative');
  const [configServer, setConfigServer] = useState<ConfigServer>('child');
  const [configSearch, setConfigSearch] = useState('');
  const [privacyTab, setPrivacyTab] = useState<PrivacyTab>('overview');
  const [captureTarget, setCaptureTarget] =
    useState<CaptureTarget>('resolver');
  const [captureFilter, setCaptureFilter] = useState<CaptureFilter>('dns');
  const [captureFiles, setCaptureFiles] = useState<CaptureFile[]>([]);
  const [captureStatus, setCaptureStatus] = useState<string>('');
  const [captureRunning, setCaptureRunning] = useState<
    Record<CaptureTarget, boolean>
  >({
    resolver: false,
    authoritative: false,
  });
  const [signingBusy, setSigningBusy] = useState(false);
  const [signingStatus, setSigningStatus] = useState('');
  const [signingOutput, setSigningOutput] = useState('');
  const [signingSteps, setSigningSteps] = useState<SigningStep[]>([]);
  const [proofBusy, setProofBusy] = useState(false);
  const [proofStatus, setProofStatus] = useState('');
  const [proofOutput, setProofOutput] = useState('');
  const [proofCaptureFile, setProofCaptureFile] = useState('');
  const [proofColdCache, setProofColdCache] = useState(true);
  const [proofFlushCache, setProofFlushCache] = useState(false);
  const [privacyBusy, setPrivacyBusy] = useState(false);
  const [privacyStatus, setPrivacyStatus] = useState('');
  const [privacyOutput, setPrivacyOutput] = useState('');
  const [availabilityBusy, setAvailabilityBusy] = useState(false);
  const [availabilityStatus, setAvailabilityStatus] = useState('');
  const [availabilityOutput, setAvailabilityOutput] = useState('');
  const [availabilityMetrics, setAvailabilityMetrics] =
    useState<AvailabilityMetricsResponse | null>(null);
  const [availabilityProbe, setAvailabilityProbe] =
    useState<AvailabilityProbeResponse | null>(null);
  const [availabilityUpdatedAt, setAvailabilityUpdatedAt] = useState('');
  const [perfTarget, setPerfTarget] = useState<PerfTarget>('resolver_valid');
  const [perfQueries, setPerfQueries] = useState(DEFAULT_PERF_QUERIES);
  const [dnsperfBusy, setDnsperfBusy] = useState(false);
  const [dnsperfStatus, setDnsperfStatus] = useState('');
  const [dnsperfOutput, setDnsperfOutput] = useState('');
  const [dnsperfSummary, setDnsperfSummary] = useState<DnsperfSummary | null>(
    null
  );
  const [dnsperfDuration, setDnsperfDuration] = useState(15);
  const [dnsperfQps, setDnsperfQps] = useState(20);
  const [dnsperfMaxQueries, setDnsperfMaxQueries] = useState(200);
  const [dnsperfThreads, setDnsperfThreads] = useState(1);
  const [dnsperfClients, setDnsperfClients] = useState(1);
  const [resperfBusy, setResperfBusy] = useState(false);
  const [resperfStatus, setResperfStatus] = useState('');
  const [resperfOutput, setResperfOutput] = useState('');
  const [resperfPlotFile, setResperfPlotFile] = useState('');
  const [resperfMaxQps, setResperfMaxQps] = useState(100);
  const [resperfRampQps, setResperfRampQps] = useState(10);
  const [resperfClients, setResperfClients] = useState(5);
  const [resperfQueriesPerStep, setResperfQueriesPerStep] = useState(100);
  const [resperfPlotName, setResperfPlotName] = useState('resperf_plot.txt');
  const [loadCount, setLoadCount] = useState(200);
  const [loadQps, setLoadQps] = useState(20);
  const [probeCount, setProbeCount] = useState(5);
  const [floodBusy, setFloodBusy] = useState(false);
  const [floodStatus, setFloodStatus] = useState('');
  const [floodSummary, setFloodSummary] = useState('');
  const [floodResults, setFloodResults] = useState<FloodStepResult[]>([]);
  const [floodStartQps, setFloodStartQps] = useState(10);
  const [floodEndQps, setFloodEndQps] = useState(100);
  const [floodStepQps, setFloodStepQps] = useState(10);
  const [floodStepSeconds, setFloodStepSeconds] = useState(30);
  const [floodOutstanding, setFloodOutstanding] = useState(200);
  const [floodTimeoutMs, setFloodTimeoutMs] = useState(1000);
  const [floodStopLoss, setFloodStopLoss] = useState(2);
  const [floodStopP95, setFloodStopP95] = useState(200);
  const [floodStopServfail, setFloodStopServfail] = useState(2);
  const [floodStopCpu, setFloodStopCpu] = useState(85);
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [baselineStatus, setBaselineStatus] = useState('');
  const [baselineDuration, setBaselineDuration] = useState(60);
  const [baselineProbeCount, setBaselineProbeCount] = useState(20);
  const [baselineSummary, setBaselineSummary] =
    useState<BaselineSummary | null>(null);
  const [baselineCaptureFile, setBaselineCaptureFile] = useState('');
  const [warmupBusy, setWarmupBusy] = useState(false);
  const [cooldownRemaining, setCooldownRemaining] = useState(0);
  const [limitsBusy, setLimitsBusy] = useState(false);
  const [limitsStatus, setLimitsStatus] = useState('');
  const [unboundLimitLines, setUnboundLimitLines] = useState<string[]>([]);
  const [bindRrlBlock, setBindRrlBlock] = useState('');
  const [bindRrlEnabled, setBindRrlEnabled] = useState<boolean | null>(null);
  const [rateLimitDelta, setRateLimitDelta] = useState<{
    ratelimited: number;
    ip_ratelimited: number;
    total: number;
  } | null>(null);
  const [rateLimitAfter, setRateLimitAfter] =
    useState<AvailabilityMetricsResponse | null>(null);
  const [rrlStatus, setRrlStatus] = useState('');
  const [rrlResult, setRrlResult] = useState<RrlTestResponse | null>(null);
  const [rrlCount, setRrlCount] = useState(300);
  const [ampBusy, setAmpBusy] = useState(false);
  const [ampStatus, setAmpStatus] = useState('');
  const [ampResults, setAmpResults] = useState<AmplificationResult[]>([]);
  const [ampCount, setAmpCount] = useState(10);
  const [ampDnssec, setAmpDnssec] = useState(true);
  const [ampTcpFallback, setAmpTcpFallback] = useState(true);
  const [ampQtypes, setAmpQtypes] = useState<string[]>([
    'DNSKEY',
    'ANY',
    'TXT',
    'RRSIG',
  ]);
  const [ampEdnsSizes, setAmpEdnsSizes] = useState<number[]>([1232, 4096]);
  const [ampName, setAmpName] = useState('example.test');
  const [mixBusy, setMixBusy] = useState(false);
  const [mixStatus, setMixStatus] = useState('');
  const [mixResult, setMixResult] = useState<MixLoadResponse | null>(null);
  const [mixCount, setMixCount] = useState(200);
  const [mixEdns, setMixEdns] = useState(1232);
  const [mixDnssec, setMixDnssec] = useState(true);
  const [mixTcpFallback, setMixTcpFallback] = useState(true);
  const [mixZone, setMixZone] = useState('example.test');
  const [controlsBusy, setControlsBusy] = useState(false);
  const [controlsStatus, setControlsStatus] = useState('');
  const [unboundCtl, setUnboundCtl] = useState<UnboundControls>(
    DEFAULT_UNBOUND_CONTROLS
  );
  const [bindCtl, setBindCtl] = useState<BindControls>(DEFAULT_BIND_CONTROLS);
  const [indicators, setIndicators] = useState<IndicatorState>({
    loading: false,
    message: 'Not loaded.',
  });

  const scrollToConfigs = () => {
    const target = document.getElementById('configs');
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      window.location.hash = 'configs';
    }
  };

  const clientBase = `${API_BASE}/${req.client}`;
  const missingLabKey = useMemo(() => LAB_API_KEY.trim().length === 0, []);
  const labHeaders: Record<string, string> = {};
  if (LAB_API_KEY.trim()) {
    labHeaders['x-api-key'] = LAB_API_KEY;
  }
  const clientHeaders: Record<string, string> = {};
  if (CLIENT_API_KEY.trim()) {
    clientHeaders['x-api-key'] = CLIENT_API_KEY;
  }
  const groupPrefixes =
    configGroup === 'authoritative' ? ['bind/', 'bind_parent/'] : ['unbound/'];
  const groupedFiles = configFiles.filter((f) =>
    groupPrefixes.some((prefix) => f.path.startsWith(prefix))
  );
  const serverFilteredFiles = groupedFiles.filter((f) => {
    if (configGroup === 'authoritative') {
      return configServer === 'parent'
        ? f.path.startsWith('bind_parent/')
        : f.path.startsWith('bind/');
    }
    if (configServer === 'plain') {
      return (
        f.path.startsWith('unbound/') &&
        (f.path.includes('plain') || f.path.endsWith('root.hints'))
      );
    }
    return (
      f.path.startsWith('unbound/') &&
      (!f.path.includes('plain') || f.path.endsWith('root.hints'))
    );
  });
  const visibleConfigFiles = serverFilteredFiles.filter((f) =>
    configSearch.trim()
      ? f.path.toLowerCase().includes(configSearch.trim().toLowerCase())
      : true
  );
  const resolverIpByClient: Record<ResolverKind, Record<Client, string>> = {
    valid: {
      trusted: '172.32.0.20',
      untrusted: '172.33.0.20',
      mgmt: '172.30.0.20',
    },
    plain: {
      trusted: '172.32.0.21',
      untrusted: '172.33.0.21',
      mgmt: '172.30.0.21',
    },
  };
  const resolverLabel = `${req.resolver} (${resolverIpByClient[req.resolver][req.client]})`;
  const perfTargetOptions: { value: PerfTarget; label: string }[] = [
    { value: 'resolver_valid', label: 'Resolver (validating) — 172.32.0.20' },
    { value: 'resolver_plain', label: 'Resolver (plain) — 172.32.0.21' },
    { value: 'authoritative_parent', label: 'Authoritative parent — 172.31.0.10' },
    { value: 'authoritative_child', label: 'Authoritative child — 172.31.0.11' },
  ];
  const nxdomainRatio = availabilityMetrics?.ratios.nxdomain;
  const servfailRatio = availabilityMetrics?.ratios.servfail;
  const cacheHitRatio = availabilityMetrics?.ratios.cache_hit;
  const ratelimitRatio = availabilityMetrics?.ratios.ratelimited;
  const ipRatelimitRatio = availabilityMetrics?.ratios.ip_ratelimited;
  const selectedConfig = configFiles.find((f) => f.path === configPath);
  const sortedAmpResults = useMemo(
    () =>
      [...ampResults].sort(
        (a, b) =>
          a.edns_size - b.edns_size || a.qtype.localeCompare(b.qtype)
      ),
    [ampResults]
  );

  const isSectionVisible = (id: SectionId) =>
    activeSection === 'all' || activeSection === id;

  const selectSection = (id: SectionId) => {
    setActiveSection(id);
    if (id === 'all') {
      window.history.replaceState(null, '', window.location.pathname);
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }
    const target = document.getElementById(id);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    window.location.hash = id;
  };

  useEffect(() => {
    const hash = window.location.hash.replace('#', '');
    if (hash && SECTION_TABS.some((tab) => tab.id === hash)) {
      setActiveSection(hash as SectionId);
    }
  }, []);

  useEffect(() => {
    if (configGroup === 'authoritative') {
      if (configServer !== 'child' && configServer !== 'parent') {
        setConfigServer('child');
      }
    } else if (configServer !== 'resolver' && configServer !== 'plain') {
      setConfigServer('resolver');
    }
  }, [configGroup, configServer]);

  useEffect(() => {
    if (visibleConfigFiles.length === 0) {
      return;
    }
    if (!configPath || !visibleConfigFiles.some((f) => f.path === configPath)) {
      setConfigPath(visibleConfigFiles[0].path);
    }
  }, [visibleConfigFiles, configPath]);

  const runDig = async () => {
    await runDigWithRequest(req, 'Running dig...');
  };

  const executeDigRequest = async (
    request: DigRequest
  ): Promise<{
    ok: boolean;
    output: OutputView;
    rcode?: string;
    ad?: boolean;
  }> => {
    const { client, resolver, ...body } = request;
    if (backend === 'client') {
      const server = resolverIpByClient[resolver][client];
      const result = await postJson<ClientDigResponse>(
        `${API_BASE}/${client}/dig`,
        { ...body, server },
        clientHeaders
      );
      const parsedRcode = parseDigRcode(result.output);
      const parsedAd = parseDigAd(result.output);
      const adFlag = parsedAd ?? result.ad;
      return {
        ok: result.ok,
        output: {
          ok: result.ok,
          command: result.cmd.join(' '),
          text: result.output,
        },
        rcode: parsedRcode,
        ad: adFlag,
      };
    }

    const result = await postJson<LabDigResponse>(
      `${LAB_API_BASE}/dig`,
      { profile: client, resolver, ...body },
      labHeaders
    );
    const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
    const parsedRcode = parseDigRcode(text);
    const parsedAd = parseDigAd(text);
    return {
      ok: result.ok,
      output: { ok: result.ok, command: result.command, text },
      rcode: parsedRcode,
      ad: parsedAd,
    };
  };

  const runDigWithRequest = async (request: DigRequest, label: string) => {
    setIsBusy(true);
    setStatus(label);
    try {
      const result = await executeDigRequest(request);
      setOutput(result.output);
      setStatus(
        result.ok ? formatStatusLabel(result.rcode, result.ad) : 'Completed with errors'
      );
    } catch (err) {
      setOutput(null);
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setStatus,
        (value) => setOutput({ ok: false, command: 'diagnostics', text: value })
      );
    } finally {
      if (outputRef.current) {
        outputRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      setIsBusy(false);
    }
  };

  const executeLabDig = async (request: DigRequest) => {
    const { client, resolver, ...body } = request;
    const result = await postJson<LabDigResponse>(
      `${LAB_API_BASE}/dig`,
      { profile: client, resolver, ...body },
      labHeaders
    );
    const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
    const parsedRcode = parseDigRcode(text);
    const parsedAd = parseDigAd(text);
    return {
      ok: result.ok,
      output: { ok: result.ok, command: result.command, text },
      rcode: parsedRcode,
      ad: parsedAd,
    };
  };

  const applyNsec3ProofPreset = () => {
    setReq({
      ...req,
      resolver: 'valid',
      name: 'nope1.example.test',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    });
    setStatus('Loaded NSEC3 proof preset.');
  };

  const runNsec3Proof = async () => {
    const request: DigRequest = {
      ...req,
      resolver: 'valid',
      name: 'nope1.example.test',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    };
    setReq(request);
    await runDigWithRequest(request, 'Running NSEC3 proof query...');
  };

  const clearOutput = () => {
    setOutput(null);
    setStatus('');
  };

  const applyQnameMinPreset = () => {
    setReq({
      ...req,
      resolver: 'valid',
      name: 'deep.sub.example.test',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    });
    setStatus('Loaded QNAME minimization preset.');
  };

  const runQnameMin = async () => {
    const request: DigRequest = {
      ...req,
      resolver: 'valid',
      name: 'deep.sub.example.test',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    };
    setReq(request);
    await runDigWithRequest(request, 'Running QNAME minimization query...');
    if (!missingLabKey) {
      await loadIndicators();
    }
  };

  const runAggressiveNsecDemo = async () => {
    const base: DigRequest = {
      ...req,
      resolver: 'valid',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    };
    const firstReq: DigRequest = { ...base, name: 'nope1.example.test' };
    const secondReq: DigRequest = { ...base, name: 'nope2.example.test' };

    setReq(firstReq);
    setIsBusy(true);
    setStatus('Running aggressive NSEC demo (two NXDOMAIN queries)...');
    try {
      const first = await executeDigRequest(firstReq);
      const second = await executeDigRequest(secondReq);
      const combinedText = [
        '# Aggressive NSEC proof (expected NXDOMAIN)',
        `# Query 1: ${firstReq.name}`,
        first.output.command,
        '',
        first.output.text,
        '',
        `# Query 2: ${secondReq.name}`,
        second.output.command,
        '',
        second.output.text,
      ].join('\n');
      setOutput({
        ok: first.ok && second.ok,
        command: 'dig (2 queries)',
        text: combinedText,
      });
      setStatus(
        `Aggressive NSEC demo completed. Q1: ${formatDemoStatus(
          first.rcode,
          first.ad
        )}, Q2: ${formatDemoStatus(second.rcode, second.ad)}`
      );
    } catch (err) {
      setStatus((err as Error).message);
      setOutput(null);
    } finally {
      if (outputRef.current) {
        outputRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      setIsBusy(false);
    }
  };

  const runAggressiveNsecProof = async () => {
    if (missingLabKey) {
      setProofStatus('Missing Lab API key.');
      return;
    }

    const zone = 'example.test';
    const base: DigRequest = {
      ...req,
      client: 'trusted',
      resolver: 'valid',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    };
    const firstReq: DigRequest = {
      ...base,
      name: `nope1-${Math.random().toString(36).slice(2, 7)}.${zone}`,
    };
    let secondReq: DigRequest = {
      ...base,
      name: `nope2-${Math.random().toString(36).slice(2, 7)}.${zone}`,
    };

    setProofBusy(true);
    setProofStatus('Preparing proof...');
    setProofOutput('');
    setProofCaptureFile('');

    try {
      if (proofColdCache) {
        setProofStatus('Restarting resolver to clear cache...');
        await postJson<LabDigResponse>(
          `${LAB_API_BASE}/resolver/restart`,
          {},
          labHeaders
        );
        await new Promise((resolve) => setTimeout(resolve, 3000));
      } else if (proofFlushCache) {
        setProofStatus('Flushing resolver cache (example.test)...');
        await postJson<LabDigResponse>(
          `${LAB_API_BASE}/resolver/flush`,
          { zone: 'example.test' },
          labHeaders
        );
        await new Promise((resolve) => setTimeout(resolve, 800));
      }

      setProofStatus('Starting authoritative capture...');
      const start = await postJson<CaptureStartResponse>(
        `${LAB_API_BASE}/capture/start`,
        { target: 'authoritative', filter: 'dns' },
        labHeaders
      );
      setProofCaptureFile(start.file);
      await new Promise((resolve) => setTimeout(resolve, 600));

      setProofStatus('Running aggressive NSEC demo (two NXDOMAIN queries)...');
      const first = await executeLabDig(firstReq);
      const interval = parseNsecInterval(first.output.text);
      if (interval) {
        const picked = pickLabelBetween(interval.owner, interval.next, zone);
        if (picked) {
          secondReq = { ...base, name: picked };
        }
      }
      const second = await executeLabDig(secondReq);

      await new Promise((resolve) => setTimeout(resolve, 600));

      setProofStatus('Stopping capture...');
      const stopped = await postJson<CaptureStopResponse>(
        `${LAB_API_BASE}/capture/stop`,
        { target: 'authoritative' },
        labHeaders
      );

      const file = stopped.file || start.file;
      setProofCaptureFile(file || '');

      let summaryText = 'No capture summary.';
      if (file) {
        const summary = await getJson<CaptureSummaryResponse>(
          `${LAB_API_BASE}/capture/summary?file=${encodeURIComponent(file)}`,
          labHeaders
        );
        const warningLines: string[] = [];
        if (summary.total_packets === 0) {
          warningLines.push(
            'WARNING: capture empty (0 packets). Likely cache hit or capture failed.'
          );
        } else if (summary.upstream_queries === 0) {
          warningLines.push(
            'WARNING: no resolver -> authoritative traffic captured (cache hit likely).'
          );
        }
        summaryText = [
          '# Capture summary',
          `file: ${summary.file}`,
          `total DNS packets: ${summary.total_packets}`,
          `upstream queries (resolver -> authoritative): ${summary.upstream_queries}`,
          ...(warningLines.length ? ['', ...warningLines] : []),
        ].join('\n');
        if (warningLines.length) {
          setProofStatus(
            'Capture empty. Restart resolver (cold cache) and rerun Demo + Proof.'
          );
        }
      }

      const combinedText = [
        `# Query 1: ${firstReq.name}`,
        first.output.command,
        '',
        first.output.text,
        '',
        `# Query 2: ${secondReq.name}`,
        second.output.command,
        '',
        second.output.text,
        '',
        summaryText,
      ].join('\n');

      setProofOutput(combinedText);
      setProofStatus('Aggressive NSEC proof completed.');
    } catch (err) {
      setProofOutput('');
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setProofStatus,
        setProofOutput
      );
    } finally {
      setProofBusy(false);
    }
  };

  const runAggressiveNsecProofCold = async () => {
    if (missingLabKey) {
      setProofStatus('Missing Lab API key.');
      return;
    }

    const zone = 'example.test';
    const base: DigRequest = {
      ...req,
      client: 'trusted',
      resolver: 'valid',
      qtype: 'A',
      dnssec: true,
      trace: false,
      short: false,
    };
    const firstReq: DigRequest = {
      ...base,
      name: `nope1-${Math.random().toString(36).slice(2, 7)}.${zone}`,
    };
    let secondReq: DigRequest = {
      ...base,
      name: `nope2-${Math.random().toString(36).slice(2, 7)}.${zone}`,
    };

    setProofBusy(true);
    setProofStatus('Cold run: restarting resolver...');
    setProofOutput('');
    setProofCaptureFile('');

    try {
      await postJson<LabDigResponse>(
        `${LAB_API_BASE}/resolver/restart`,
        {},
        labHeaders
      );
      await new Promise((resolve) => setTimeout(resolve, 5000));

      setProofStatus('Cold run: starting authoritative capture...');
      const start = await postJson<CaptureStartResponse>(
        `${LAB_API_BASE}/capture/start`,
        { target: 'authoritative', filter: 'dns' },
        labHeaders
      );
      setProofCaptureFile(start.file);
      await new Promise((resolve) => setTimeout(resolve, 800));
      const health = await getJson<CaptureHealthResponse>(
        `${LAB_API_BASE}/capture/health?target=authoritative`,
        labHeaders
      );
      if (!health.running) {
        setProofStatus('Capture did not start. Check capture container.');
        setProofOutput(health.detail || 'Capture health check failed.');
        await postJson<CaptureStopResponse>(
          `${LAB_API_BASE}/capture/stop`,
          { target: 'authoritative' },
          labHeaders
        );
        return;
      }

      setProofStatus('Cold run: running aggressive NSEC demo...');
      const first = await executeLabDig(firstReq);
      const interval = parseNsecInterval(first.output.text);
      if (interval) {
        const picked = pickLabelBetween(interval.owner, interval.next, zone);
        if (picked) {
          secondReq = { ...base, name: picked };
        }
      }
      const second = await executeLabDig(secondReq);

      await new Promise((resolve) => setTimeout(resolve, 800));

      setProofStatus('Cold run: stopping capture...');
      const stopped = await postJson<CaptureStopResponse>(
        `${LAB_API_BASE}/capture/stop`,
        { target: 'authoritative' },
        labHeaders
      );

      const file = stopped.file || start.file;
      setProofCaptureFile(file || '');

      let summaryText = 'No capture summary.';
      if (file) {
        const summary = await getJson<CaptureSummaryResponse>(
          `${LAB_API_BASE}/capture/summary?file=${encodeURIComponent(file)}`,
          labHeaders
        );
        const warningLines: string[] = [];
        if (summary.total_packets === 0) {
          warningLines.push(
            'WARNING: capture empty (0 packets). Capture likely missed or tcpdump failed.'
          );
        } else if (summary.upstream_queries === 0) {
          warningLines.push(
            'WARNING: no resolver -> authoritative traffic captured (cache hit likely).'
          );
        }
        summaryText = [
          '# Capture summary',
          `file: ${summary.file}`,
          `total DNS packets: ${summary.total_packets}`,
          `upstream queries (resolver -> authoritative): ${summary.upstream_queries}`,
          ...(warningLines.length ? ['', ...warningLines] : []),
        ].join('\n');
        if (warningLines.length) {
          setProofStatus(
            'Cold run finished, but capture is empty. Try again or check capture target.'
          );
        }
      }

      const combinedText = [
        '# Aggressive NSEC proof (expected NXDOMAIN)',
        `# Query 1: ${firstReq.name}`,
        first.output.command,
        '',
        first.output.text,
        '',
        `# Query 2: ${secondReq.name}`,
        second.output.command,
        '',
        second.output.text,
        '',
        summaryText,
      ].join('\n');

      setProofOutput(combinedText);
      if (!summaryText.includes('WARNING')) {
        setProofStatus('Cold run completed.');
      }
    } catch (err) {
      setProofOutput('');
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setProofStatus,
        setProofOutput
      );
    } finally {
      setProofBusy(false);
    }
  };

  const clearAuthoritativeSigned = async () => {
    if (missingLabKey) {
      setSigningStatus('Missing Lab API key.');
      return;
    }
    setSigningBusy(true);
    setSigningStatus('Clearing authoritative signed files and restarting...');
    try {
      setSigningSteps([]);
      const result = await postJson<MaintenanceResponse>(
        `${LAB_API_BASE}/maintenance/authoritative/clear-signed`,
        {},
        labHeaders
      );
      const text = `${result.command}\n\n${result.stdout}${
        result.stderr ? `\n${result.stderr}` : ''
      }`.trim();
      setSigningOutput(text || 'Maintenance completed.');
      setSigningStatus(
        result.ok
          ? 'Authoritative signed files cleared. Parent + child restarted.'
          : 'Maintenance failed.'
      );
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setSigningStatus,
        setSigningOutput
      );
    } finally {
      setSigningBusy(false);
    }
  };

  const clearProofOutput = () => {
    setProofOutput('');
    setProofStatus('');
    setProofCaptureFile('');
  };

  const checkHealth = async () => {
    setIsBusy(true);
    setStatus('Checking health...');
    try {
      if (backend === 'client') {
        const result = await getJson<{
          ok: boolean;
          profile: string;
          default_dns_server: string;
        }>(`${clientBase}/health`, clientHeaders);
        setStatus(
          result.ok
            ? `Client API healthy (${result.profile} via ${
                result.default_dns_server || 'default'
              })`
            : 'Client API unhealthy'
        );
      } else {
        const result = await getJson<{ ok: boolean }>(
          `${LAB_API_BASE}/health`,
          labHeaders
        );
        setStatus(result.ok ? 'Lab API healthy' : 'Lab API unhealthy');
      }
    } catch (err) {
      setStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const viewLogs = async (service: 'bind' | 'unbound') => {
    setIsBusy(true);
    setStatus(`Fetching ${service} logs (Lab API)...`);
    try {
      const result = await getJson<LabDigResponse>(
        `${LAB_API_BASE}/logs/${service}?tail=200`,
        labHeaders
      );
      const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
      setOutput({ ok: result.ok, command: result.command, text });
      setStatus(result.ok ? 'Logs fetched' : 'Log fetch failed');
    } catch (err) {
      setOutput(null);
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setStatus,
        (value) => setOutput({ ok: false, command: 'diagnostics', text: value })
      );
    } finally {
      setIsBusy(false);
    }
  };

  const loadConfigList = async () => {
    setIsBusy(true);
    setConfigStatus('Loading config file list...');
    try {
      const result = await getJson<ConfigListResponse>(
        `${LAB_API_BASE}/config/list`,
        labHeaders
      );
      setConfigFiles(result.files);
      setConfigStatus(`Loaded ${result.files.length} files.`);
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setConfigStatus
      );
    } finally {
      setIsBusy(false);
    }
  };

  const viewConfigFile = async () => {
    if (!configPath) {
      setConfigStatus('Select a config file first.');
      return;
    }
    setIsBusy(true);
    setConfigStatus(`Loading ${configPath}...`);
    try {
      const result = await getJson<ConfigFileResponse>(
        `${LAB_API_BASE}/config/file?path=${encodeURIComponent(configPath)}`,
        labHeaders
      );
      setConfigContent(result.content);
      setConfigStatus(
        `Loaded ${result.path} (${result.size} bytes)${
          result.truncated ? ' [TRUNCATED]' : ''
        }`
      );
    } catch (err) {
      setConfigContent('');
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setConfigStatus
      );
    } finally {
      setIsBusy(false);
    }
  };

  const exportConfigBundle = () => {
    if (!configPath || !configContent) {
      setConfigStatus('Load a config file before exporting.');
      return;
    }
    const safeName = configPath.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');
    const payload = {
      path: configPath,
      size: configContent.length,
      exported_at: new Date().toISOString(),
      content: configContent,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `config-bundle-${safeName || 'config'}.json`;
    link.click();
    URL.revokeObjectURL(url);
    setConfigStatus(`Exported bundle for ${configPath}.`);
  };

  const maybeAttachStartupDiagnostics = async (
    baseMessage: string,
    setStatusMessage: (value: string) => void,
    setOutputMessage?: (value: string) => void
  ) => {
    setStatusMessage(baseMessage);
    if (missingLabKey) {
      return;
    }
    if (!/HTTP 5\d{2}/.test(baseMessage) && !baseMessage.toLowerCase().includes('timeout')) {
      return;
    }
    try {
      const diag = await getJson<StartupDiagnosticsResponse>(
        `${LAB_API_BASE}/diagnostics/startup`,
        labHeaders
      );
      if (diag.issues && diag.issues.length > 0) {
        setStatusMessage(`${baseMessage} • ${diag.issues[0]}`);
        if (setOutputMessage) {
          const lines = ['Startup diagnostics:', ...diag.issues];
          const excerpt = diag.details.bind_parent_excerpt;
          if (excerpt) {
            lines.push('', 'bind_parent log excerpt:', excerpt);
          }
          setOutputMessage(lines.join('\n'));
        }
      }
    } catch {
      // ignore diagnostics errors
    }
  };

  const loadCaptures = async () => {
    setIsBusy(true);
    setCaptureStatus('Loading captures...');
    try {
      const result = await getJson<CaptureListResponse>(
        `${LAB_API_BASE}/capture/list`,
        labHeaders
      );
      setCaptureFiles(result.files);
      setCaptureRunning(result.running);
      setCaptureStatus(`Loaded ${result.files.length} captures.`);
    } catch (err) {
      setCaptureStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  useEffect(() => {
    if (missingLabKey) {
      return;
    }
    void loadCaptures();
  }, [missingLabKey]);

  const loadIndicators = async () => {
    if (missingLabKey) {
      setIndicators({
        loading: false,
        message: 'Missing Lab API key.',
      });
      return;
    }

    setIndicators({ loading: true, message: 'Loading indicators...' });

    let childEnabled: boolean | undefined;
    let parentEnabled: boolean | undefined;
    let aggressiveEnabled: boolean | undefined;
    let qnameEnabled: boolean | undefined;
    let childDetail = '';
    let parentDetail = '';
    let aggressiveDetail = '';
    let qnameDetail = '';
    const isNotFound = (err: unknown) =>
      (err as Error).message.toLowerCase().includes('http 404');
    const loadZoneIndicator = async (
      signedPath: string,
      unsignedPath: string
    ) => {
      try {
        const signed = await getJson<ConfigFileResponse>(
          `${LAB_API_BASE}/config/file?path=${encodeURIComponent(signedPath)}`,
          labHeaders
        );
        return parseNsec3FromZone(signed.content, signed.path);
      } catch (err) {
        if (!isNotFound(err)) {
          throw err;
        }
      }

      const unsigned = await getJson<ConfigFileResponse>(
        `${LAB_API_BASE}/config/file?path=${encodeURIComponent(unsignedPath)}`,
        labHeaders
      );
      return parseNsec3FromZone(unsigned.content, unsigned.path);
    };

    try {
      const parsed = await loadZoneIndicator(
        'bind/zones/db.example.test.signed',
        'bind/zones/db.example.test'
      );
      childEnabled = parsed.enabled;
      childDetail = parsed.detail;
    } catch (err) {
      childEnabled = undefined;
      childDetail = (err as Error).message;
    }

    try {
      const parsed = await loadZoneIndicator(
        'bind_parent/zones/db.test.signed',
        'bind_parent/zones/db.test'
      );
      parentEnabled = parsed.enabled;
      parentDetail = parsed.detail;
    } catch (err) {
      parentEnabled = undefined;
      parentDetail = (err as Error).message;
    }

    try {
      const unbound = await getJson<ConfigFileResponse>(
        `${LAB_API_BASE}/config/file?path=${encodeURIComponent(
          'unbound/unbound.conf'
        )}`,
        labHeaders
      );
      const parsed = parseAggressiveNsec(unbound.content);
      aggressiveEnabled = parsed.enabled;
      aggressiveDetail = parsed.detail;
      const qnameParsed = parseQnameMinimisation(unbound.content);
      qnameEnabled = qnameParsed.enabled;
      qnameDetail = qnameParsed.detail;
    } catch (err) {
      aggressiveEnabled = undefined;
      aggressiveDetail = (err as Error).message;
      qnameEnabled = undefined;
      qnameDetail = (err as Error).message;
    }

    setIndicators({
      loading: false,
      message: 'Indicators updated.',
      nsec3Child: childEnabled,
      nsec3Parent: parentEnabled,
      aggressiveNsec: aggressiveEnabled,
      qnameMinim: qnameEnabled,
      childDetail,
      parentDetail,
      aggressiveDetail,
      qnameDetail,
      updatedAt: new Date().toLocaleString(),
    });
  };

  useEffect(() => {
    if (missingLabKey) {
      return;
    }
    void loadIndicators();
  }, [missingLabKey]);

  const startCapture = async () => {
    setIsBusy(true);
    setCaptureStatus(`Starting ${captureTarget} capture...`);
    try {
      const result = await postJson<CaptureStartResponse>(
        `${LAB_API_BASE}/capture/start`,
        { target: captureTarget, filter: captureFilter },
        labHeaders
      );
      setCaptureStatus(
        `Capture started on ${result.target}: ${result.file} (${result.filter})`
      );
      await loadCaptures();
    } catch (err) {
      setCaptureStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const stopCapture = async () => {
    setIsBusy(true);
    setCaptureStatus(`Stopping ${captureTarget} capture...`);
    try {
      const result = await postJson<CaptureStopResponse>(
        `${LAB_API_BASE}/capture/stop`,
        { target: captureTarget },
        labHeaders
      );
      setCaptureStatus(
        result.file
          ? `Capture stopped. File: ${result.file}`
          : `Capture stopped on ${result.target}.`
      );
      await loadCaptures();
    } catch (err) {
      setCaptureStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const switchSigningMode = async (mode: 'nsec' | 'nsec3') => {
    if (missingLabKey) {
      setSigningStatus('Missing Lab API key.');
      return;
    }
    setSigningBusy(true);
    setSigningStatus(`Switching to ${mode.toUpperCase()}...`);
    setSigningOutput('');
    setSigningSteps([]);
    try {
      const result = await postJson<SigningSwitchResponse>(
        `${LAB_API_BASE}/signing/switch`,
        { mode } satisfies SigningSwitchRequest,
        labHeaders
      );
      setSigningSteps(result.steps);
      const combined = result.steps
        .map((step, index) => {
          const stdout = step.stdout?.trim();
          const stderr = step.stderr?.trim();
          const details = [stdout, stderr].filter(Boolean).join('\n');
          const header = `# ${index + 1}. ${step.step} (${step.ok ? 'OK' : 'FAIL'}, exit ${step.exit_code})`;
          return [header, step.command, details].filter(Boolean).join('\n');
        })
        .join('\n\n');
      let combinedOutput = combined || 'No output.';
      if (mode === 'nsec' && result.ok) {
        setSigningStatus('Clearing signed files for inline mode...');
        const maintenance = await postJson<MaintenanceResponse>(
          `${LAB_API_BASE}/maintenance/authoritative/clear-signed`,
          {},
          labHeaders
        );
        const maintenanceText = `${maintenance.command}\n\n${maintenance.stdout}${
          maintenance.stderr ? `\n${maintenance.stderr}` : ''
        }`.trim();
        combinedOutput = [
          combinedOutput,
          '',
          '# Clear signed files',
          maintenanceText || 'Maintenance completed.',
        ]
          .filter(Boolean)
          .join('\n');
        setSigningStatus(
          maintenance.ok
            ? 'Switched to NSEC and cleared signed files.'
            : 'Switched to NSEC but cleanup failed.'
        );
      } else {
        setSigningStatus(
          result.ok
            ? `Switched to ${mode.toUpperCase()}`
            : `Switch failed (mode ${mode.toUpperCase()})`
        );
      }
      setSigningOutput(combinedOutput);
      await loadIndicators();
    } catch (err) {
      setSigningStatus((err as Error).message);
      setSigningSteps([]);
    } finally {
      setSigningBusy(false);
    }
  };

  const downloadCapture = async (file: string) => {
    setIsBusy(true);
    setCaptureStatus(`Downloading ${file}...`);
    try {
      const res = await fetch(
        `${LAB_API_BASE}/capture/download?file=${encodeURIComponent(file)}`,
        { headers: labHeaders }
      );
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setCaptureStatus(`Downloaded ${file}`);
    } catch (err) {
      setCaptureStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const formatPrivacyResult = (result: PrivacyCheckResponse) => {
    const lines = [
      `kind: ${result.kind.toUpperCase()}`,
      `endpoint: ${result.endpoint}`,
      `method: ${result.method}`,
      `query: ${result.name} ${result.qtype}`,
      `rcode: ${result.rcode ?? 'unknown'}`,
      `response_bytes: ${result.response_bytes}`,
      `elapsed_ms: ${result.elapsed_ms}`,
    ];
    if (result.detail) {
      lines.push(`detail: ${result.detail}`);
    }
    return lines.join('\n');
  };

  const runPrivacyCheck = async (kind: 'dot' | 'doh') => {
    if (missingLabKey) {
      setPrivacyStatus('Missing Lab API key.');
      return;
    }
    setPrivacyBusy(true);
    setPrivacyStatus(`Running ${kind.toUpperCase()} check...`);
    setPrivacyOutput('');
    try {
      const result = await postJson<PrivacyCheckResponse>(
        `${LAB_API_BASE}/privacy/${kind}-check`,
        { name: req.name, qtype: req.qtype === 'AAAA' ? 'AAAA' : 'A' },
        labHeaders
      );
      setPrivacyOutput(formatPrivacyResult(result));
      if (!result.ok) {
        setPrivacyStatus(`${kind.toUpperCase()} check failed`);
      } else if (result.rcode === 'NOERROR') {
        setPrivacyStatus(`${kind.toUpperCase()} check OK (NOERROR)`);
      } else {
        setPrivacyStatus(
          `${kind.toUpperCase()} check completed (${result.rcode ?? 'unknown'})`
        );
      }
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setPrivacyStatus,
        setPrivacyOutput
      );
    } finally {
      setPrivacyBusy(false);
    }
  };

  const setPrivacyName = (name: string) => {
    setReq((prev) => ({ ...prev, name, qtype: 'A' }));
    setPrivacyStatus(`Privacy query set to ${name}.`);
    setPrivacyOutput('');
  };

  const fetchAvailabilityMetrics = async () => {
    if (missingLabKey) {
      setAvailabilityStatus('Missing Lab API key.');
      return;
    }
    setAvailabilityBusy(true);
    setAvailabilityStatus('Fetching resolver stats...');
    try {
      const result = await getJson<AvailabilityMetricsResponse>(
        `${LAB_API_BASE}/availability/metrics`,
        labHeaders
      );
      setAvailabilityMetrics(result);
      setAvailabilityUpdatedAt(new Date().toLocaleTimeString());
      setAvailabilityStatus('Metrics loaded.');
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setAvailabilityStatus,
        setAvailabilityOutput
      );
    } finally {
      setAvailabilityBusy(false);
    }
  };

  const runAvailabilityProbe = async () => {
    if (missingLabKey) {
      setAvailabilityStatus('Missing Lab API key.');
      return;
    }
    setAvailabilityBusy(true);
    setAvailabilityStatus('Running latency probe...');
    try {
      const body: AvailabilityProbeRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        count: probeCount,
      };
      const result = await postJson<AvailabilityProbeResponse>(
        `${LAB_API_BASE}/availability/probe`,
        body,
        labHeaders
      );
      setAvailabilityProbe(result);
      setAvailabilityUpdatedAt(new Date().toLocaleTimeString());
      setAvailabilityStatus(
        `Probe completed: avg ${result.avg_ms} ms (${result.count} queries).`
      );
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setAvailabilityStatus,
        setAvailabilityOutput
      );
    } finally {
      setAvailabilityBusy(false);
    }
  };

  const runAvailabilityLoad = async () => {
    if (missingLabKey) {
      setAvailabilityStatus('Missing Lab API key.');
      return;
    }
    setAvailabilityBusy(true);
    setAvailabilityStatus('Running low-rate load...');
    setAvailabilityOutput('');
    try {
      const body: AvailabilityLoadRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        count: loadCount,
        qps: loadQps,
      };
      const result = await postJson<AvailabilityLoadResponse>(
        `${LAB_API_BASE}/availability/load`,
        body,
        labHeaders
      );
      const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
      setAvailabilityOutput(`${result.command}\n\n${text}`.trim());
      setAvailabilityStatus(
        result.ok ? 'Load test completed.' : 'Load test completed with errors.'
      );
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setAvailabilityStatus,
        setAvailabilityOutput
      );
    } finally {
      setAvailabilityBusy(false);
    }
  };

  const runDnsperf = async () => {
    if (missingLabKey) {
      setDnsperfStatus('Missing Lab API key.');
      return;
    }
    setDnsperfBusy(true);
    setDnsperfStatus('Running dnsperf...');
    setDnsperfOutput('');
    setDnsperfSummary(null);
    try {
      const body: DnsperfRequest = {
        target: perfTarget,
        duration_s: dnsperfDuration,
        qps: dnsperfQps,
        max_queries: dnsperfMaxQueries,
        threads: dnsperfThreads,
        clients: dnsperfClients,
        queries: perfQueries.trim() ? perfQueries : undefined,
      };
      const result = await postJson<DnsperfResponse>(
        `${LAB_API_BASE}/perf/dnsperf`,
        body,
        labHeaders
      );
      const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
      setDnsperfOutput(`${result.command}\n\n${text}`.trim());
      setDnsperfSummary(result.summary ?? null);
      setDnsperfStatus(result.ok ? 'dnsperf completed.' : 'dnsperf completed with errors.');
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setDnsperfStatus,
        setDnsperfOutput
      );
    } finally {
      setDnsperfBusy(false);
    }
  };

  const runResperf = async () => {
    if (missingLabKey) {
      setResperfStatus('Missing Lab API key.');
      return;
    }
    setResperfBusy(true);
    setResperfStatus('Running resperf...');
    setResperfOutput('');
    setResperfPlotFile('');
    try {
      const body: ResperfRequest = {
        target: perfTarget,
        max_qps: resperfMaxQps,
        ramp_qps: resperfRampQps,
        clients: resperfClients,
        queries_per_step: resperfQueriesPerStep,
        plot_file: resperfPlotName.trim() ? resperfPlotName.trim() : undefined,
        queries: perfQueries.trim() ? perfQueries : undefined,
      };
      const result = await postJson<ResperfResponse>(
        `${LAB_API_BASE}/perf/resperf`,
        body,
        labHeaders
      );
      const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
      setResperfOutput(`${result.command}\n\n${text}`.trim());
      setResperfPlotFile(result.plot_file ?? '');
      setResperfStatus(result.ok ? 'resperf completed.' : 'resperf completed with errors.');
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setResperfStatus,
        setResperfOutput
      );
    } finally {
      setResperfBusy(false);
    }
  };

  const runFloodTest = async () => {
    if (missingLabKey) {
      setFloodStatus('Missing Lab API key.');
      return;
    }
    setFloodBusy(true);
    setFloodStatus('Running flooding guardrails...');
    setFloodSummary('');
    setFloodResults([]);
    try {
      const body: FloodTestRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        qps_start: floodStartQps,
        qps_end: floodEndQps,
        qps_step: floodStepQps,
        step_seconds: floodStepSeconds,
        max_outstanding: floodOutstanding,
        timeout_ms: floodTimeoutMs,
        stop_loss_pct: floodStopLoss,
        stop_p95_ms: floodStopP95,
        stop_servfail_pct: floodStopServfail,
        stop_cpu_pct: floodStopCpu,
      };
      const result = await postJson<FloodTestResponse>(
        `${LAB_API_BASE}/availability/flood`,
        body,
        labHeaders
      );
      setFloodResults(result.steps);
      const summary = result.stopped_early
        ? `Stopped early: ${result.stop_reason || 'guardrail'}`
        : 'Completed full ramp.';
      setFloodSummary(`${result.target} • ${summary}`);
      setFloodStatus(summary);
    } catch (err) {
      setFloodStatus((err as Error).message);
      setFloodResults([]);
    } finally {
      setFloodBusy(false);
    }
  };

  const runBaseline = async () => {
    if (missingLabKey) {
      setBaselineStatus('Missing Lab API key.');
      return;
    }
    setBaselineBusy(true);
    setBaselineStatus(`Collecting baseline (${baselineDuration}s)...`);
    setBaselineSummary(null);
    setBaselineCaptureFile('');
    const startedAt = Date.now();
    let captureFile: string | null = null;
    try {
      const before = await getJson<AvailabilityMetricsResponse>(
        `${LAB_API_BASE}/availability/metrics`,
        labHeaders
      );
      const stats = await getJson<ResolverStatsResponse>(
        `${LAB_API_BASE}/availability/resolver-stats?resolver=${req.resolver}`,
        labHeaders
      );
      try {
        const captureStart = await postJson<CaptureStartResponse>(
          `${LAB_API_BASE}/capture/start`,
          { target: 'authoritative', filter: 'dns' },
          labHeaders
        );
        captureFile = captureStart.file;
      } catch (err) {
        if (!(err as Error).message.includes('HTTP 409')) {
          throw err;
        }
      }

      await new Promise((resolve) => setTimeout(resolve, baselineDuration * 1000));

      let upstreamQueries: number | undefined;
      if (captureFile) {
        try {
          await postJson<CaptureStopResponse>(
            `${LAB_API_BASE}/capture/stop`,
            { target: 'authoritative' },
            labHeaders
          );
          const summary = await getJson<CaptureSummaryResponse>(
            `${LAB_API_BASE}/capture/summary?file=${encodeURIComponent(captureFile)}`,
            labHeaders
          );
          upstreamQueries = summary.upstream_queries;
        } catch {
          // ignore capture errors
        }
      }

      const after = await getJson<AvailabilityMetricsResponse>(
        `${LAB_API_BASE}/availability/metrics`,
        labHeaders
      );
      const probeBody: AvailabilityProbeRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        count: baselineProbeCount,
      };
      const probe = await postJson<AvailabilityProbeResponse>(
        `${LAB_API_BASE}/availability/probe`,
        probeBody,
        labHeaders
      );

      const elapsed = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
      const totalDelta = after.totals.queries - before.totals.queries;
      const qps = totalDelta / elapsed;

      setBaselineSummary({
        duration_s: elapsed,
        qps,
        total_queries: totalDelta,
        cache_hit_ratio: after.ratios.cache_hit,
        nxdomain_ratio: after.ratios.nxdomain,
        servfail_ratio: after.ratios.servfail,
        p50_ms: probe.p50_ms ?? probe.avg_ms,
        p95_ms: probe.p95_ms ?? probe.max_ms,
        cpu_pct: stats.cpu_pct,
        mem_mb: stats.mem_bytes ? stats.mem_bytes / (1024 * 1024) : undefined,
        mem_pct: stats.mem_pct,
        upstream_qps:
          upstreamQueries !== undefined ? upstreamQueries / elapsed : undefined,
        upstream_queries: upstreamQueries,
        capture_file: captureFile ?? undefined,
      });
      if (captureFile) {
        setBaselineCaptureFile(captureFile);
      }
      setBaselineStatus('Baseline completed.');
    } catch (err) {
      setBaselineStatus((err as Error).message);
    } finally {
      setBaselineBusy(false);
    }
  };

  const runWarmup = async () => {
    if (missingLabKey) {
      setBaselineStatus('Missing Lab API key.');
      return;
    }
    setWarmupBusy(true);
    setBaselineStatus('Running warm-up (short load)...');
    try {
      const body: AvailabilityLoadRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        count: 50,
        qps: 20,
      };
      await postJson<AvailabilityLoadResponse>(
        `${LAB_API_BASE}/availability/load`,
        body,
        labHeaders
      );
      setBaselineStatus('Warm-up completed.');
    } catch (err) {
      setBaselineStatus((err as Error).message);
    } finally {
      setWarmupBusy(false);
    }
  };

  const startCooldown = (seconds: number) => {
    setCooldownRemaining(seconds);
    const start = Date.now();
    const timer = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000);
      const remaining = Math.max(0, seconds - elapsed);
      setCooldownRemaining(remaining);
      if (remaining === 0) {
        window.clearInterval(timer);
      }
    }, 500);
  };

  const restartResolver = async () => {
    if (missingLabKey) {
      setBaselineStatus('Missing Lab API key.');
      return;
    }
    setBaselineStatus('Restarting resolver (flush all cache)...');
    try {
      await postJson<LabDigResponse>(`${LAB_API_BASE}/resolver/restart`, {}, labHeaders);
      setBaselineStatus('Resolver restarted.');
    } catch (err) {
      setBaselineStatus((err as Error).message);
    }
  };

  const flushResolver = async () => {
    if (missingLabKey) {
      setBaselineStatus('Missing Lab API key.');
      return;
    }
    setBaselineStatus('Flushing resolver cache (example.test)...');
    try {
      await postJson<LabDigResponse>(
        `${LAB_API_BASE}/resolver/flush`,
        { zone: 'example.test' },
        labHeaders
      );
      setBaselineStatus('Resolver cache flushed.');
    } catch (err) {
      setBaselineStatus((err as Error).message);
    }
  };

  const loadServiceLimits = async () => {
    if (missingLabKey) {
      setLimitsStatus('Missing Lab API key.');
      return;
    }
    setLimitsBusy(true);
    setLimitsStatus('Loading service limit configs...');
    try {
      const [unboundCfg, bindCfg] = await Promise.all([
        getJson<ConfigFileResponse>(
          `${LAB_API_BASE}/config/file?path=${encodeURIComponent(
            'unbound/unbound.conf'
          )}`,
          labHeaders
        ),
        getJson<ConfigFileResponse>(
          `${LAB_API_BASE}/config/file?path=${encodeURIComponent(
            'bind/named.conf'
          )}`,
          labHeaders
        ),
      ]);

      const unboundKeys = [
        'num-queries-per-thread',
        'outgoing-range',
        'outgoing-num-tcp',
        'ratelimit',
        'ip-ratelimit',
        'msg-cache-size',
        'rrset-cache-size',
        'neg-cache-size',
      ];
      const unboundLines = unboundKeys.map((key) => {
        const value = readConfigValue(unboundCfg.content, key);
        return `${key}: ${value ?? 'not set'}`;
      });
      setUnboundLimitLines(unboundLines);

      const rrlBlock = extractBlock(bindCfg.content, 'rate-limit');
      setBindRrlBlock(rrlBlock || 'rate-limit block not found.');
      setBindRrlEnabled(Boolean(rrlBlock));
      setLimitsStatus('Loaded service limits.');
    } catch (err) {
      setLimitsStatus((err as Error).message);
      setUnboundLimitLines([]);
      setBindRrlBlock('');
      setBindRrlEnabled(null);
    } finally {
      setLimitsBusy(false);
    }
  };

  const runRateLimitProof = async () => {
    if (missingLabKey) {
      setLimitsStatus('Missing Lab API key.');
      return;
    }
    setLimitsBusy(true);
    setLimitsStatus('Running rate-limit proof (baseline -> flood -> metrics)...');
    setRateLimitDelta(null);
    setRateLimitAfter(null);
    try {
      const before = await getJson<AvailabilityMetricsResponse>(
        `${LAB_API_BASE}/availability/metrics`,
        labHeaders
      );
      const floodBody: FloodTestRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: req.name,
        qtype: req.qtype,
        qps_start: 120,
        qps_end: 120,
        qps_step: 1,
        step_seconds: 10,
        max_outstanding: 200,
        timeout_ms: 1000,
        stop_loss_pct: 0,
        stop_p95_ms: 0,
        stop_servfail_pct: 0,
        stop_cpu_pct: 0,
      };
      await postJson<FloodTestResponse>(
        `${LAB_API_BASE}/availability/flood`,
        floodBody,
        labHeaders
      );
      const after = await getJson<AvailabilityMetricsResponse>(
        `${LAB_API_BASE}/availability/metrics`,
        labHeaders
      );
      setRateLimitAfter(after);
      setRateLimitDelta({
        ratelimited: after.totals.ratelimited - before.totals.ratelimited,
        ip_ratelimited: after.totals.ip_ratelimited - before.totals.ip_ratelimited,
        total: after.totals.queries - before.totals.queries,
      });
      setLimitsStatus('Rate-limit proof completed.');
    } catch (err) {
      setLimitsStatus((err as Error).message);
      setRateLimitDelta(null);
      setRateLimitAfter(null);
    } finally {
      setLimitsBusy(false);
    }
  };

  const runRrlTest = async () => {
    if (missingLabKey) {
      setRrlStatus('Missing Lab API key.');
      return;
    }
    setLimitsBusy(true);
    setRrlStatus('Running BIND RRL test...');
    setRrlResult(null);
    try {
      const body: RrlTestRequest = {
        name: 'example.test',
        qtype: 'A',
        count: rrlCount,
        log_tail: 200,
      };
      const result = await postJson<RrlTestResponse>(
        `${LAB_API_BASE}/availability/rrl-test`,
        body,
        labHeaders
      );
      setRrlResult(result);
      setRrlStatus(
        result.rrl_enabled
          ? result.matches.length > 0
            ? `RRL log hits: ${result.matches.length}`
            : 'RRL enabled but no log hits detected.'
          : 'RRL disabled. Enable in Controls.'
      );
    } catch (err) {
      setRrlStatus((err as Error).message);
      setRrlResult(null);
    } finally {
      setLimitsBusy(false);
    }
  };

  const toggleAmpQtype = (qtype: string) => {
    setAmpQtypes((prev) =>
      prev.includes(qtype) ? prev.filter((q) => q !== qtype) : [...prev, qtype]
    );
  };

  const toggleAmpEdns = (size: number) => {
    setAmpEdnsSizes((prev) =>
      prev.includes(size) ? prev.filter((s) => s !== size) : [...prev, size]
    );
  };

  const runAmplificationTest = async () => {
    if (missingLabKey) {
      setAmpStatus('Missing Lab API key.');
      return;
    }
    if (ampQtypes.length === 0 || ampEdnsSizes.length === 0) {
      setAmpStatus('Select at least one qtype and EDNS size.');
      return;
    }
    setAmpBusy(true);
    setAmpStatus('Running amplification test...');
    try {
      const body: AmplificationTestRequest = {
        profile: req.client,
        resolver: req.resolver,
        name: ampName,
        qtypes: ampQtypes,
        edns_sizes: ampEdnsSizes,
        count_per_qtype: ampCount,
        dnssec: ampDnssec,
        tcp_fallback: ampTcpFallback,
      };
      const result = await postJson<AmplificationTestResponse>(
        `${LAB_API_BASE}/amplification/test`,
        body,
        labHeaders
      );
      setAmpResults(result.results);
      setAmpStatus(`Completed (${result.results.length} rows).`);
    } catch (err) {
      setAmpStatus((err as Error).message);
      setAmpResults([]);
    } finally {
      setAmpBusy(false);
    }
  };

  const runMixLoad = async () => {
    if (missingLabKey) {
      setMixStatus('Missing Lab API key.');
      return;
    }
    setMixBusy(true);
    setMixStatus('Running mixed load...');
    try {
      const body: MixLoadRequest = {
        profile: req.client,
        resolver: req.resolver,
        zone: mixZone,
        count: mixCount,
        edns_size: mixEdns,
        dnssec: mixDnssec,
        tcp_fallback: mixTcpFallback,
      };
      const result = await postJson<MixLoadResponse>(
        `${LAB_API_BASE}/amplification/mix`,
        body,
        labHeaders
      );
      setMixResult(result);
      setMixStatus('Mix run completed.');
    } catch (err) {
      setMixStatus((err as Error).message);
      setMixResult(null);
    } finally {
      setMixBusy(false);
    }
  };

  const loadControls = async () => {
    if (missingLabKey) {
      setControlsStatus('Missing Lab API key.');
      return;
    }
    setControlsBusy(true);
    setControlsStatus('Loading controls...');
    try {
      const result = await getJson<ControlsStatusResponse>(
        `${LAB_API_BASE}/controls/status`,
        labHeaders
      );
      setUnboundCtl(result.unbound);
      setBindCtl(result.bind);
      setControlsStatus('Loaded.');
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setControlsStatus
      );
    } finally {
      setControlsBusy(false);
    }
  };

  const applyControls = async () => {
    if (missingLabKey) {
      setControlsStatus('Missing Lab API key.');
      return;
    }
    setControlsBusy(true);
    setControlsStatus('Applying controls...');
    try {
      const result = await postJson<ControlsStatusResponse>(
        `${LAB_API_BASE}/controls/apply`,
        { unbound: unboundCtl, bind: bindCtl },
        labHeaders
      );
      setUnboundCtl(result.unbound);
      setBindCtl(result.bind);
      setControlsStatus('Applied and restarted services.');
      await fetchAvailabilityMetrics();
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setControlsStatus
      );
    } finally {
      setControlsBusy(false);
    }
  };

  return (
    <div className="page">
      <header className="hero">
        <div className="hero-main">
          <div className="eyebrow">DNS Security Lab</div>
          <h1>DNS Security Control System</h1>
          <p>
            One-page console for queries, DNSSEC validation, privacy checks, and
            safe operational controls across the lab stack.
          </p>
          <div className="hero-actions">
            <button onClick={checkHealth} disabled={isBusy}>
              Health Check
            </button>
            <button onClick={loadIndicators} disabled={isBusy || missingLabKey}>
              Refresh Indicators
            </button>
            <button onClick={fetchAvailabilityMetrics} disabled={availabilityBusy || missingLabKey}>
              Fetch Metrics
            </button>
          </div>
        </div>
        <div className="hero-panel">
          <div className="hero-card">
            <div className="hero-label">Active API</div>
            <div className="hero-value">
              {backend === 'client' ? 'Client API' : 'Lab API'}
            </div>
            <div className="hero-sub">
              {backend === 'client' ? clientBase : LAB_API_BASE}
            </div>
          </div>
          <div className="hero-card">
            <div className="hero-label">Resolver</div>
            <div className="hero-value">{resolverLabel}</div>
            <div className="hero-sub">Profile: {req.client}</div>
          </div>
          <div className="hero-card">
            <div className="hero-label">Key Indicators</div>
            <div className="hero-pills">
              <span className={`status-pill ${indicatorClass(indicators.nsec3Child)}`}>
                Child NSEC3
              </span>
              <span className={`status-pill ${indicatorClass(indicators.nsec3Parent)}`}>
                Parent NSEC3
              </span>
              <span className={`status-pill ${indicatorClass(indicators.aggressiveNsec)}`}>
                Aggressive NSEC
              </span>
              <span className={`status-pill ${indicatorClass(indicators.qnameMinim)}`}>
                QNAME Min
              </span>
            </div>
            <div className="hero-sub">
              Updated: {indicators.updatedAt || 'not loaded'}
            </div>
          </div>
        </div>
      </header>

      <nav className="section-tabs">
        {SECTION_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={activeSection === tab.id ? 'active' : ''}
            onClick={() => selectSection(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {backend === 'lab_api' && missingLabKey && (
        <div className="alert">
          <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
          <code>.env.local</code> to match <code>LAB_API_KEY</code> from
          <code>docker-compose.yml</code>.
        </div>
      )}

      {isSectionVisible('overview') && (
      <section className="card overview-card" id="overview">
        <div className="card-title">Overview</div>
        <div className="overview-grid">
          <div className="overview-tile">
            <div className="overview-label">Status</div>
            <div className="overview-value">{status || 'Ready'}</div>
            <div className="overview-sub">Dig + health feedback</div>
          </div>
          <div className="overview-tile">
            <div className="overview-label">Availability</div>
            <div className="overview-value">
              {availabilityMetrics ? `${availabilityMetrics.totals.queries} queries` : 'Not loaded'}
            </div>
            <div className="overview-sub">
              Updated: {availabilityUpdatedAt || '—'}
            </div>
          </div>
          <div className="overview-tile">
            <div className="overview-label">Privacy</div>
            <div className="overview-value">
              QNAME: {formatIndicator(indicators.qnameMinim)}
            </div>
            <div className="overview-sub">DoT + DoH enabled</div>
          </div>
          <div className="overview-tile">
            <div className="overview-label">Capture</div>
            <div className="overview-value">
              Resolver: {captureRunning.resolver ? 'running' : 'idle'}
            </div>
            <div className="overview-sub">
              Auth: {captureRunning.authoritative ? 'running' : 'idle'}
            </div>
          </div>
        </div>
      </section>
      )}

      {isSectionVisible('topology') && (
      <section className="card" id="topology">
        <div className="card-title">Nodes / Topology</div>
        <div className="topology-grid">
          {TOPOLOGY_NODES.map((node) => (
            <div key={node.name} className="node-card">
              <div className="node-header">
                <div className="node-title">{node.name}</div>
                <button
                  type="button"
                  className={`status-dot action ${healthClass(node.health)}`}
                  onClick={scrollToConfigs}
                  title="Open config viewer"
                >
                  {healthLabel(node.health)}
                </button>
              </div>
              <div className="node-role">{node.role}</div>
              <div className="node-meta">
                <div>
                  <strong>IP:</strong> {node.ip}
                </div>
                <div>
                  <strong>Ports:</strong> {node.ports}
                </div>
              </div>
              <div className="node-tags">
                {node.tags.map((tag) => (
                  <span key={tag} className="tag">
                    {tag}
                  </span>
                ))}
              </div>
              <ul className="node-list">
                {node.meta.map((meta) => (
                  <li key={meta}>{meta}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="topology-notes">
          <div className="notes-panel">
            <div className="notes-title">React UI MVP checklist</div>
            {MVP_UI_NOTES.map((section) => (
              <div key={section.title} className="notes-section">
                <div className="notes-heading">{section.title}</div>
                <ul>
                  {section.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="notes-image">
            <img src="/ui-notes.svg" alt="MVP UI notes reference" />
          </div>
        </div>
      </section>
      )}

      {isSectionVisible('dig') && (
      <section className="card" id="dig">
        <div className="card-title">Dig Request</div>
        <div className="grid">
          <label>
            Execute via
            <select
              value={backend}
              onChange={(e) => setBackend(e.target.value as Backend)}
            >
              <option value="client">client API</option>
              <option value="lab_api">lab API</option>
            </select>
          </label>

          <label>
            Client
            <select
              value={req.client}
              onChange={(e) =>
                setReq({ ...req, client: e.target.value as Client })
              }
            >
              <option value="trusted">trusted</option>
              <option value="untrusted">untrusted</option>
              <option value="mgmt">mgmt</option>
            </select>
          </label>

          <label>
            Resolver
            <select
              value={req.resolver}
              onChange={(e) =>
                setReq({ ...req, resolver: e.target.value as ResolverKind })
              }
            >
              <option value="valid">validating</option>
              <option value="plain">plain</option>
            </select>
          </label>

          <label>
            Name
            <input
              value={req.name}
              onChange={(e) => setReq({ ...req, name: e.target.value })}
              placeholder="www.example.test"
            />
          </label>

          <label>
            Type
            <select
              value={req.qtype}
              onChange={(e) => setReq({ ...req, qtype: e.target.value })}
            >
              {[
                'A',
                'AAAA',
                'CAA',
                'CNAME',
                'DS',
                'DNSKEY',
                'MX',
                'NS',
                'NSEC',
                'NSEC3',
                'NSEC3PARAM',
                'RRSIG',
                'SOA',
                'SRV',
                'TXT',
                'ANY',
              ].map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>

          <label className="toggle">
            <input
              type="checkbox"
              checked={req.dnssec}
              onChange={(e) => setReq({ ...req, dnssec: e.target.checked })}
            />
            DNSSEC
          </label>

          <label className="toggle">
            <input
              type="checkbox"
              checked={req.trace}
              onChange={(e) => setReq({ ...req, trace: e.target.checked })}
            />
            Trace
          </label>

          <label className="toggle">
            <input
              type="checkbox"
              checked={req.short}
              onChange={(e) => setReq({ ...req, short: e.target.checked })}
            />
            Short
          </label>
        </div>

        <div className="actions">
          <button onClick={runDig} disabled={isBusy}>
            Run Dig
          </button>
          <button onClick={checkHealth} disabled={isBusy}>
            Health
          </button>
          <button onClick={() => viewLogs('bind')} disabled={isBusy}>
            Bind Logs
          </button>
          <button onClick={() => viewLogs('unbound')} disabled={isBusy}>
            Unbound Logs
          </button>
        </div>

        <div className="status">{status || 'Ready.'}</div>
      </section>
      )}

      {isSectionVisible('output') && (
      <section className="card" id="output" ref={outputRef}>
        <div className="card-title">Output</div>
        <pre className="output">
          {output ? `${output.command}\n\n${output.text}` : 'No output yet.'}
        </pre>
      </section>
      )}

      {isSectionVisible('dnssec') && (
      <section className="card" id="dnssec">
        <div className="card-title">NSEC3 / Aggressive NSEC</div>
        <div className="hint">
          <div>
            <strong>NSEC3 signing:</strong> detected from signed zone files when
            available (falls back to the unsigned zone file if no signed file is
            present).
          </div>
          <div>
            <strong>Aggressive NSEC:</strong> enabled on the validating resolver
            (<code>aggressive-nsec: yes</code>).
          </div>
        </div>
        <div className="indicator-row">
          <div className={`indicator ${indicatorClass(indicators.nsec3Child)}`}>
            <span className="indicator-dot" />
            Child NSEC3: {formatIndicator(indicators.nsec3Child)}
          </div>
          <div className={`indicator ${indicatorClass(indicators.nsec3Parent)}`}>
            <span className="indicator-dot" />
            Parent NSEC3: {formatIndicator(indicators.nsec3Parent)}
          </div>
          <div className={`indicator ${indicatorClass(indicators.aggressiveNsec)}`}>
            <span className="indicator-dot" />
            Aggressive NSEC: {formatIndicator(indicators.aggressiveNsec)}
          </div>
          <div className={`indicator ${indicatorClass(indicators.qnameMinim)}`}>
            <span className="indicator-dot" />
            QNAME Minimization: {formatIndicator(indicators.qnameMinim)}
          </div>
        </div>
        <div className="indicator-meta">
          <div>Child: {indicators.childDetail || 'not checked'}</div>
          <div>Parent: {indicators.parentDetail || 'not checked'}</div>
          <div>Aggressive: {indicators.aggressiveDetail || 'not checked'}</div>
          <div>QNAME: {indicators.qnameDetail || 'not checked'}</div>
          <div>
            Status: {indicators.message}{' '}
            {indicators.updatedAt ? `(${indicators.updatedAt})` : ''}
          </div>
        </div>
        <div className="actions">
          <button
            onClick={() => switchSigningMode('nsec3')}
            disabled={isBusy || signingBusy || missingLabKey}
          >
            Switch to NSEC3 (offline)
          </button>
          <button
            onClick={() => switchSigningMode('nsec')}
            disabled={isBusy || signingBusy || missingLabKey}
          >
            Switch to NSEC (inline)
          </button>
          <button
            onClick={clearAuthoritativeSigned}
            disabled={isBusy || signingBusy || missingLabKey}
          >
            Clear Signed Files
          </button>
          <button onClick={loadIndicators} disabled={isBusy || missingLabKey}>
            Refresh Indicators
          </button>
        </div>
        <div className="status">
          {signingStatus ||
            'Use the switch buttons to change between inline NSEC and offline NSEC3.'}
        </div>
        {signingSteps.length > 0 && (
          <div className="step-list">
            {signingSteps.map((step, index) => {
              const detail = [step.stdout?.trim(), step.stderr?.trim()]
                .filter(Boolean)
                .join('\n');
              return (
                <div
                  key={`${step.step}-${index}`}
                  className={`step-item ${step.ok ? 'ok' : 'fail'}`}
                >
                  <div className="step-header">
                    <div className="step-label">
                      {index + 1}. {step.step}
                    </div>
                    <span className={`step-badge ${step.ok ? 'ok' : 'fail'}`}>
                      {step.ok ? 'OK' : 'FAIL'}
                    </span>
                  </div>
                  <div className="step-command">{step.command}</div>
                  {detail && <pre className="step-output">{detail}</pre>}
                </div>
              );
            })}
          </div>
        )}
        <pre className="output">
          {signingOutput || 'No switch output yet.'}
        </pre>
        <div className="preset-grid">
          <div className="preset">
            <div className="preset-title">NSEC3 Proof (NXDOMAIN)</div>
            <div className="preset-desc">
              Query a non-existent name with DNSSEC enabled to see NSEC3 proof.
            </div>
            <div className="actions">
              <button onClick={applyNsec3ProofPreset} disabled={isBusy}>
                Load Preset
              </button>
              <button onClick={runNsec3Proof} disabled={isBusy}>
                Run Query
              </button>
              <button onClick={clearOutput} disabled={isBusy}>
                Clear Output
              </button>
            </div>
          </div>
          <div className="preset">
            <div className="preset-title">QNAME Minimization (Privacy)</div>
            <div className="preset-desc">
              Query a deep name; check the QNAME indicator to confirm minimisation.
            </div>
            <div className="actions">
              <button onClick={applyQnameMinPreset} disabled={isBusy}>
                Load Preset
              </button>
              <button onClick={runQnameMin} disabled={isBusy}>
                Run Query
              </button>
              <button onClick={clearOutput} disabled={isBusy}>
                Clear Output
              </button>
            </div>
          </div>
          <div className="preset">
          <div className="preset-title">Aggressive NSEC Demo</div>
          <div className="preset-desc">
            Runs two NXDOMAIN queries; the second should be synthesized from cached
            denial proofs.
          </div>
          <div className="preset-note">
            This demo intentionally uses two non-existent names to validate
            aggressive NSEC behavior. NXDOMAIN is expected.
          </div>
          <div className="actions">
            <button onClick={runAggressiveNsecDemo} disabled={isBusy}>
              Run Demo
            </button>
            <button
              onClick={runAggressiveNsecProof}
              disabled={isBusy || proofBusy || missingLabKey}
            >
              Run Demo + Proof
            </button>
            <button
              onClick={runAggressiveNsecProofCold}
              disabled={isBusy || proofBusy || missingLabKey}
            >
              Run Demo + Proof (Cold)
            </button>
            <button
              onClick={() => proofCaptureFile && downloadCapture(proofCaptureFile)}
              disabled={
                isBusy || proofBusy || missingLabKey || !proofCaptureFile
              }
            >
              Download PCAP
            </button>
            <button onClick={clearProofOutput} disabled={isBusy || proofBusy}>
              Clear Proof
            </button>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              checked={proofColdCache}
              onChange={(e) => {
                setProofColdCache(e.target.checked);
                if (e.target.checked) {
                  setProofFlushCache(false);
                }
              }}
            />
            Restart resolver (clear cache)
          </label>
          <label className="toggle">
            <input
              type="checkbox"
              checked={proofFlushCache}
              onChange={(e) => {
                setProofFlushCache(e.target.checked);
                if (e.target.checked) {
                  setProofColdCache(false);
                }
              }}
            />
            Flush resolver cache (example.test)
          </label>
        </div>
      </div>
      <div className="status">
        {proofStatus ||
          'Use "Run Demo + Proof" to capture authoritative traffic and count upstream queries.'}
      </div>
      <pre className="output">{proofOutput || 'No proof output yet.'}</pre>
      </section>
      )}

    {isSectionVisible('privacy') && (
    <section className="card" id="privacy">
      <div className="card-title">DNS Query Privacy</div>
      <div className="hint">
        Transport privacy and log minimization (DoT, DoH, QNAME minimization).
      </div>
      <div className="indicator-row">
        <div className={`indicator ${indicatorClass(indicators.qnameMinim)}`}>
          <span className="indicator-dot" />
          QNAME Minimization: {formatIndicator(indicators.qnameMinim)}
        </div>
        <div className="indicator enabled">
          <span className="indicator-dot" />
          DoT: configured
        </div>
        <div className="indicator enabled">
          <span className="indicator-dot" />
          DoH: configured
        </div>
        <div className="indicator enabled">
          <span className="indicator-dot" />
          Logs: minimized
        </div>
      </div>
      <div className="config-tabs privacy-tabs">
        <button
          className={privacyTab === 'overview' ? 'active' : ''}
          onClick={() => setPrivacyTab('overview')}
          disabled={isBusy}
        >
          Overview
        </button>
        <button
          className={privacyTab === 'dot' ? 'active' : ''}
          onClick={() => setPrivacyTab('dot')}
          disabled={isBusy}
        >
          DoT
        </button>
        <button
          className={privacyTab === 'doh' ? 'active' : ''}
          onClick={() => setPrivacyTab('doh')}
          disabled={isBusy}
        >
          DoH
        </button>
        <button
          className={privacyTab === 'logs' ? 'active' : ''}
          onClick={() => setPrivacyTab('logs')}
          disabled={isBusy}
        >
          Logs
        </button>
      </div>

      {privacyTab === 'overview' && (
        <div className="privacy-panel">
          <div className="privacy-block">
            <div className="privacy-title">What it protects</div>
            <ul>
              <li>Observation of DNS queries (who, what, when).</li>
              <li>Metadata leakage from deep names.</li>
            </ul>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">In this lab</div>
            <ul>
              <li>QNAME minimization in Unbound.</li>
              <li>DoT on resolver (TCP 853, TLS).</li>
              <li>DoH sidecar proxy on HTTPS 443.</li>
              <li>Query logging disabled in Unbound and BIND.</li>
            </ul>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Risks / tradeoffs</div>
            <ul>
              <li>Centralization with large DoH providers.</li>
              <li>Harder enterprise filtering and monitoring.</li>
              <li>DoH can bypass local split-horizon policy.</li>
            </ul>
          </div>
        </div>
      )}

      {privacyTab === 'dot' && (
        <div className="privacy-panel">
          <div className="privacy-block">
            <div className="privacy-title">Endpoint</div>
            <div className="privacy-text">
              DoT proxy is exposed on <code>127.0.0.1:853</code> (TCP).
            </div>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Quick check</div>
            <pre className="output compact">
              {`openssl s_client -connect 127.0.0.1:853 -servername resolver.test`}
            </pre>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Query target</div>
            <div className="privacy-text">
              Current: <code>{req.name}</code> ({req.qtype})
            </div>
            <div className="privacy-choice">
              <button
                type="button"
                className={req.name === PRIVACY_EXISTING_NAME ? 'active' : ''}
                onClick={() => setPrivacyName(PRIVACY_EXISTING_NAME)}
                disabled={privacyBusy}
              >
                Use existing
              </button>
              <button
                type="button"
                className={req.name === PRIVACY_NONEXISTENT_NAME ? 'active' : ''}
                onClick={() => setPrivacyName(PRIVACY_NONEXISTENT_NAME)}
                disabled={privacyBusy}
              >
                Use non-existent
              </button>
            </div>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Query example</div>
            <pre className="output compact">
              {`kdig +tls @127.0.0.1 -p 853 www.example.test`}
            </pre>
            <div className="privacy-text">
              Self-signed certs are generated on startup in{' '}
              <code>dot_proxy/certs</code>.
            </div>
          </div>
          <div className="privacy-actions">
            <button
              onClick={() => runPrivacyCheck('dot')}
              disabled={privacyBusy || missingLabKey}
            >
              Run DoT Check
            </button>
          </div>
        </div>
      )}

      {privacyTab === 'doh' && (
        <div className="privacy-panel">
          <div className="privacy-block">
            <div className="privacy-title">Endpoint</div>
            <div className="privacy-text">
              DoH proxy is exposed at <code>https://127.0.0.1:8443/dns-query</code>.
            </div>
            <div className="privacy-text">
              Health check: <code>https://127.0.0.1:8443/health</code>
            </div>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Quick check</div>
            <pre className="output compact">
              {`curl -k https://127.0.0.1:8443/health`}
            </pre>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Query target</div>
            <div className="privacy-text">
              Current: <code>{req.name}</code> ({req.qtype})
            </div>
            <div className="privacy-choice">
              <button
                type="button"
                className={req.name === PRIVACY_EXISTING_NAME ? 'active' : ''}
                onClick={() => setPrivacyName(PRIVACY_EXISTING_NAME)}
                disabled={privacyBusy}
              >
                Use existing
              </button>
              <button
                type="button"
                className={req.name === PRIVACY_NONEXISTENT_NAME ? 'active' : ''}
                onClick={() => setPrivacyName(PRIVACY_NONEXISTENT_NAME)}
                disabled={privacyBusy}
              >
                Use non-existent
              </button>
            </div>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Notes</div>
            <ul>
              <li>Self-signed TLS cert (accept or skip verification).</li>
              <li>Upstream is the validating resolver on port 53.</li>
            </ul>
          </div>
          <div className="privacy-actions">
            <button
              onClick={() => runPrivacyCheck('doh')}
              disabled={privacyBusy || missingLabKey}
            >
              Run DoH Check
            </button>
          </div>
        </div>
      )}

      {privacyTab === 'logs' && (
        <div className="privacy-panel">
          <div className="privacy-block">
            <div className="privacy-title">Unbound</div>
            <ul>
              <li>
                <code>log-queries: no</code>, <code>log-replies: no</code>,
                <code>log-local-actions: no</code>
              </li>
              <li>
                <code>log-tag-queryreply: no</code>, <code>log-servfail: no</code>
              </li>
            </ul>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">BIND</div>
            <ul>
              <li>
                <code>category queries &#123; null; &#125;</code>
              </li>
              <li>
                <code>category client &#123; null; &#125;</code>
              </li>
            </ul>
          </div>
          <div className="privacy-block">
            <div className="privacy-title">Why</div>
            <div className="privacy-text">
              Minimizes retained query metadata while preserving operational logs.
            </div>
          </div>
        </div>
      )}
      <div className="status">{privacyStatus || 'Ready.'}</div>
      <pre className="output">{privacyOutput || 'No privacy checks yet.'}</pre>
    </section>
    )}

      {isSectionVisible('availability') && (
      <section className="card" id="availability">
        <div className="card-title">Availability / Abuse Resistance</div>
        <div className="hint">
          <div>
            Monitors resolver health signals (NXDOMAIN, SERVFAIL, latency) and
            runs controlled local load. Uses the current query settings above.
          </div>
          <div>
            Target: <strong>{resolverLabel}</strong> • Name:{' '}
            <code>{req.name}</code> • QTYPE: <code>{req.qtype}</code> • Client:{' '}
            <code>{req.client}</code>
          </div>
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="indicator-row">
          <div className={`indicator ${ratioClass(nxdomainRatio, 0.2)}`}>
            <span className="indicator-dot" />
            NXDOMAIN: {formatPercent(nxdomainRatio)}
          </div>
          <div className={`indicator ${ratioClass(servfailRatio, 0.05)}`}>
            <span className="indicator-dot" />
            SERVFAIL: {formatPercent(servfailRatio)}
          </div>
          <div className={`indicator ${ratioClass(ratelimitRatio, 0.02)}`}>
            <span className="indicator-dot" />
            Rate-limited: {formatPercent(ratelimitRatio)}
          </div>
          <div className={`indicator ${ratioClass(ipRatelimitRatio, 0.02)}`}>
            <span className="indicator-dot" />
            IP rate-limited: {formatPercent(ipRatelimitRatio)}
          </div>
        </div>
        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">Total queries</div>
            <div className="metric-value">
              {availabilityMetrics ? availabilityMetrics.totals.queries : '—'}
            </div>
            <div className="metric-sub">
              Cache hit ratio: {formatPercent(cacheHitRatio)}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">NXDOMAIN</div>
            <div className="metric-value">
              {availabilityMetrics ? availabilityMetrics.totals.nxdomain : '—'}
            </div>
            <div className="metric-sub">
              SERVFAIL: {availabilityMetrics ? availabilityMetrics.totals.servfail : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Rate limited</div>
            <div className="metric-value">
              {availabilityMetrics ? availabilityMetrics.totals.ratelimited : '—'}
            </div>
            <div className="metric-sub">
              IP rate-limited:{' '}
              {availabilityMetrics ? availabilityMetrics.totals.ip_ratelimited : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Avg recursion</div>
            <div className="metric-value">
              {availabilityMetrics ? `${availabilityMetrics.avg_recursion_ms} ms` : '—'}
            </div>
            <div className="metric-sub">
              Probe avg:{' '}
              {availabilityProbe ? `${availabilityProbe.avg_ms} ms` : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Probe min/max</div>
            <div className="metric-value">
              {availabilityProbe
                ? `${availabilityProbe.min_ms} / ${availabilityProbe.max_ms} ms`
                : '—'}
            </div>
            <div className="metric-sub">
              RCODES:{' '}
              {availabilityProbe
                ? Object.entries(availabilityProbe.rcode_counts)
                    .map(([k, v]) => `${k}:${v}`)
                    .join(' ')
                : '—'}
            </div>
          </div>
        </div>
        <div className="grid">
          <label>
            Probe count
            <input
              type="number"
              min={1}
              max={30}
              value={probeCount}
              onChange={(e) => setProbeCount(Number(e.target.value))}
              disabled={availabilityBusy}
            />
          </label>
          <label>
            Load count
            <input
              type="number"
              min={1}
              max={600}
              value={loadCount}
              onChange={(e) => setLoadCount(Number(e.target.value))}
              disabled={availabilityBusy}
            />
          </label>
          <label>
            Load QPS
            <input
              type="number"
              min={1}
              max={100}
              value={loadQps}
              onChange={(e) => setLoadQps(Number(e.target.value))}
              disabled={availabilityBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button
            onClick={fetchAvailabilityMetrics}
            disabled={availabilityBusy || missingLabKey}
          >
            Fetch Stats
          </button>
          <button
            onClick={runAvailabilityProbe}
            disabled={availabilityBusy || missingLabKey}
          >
            Run Latency Probe
          </button>
          <button
            onClick={runAvailabilityLoad}
            disabled={availabilityBusy || missingLabKey}
          >
            Run Low-Rate Load
          </button>
        </div>
        <div className="status">
          {availabilityStatus ||
            `Ready.${availabilityUpdatedAt ? ` Last update: ${availabilityUpdatedAt}` : ''}`}
        </div>
        <pre className="output">
          {availabilityOutput || 'No load output yet.'}
        </pre>

        <div className="section-title">Monitoring Before Test</div>
        <div className="hint">
          Collect baseline (CPU/RAM/QPS/latency) for 1–2 minutes and capture upstream
          traffic before ramping load. Minimal monitoring: tcpdump + Unbound/BIND logs
          + dnsperf output.
        </div>
        <div className="grid">
          <label>
            Baseline duration (s)
            <input
              type="number"
              min={30}
              max={120}
              value={baselineDuration}
              onChange={(e) => setBaselineDuration(Number(e.target.value))}
              disabled={baselineBusy || warmupBusy}
            />
          </label>
          <label>
            Baseline probe count
            <input
              type="number"
              min={5}
              max={60}
              value={baselineProbeCount}
              onChange={(e) => setBaselineProbeCount(Number(e.target.value))}
              disabled={baselineBusy || warmupBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={restartResolver} disabled={baselineBusy || missingLabKey}>
            Restart Resolver
          </button>
          <button onClick={flushResolver} disabled={baselineBusy || missingLabKey}>
            Flush Cache (example.test)
          </button>
          <button onClick={runWarmup} disabled={warmupBusy || missingLabKey}>
            Warm-up (short)
          </button>
          <button onClick={runBaseline} disabled={baselineBusy || missingLabKey}>
            Run Baseline
          </button>
          <button
            onClick={() => startCooldown(60)}
            disabled={cooldownRemaining > 0}
          >
            Start Cooldown (60s)
          </button>
        </div>
        <div className="status">
          {baselineStatus || 'Ready.'}
          {cooldownRemaining > 0 ? ` Cooldown: ${cooldownRemaining}s` : ''}
        </div>
        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">Baseline QPS</div>
            <div className="metric-value">
              {baselineSummary ? baselineSummary.qps.toFixed(1) : '—'}
            </div>
            <div className="metric-sub">
              Total queries: {baselineSummary ? baselineSummary.total_queries : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Latency p50 / p95</div>
            <div className="metric-value">
              {baselineSummary
                ? `${baselineSummary.p50_ms} / ${baselineSummary.p95_ms} ms`
                : '—'}
            </div>
            <div className="metric-sub">
              Duration: {baselineSummary ? `${baselineSummary.duration_s}s` : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">NXDOMAIN / SERVFAIL</div>
            <div className="metric-value">
              {baselineSummary
                ? `${formatPercent(baselineSummary.nxdomain_ratio)} / ${formatPercent(
                    baselineSummary.servfail_ratio
                  )}`
                : '—'}
            </div>
            <div className="metric-sub">
              Cache hit: {baselineSummary ? formatPercent(baselineSummary.cache_hit_ratio) : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">CPU / RAM</div>
            <div className="metric-value">
              {baselineSummary
                ? `${baselineSummary.cpu_pct?.toFixed(1) ?? '—'}%`
                : '—'}
            </div>
            <div className="metric-sub">
              {baselineSummary && baselineSummary.mem_mb
                ? `${baselineSummary.mem_mb.toFixed(1)} MB${
                    baselineSummary.mem_pct !== undefined
                      ? ` (${baselineSummary.mem_pct.toFixed(1)}%)`
                      : ''
                  }`
                : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Upstream QPS</div>
            <div className="metric-value">
              {baselineSummary && baselineSummary.upstream_qps !== undefined
                ? baselineSummary.upstream_qps.toFixed(2)
                : '—'}
            </div>
            <div className="metric-sub">
              Upstream queries:{' '}
              {baselineSummary && baselineSummary.upstream_queries !== undefined
                ? baselineSummary.upstream_queries
                : '—'}
            </div>
          </div>
        </div>
        {baselineCaptureFile && (
          <div className="actions">
            <button
              onClick={() => downloadCapture(baselineCaptureFile)}
              disabled={missingLabKey || baselineBusy}
            >
              Download Baseline PCAP
            </button>
          </div>
        )}

        <div className="section-title">Test Procedure</div>
        <div className="step-list">
          <div className="step-item">
            1. Reset/flush cache (or restart resolver) for a clean start.
          </div>
          <div className="step-item">2. Warm-up (short test) to stabilize cache.</div>
          <div className="step-item">
            3. Run the main test with ramp-up and QPS limits (see Flooding below).
          </div>
          <div className="step-item">
            4. Record data: baseline + upstream counter (pcap/metrics) + logs.
          </div>
          <div className="step-item">
            5. Cooldown: wait 60–120s between series.
          </div>
        </div>

        <div className="section-title">Flooding (Guardrails)</div>
        <div className="hint">
          Ramp safely inside the lab only. Guardrails stop on loss, latency,
          SERVFAIL, or sustained CPU. Keep QPS low (20–100 demo, up to 200 if stable).
        </div>
        <div className="grid">
          <label>
            QPS start
            <input
              type="number"
              min={1}
              max={200}
              value={floodStartQps}
              onChange={(e) => setFloodStartQps(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            QPS end
            <input
              type="number"
              min={1}
              max={200}
              value={floodEndQps}
              onChange={(e) => setFloodEndQps(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            QPS step
            <input
              type="number"
              min={1}
              max={200}
              value={floodStepQps}
              onChange={(e) => setFloodStepQps(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Step seconds
            <input
              type="number"
              min={5}
              max={120}
              value={floodStepSeconds}
              onChange={(e) => setFloodStepSeconds(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Max outstanding
            <input
              type="number"
              min={1}
              max={500}
              value={floodOutstanding}
              onChange={(e) => setFloodOutstanding(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Timeout (ms)
            <input
              type="number"
              min={200}
              max={5000}
              value={floodTimeoutMs}
              onChange={(e) => setFloodTimeoutMs(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Stop loss %
            <input
              type="number"
              min={0}
              max={50}
              step={0.1}
              value={floodStopLoss}
              onChange={(e) => setFloodStopLoss(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Stop p95 (ms)
            <input
              type="number"
              min={0}
              max={5000}
              value={floodStopP95}
              onChange={(e) => setFloodStopP95(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Stop SERVFAIL %
            <input
              type="number"
              min={0}
              max={50}
              step={0.1}
              value={floodStopServfail}
              onChange={(e) => setFloodStopServfail(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
          <label>
            Stop CPU %
            <input
              type="number"
              min={0}
              max={100}
              step={1}
              value={floodStopCpu}
              onChange={(e) => setFloodStopCpu(Number(e.target.value))}
              disabled={floodBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={runFloodTest} disabled={floodBusy || missingLabKey}>
            Run Flooding Ramp
          </button>
        </div>
        <div className="status">
          {floodStatus || 'Ready.'}
          {floodSummary ? ` ${floodSummary}` : ''}
        </div>
        <div className="result-table">
          <div className="result-row header">
            <div>Step</div>
            <div>QPS</div>
            <div>Sent</div>
            <div>Loss</div>
            <div>P95</div>
            <div>SERVFAIL</div>
            <div>CPU</div>
            <div>RCodes / Stop</div>
          </div>
          {floodResults.length === 0 ? (
            <div className="result-row empty">No flooding results yet.</div>
          ) : (
            floodResults.map((row) => (
              <div key={`${row.step}-${row.qps}`} className="result-row">
                <div>{row.step}</div>
                <div>{row.qps} ({row.actual_qps})</div>
                <div>{row.sent}</div>
                <div>{row.loss_pct.toFixed(2)}%</div>
                <div>{row.p95_ms} ms</div>
                <div>{row.servfail_pct.toFixed(2)}%</div>
                <div>{row.cpu_pct === undefined ? '—' : `${row.cpu_pct.toFixed(1)}%`}</div>
                <div>
                  {formatKeyValues(row.rcode_counts)}
                  {row.stop_reason ? ` • stop: ${row.stop_reason}` : ''}
                </div>
              </div>
            ))
          )}
        </div>
      </section>
      )}

      {isSectionVisible('perf') && (
      <section className="card" id="perf">
        <div className="card-title">dnsperf / resperf</div>
        <div className="hint">
          <div>
            Runs inside the <code>dns_perf_tools</code> container. Keep QPS low and
            local-only. Query list feeds both dnsperf and resperf.
          </div>
          <div>
            Output is the raw tool output plus a small parsed summary (dnsperf).
          </div>
          <div>
            If you see timeouts/loss, lower QPS/clients or temporarily raise
            Unbound <code>ratelimit</code>/<code>ip-ratelimit</code> (Controls section).
          </div>
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="grid">
          <label>
            Target
            <select
              value={perfTarget}
              onChange={(e) => setPerfTarget(e.target.value as PerfTarget)}
              disabled={dnsperfBusy || resperfBusy}
            >
              {perfTargetOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="perf-queries">
          Query list (one per line)
          <textarea
            value={perfQueries}
            onChange={(e) => setPerfQueries(e.target.value)}
            disabled={dnsperfBusy || resperfBusy}
          />
        </label>
        <div className="actions">
          <button
            onClick={() => setPerfQueries(DEFAULT_PERF_QUERIES)}
            disabled={dnsperfBusy || resperfBusy}
          >
            Reset Query List
          </button>
        </div>

        <div className="section-title">dnsperf (throughput + latency)</div>
        <div className="grid">
          <label>
            Duration (s)
            <input
              type="number"
              min={1}
              max={300}
              value={dnsperfDuration}
              onChange={(e) => setDnsperfDuration(Number(e.target.value))}
              disabled={dnsperfBusy}
            />
          </label>
          <label>
            Max QPS
            <input
              type="number"
              min={1}
              max={200}
              value={dnsperfQps}
              onChange={(e) => setDnsperfQps(Number(e.target.value))}
              disabled={dnsperfBusy}
            />
          </label>
          <label>
            Max queries
            <input
              type="number"
              min={1}
              max={5000}
              value={dnsperfMaxQueries}
              onChange={(e) => setDnsperfMaxQueries(Number(e.target.value))}
              disabled={dnsperfBusy}
            />
          </label>
          <label>
            Threads
            <input
              type="number"
              min={1}
              max={8}
              value={dnsperfThreads}
              onChange={(e) => setDnsperfThreads(Number(e.target.value))}
              disabled={dnsperfBusy}
            />
          </label>
          <label>
            Clients
            <input
              type="number"
              min={1}
              max={50}
              value={dnsperfClients}
              onChange={(e) => setDnsperfClients(Number(e.target.value))}
              disabled={dnsperfBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={runDnsperf} disabled={dnsperfBusy || missingLabKey}>
            Run dnsperf
          </button>
        </div>
        <div className="status">{dnsperfStatus || 'Ready.'}</div>
        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">Queries sent</div>
            <div className="metric-value">
              {dnsperfSummary?.queries_sent ?? '—'}
            </div>
            <div className="metric-sub">
              Completed: {dnsperfSummary?.queries_completed ?? '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Lost</div>
            <div className="metric-value">
              {dnsperfSummary?.queries_lost ?? '—'}
            </div>
            <div className="metric-sub">
              QPS: {dnsperfSummary?.qps?.toFixed(2) ?? '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Latency avg</div>
            <div className="metric-value">
              {typeof dnsperfSummary?.avg_latency_ms === 'number'
                ? `${dnsperfSummary.avg_latency_ms.toFixed(2)} ms`
                : '—'}
            </div>
            <div className="metric-sub">
              Min/Max:{' '}
              {typeof dnsperfSummary?.min_latency_ms === 'number' &&
              typeof dnsperfSummary?.max_latency_ms === 'number'
                ? `${dnsperfSummary.min_latency_ms.toFixed(2)} / ${dnsperfSummary.max_latency_ms.toFixed(2)} ms`
                : '—'}
            </div>
          </div>
        </div>
        <pre className="output">
          {dnsperfOutput || 'No dnsperf output yet.'}
        </pre>

        <div className="section-title">resperf (ramp + capacity curve)</div>
        <div className="grid">
          <label>
            Max QPS
            <input
              type="number"
              min={1}
              max={300}
              value={resperfMaxQps}
              onChange={(e) => setResperfMaxQps(Number(e.target.value))}
              disabled={resperfBusy}
            />
          </label>
          <label>
            Ramp QPS
            <input
              type="number"
              min={1}
              max={50}
              value={resperfRampQps}
              onChange={(e) => setResperfRampQps(Number(e.target.value))}
              disabled={resperfBusy}
            />
          </label>
          <label>
            Clients
            <input
              type="number"
              min={1}
              max={50}
              value={resperfClients}
              onChange={(e) => setResperfClients(Number(e.target.value))}
              disabled={resperfBusy}
            />
          </label>
          <label>
            Queries/step
            <input
              type="number"
              min={1}
              max={2000}
              value={resperfQueriesPerStep}
              onChange={(e) => setResperfQueriesPerStep(Number(e.target.value))}
              disabled={resperfBusy}
            />
          </label>
          <label>
            Plot file name
            <input
              value={resperfPlotName}
              onChange={(e) => setResperfPlotName(e.target.value)}
              disabled={resperfBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={runResperf} disabled={resperfBusy || missingLabKey}>
            Run resperf
          </button>
        </div>
        <div className="status">{resperfStatus || 'Ready.'}</div>
        <div className="hint">
          <div>
            Plot file: <code>{resperfPlotFile || 'not generated yet'}</code>
          </div>
          <div>
            Files are saved under <code>captures/</code> on the host.
          </div>
        </div>
        <pre className="output">
          {resperfOutput || 'No resperf output yet.'}
        </pre>
      </section>
      )}

      {isSectionVisible('limits') && (
      <section className="card" id="limits">
        <div className="card-title">Service Limits (Rate Limiting)</div>
        <div className="hint">
          Evidence for availability protection: config excerpts + rate-limited metrics
          + BIND RRL log hits. Use in-lab only.
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="grid">
          <label>
            RRL test count
            <input
              type="number"
              min={1}
              max={800}
              value={rrlCount}
              onChange={(e) => setRrlCount(Number(e.target.value))}
              disabled={limitsBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={loadServiceLimits} disabled={limitsBusy || missingLabKey}>
            Load Service Limits
          </button>
          <button onClick={runRateLimitProof} disabled={limitsBusy || missingLabKey}>
            Run Rate-Limit Proof
          </button>
          <button onClick={runRrlTest} disabled={limitsBusy || missingLabKey}>
            Run BIND RRL Test
          </button>
        </div>
        <div className="status">{limitsStatus || 'Ready.'}</div>

        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">Requests limited (delta)</div>
            <div className="metric-value">
              {rateLimitDelta ? rateLimitDelta.ratelimited : '—'}
            </div>
            <div className="metric-sub">
              IP-limited delta:{' '}
              {rateLimitDelta ? rateLimitDelta.ip_ratelimited : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Queries during proof</div>
            <div className="metric-value">
              {rateLimitDelta ? rateLimitDelta.total : '—'}
            </div>
            <div className="metric-sub">
              After total:{' '}
              {rateLimitAfter ? rateLimitAfter.totals.queries : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">BIND RRL</div>
            <div className="metric-value">
              {bindRrlEnabled === null ? '—' : bindRrlEnabled ? 'enabled' : 'disabled'}
            </div>
            <div className="metric-sub">{rrlStatus || 'No test yet.'}</div>
          </div>
        </div>

        <div className="section-title">Unbound limits (config excerpt)</div>
        <pre className="output compact">
          {unboundLimitLines.length > 0
            ? unboundLimitLines.join('\n')
            : 'Load service limits to view Unbound settings.'}
        </pre>

        <div className="section-title">BIND RRL (config excerpt)</div>
        <pre className="output compact">
          {bindRrlBlock || 'Load service limits to view BIND rate-limit block.'}
        </pre>

        <div className="section-title">BIND RRL log excerpt</div>
        <pre className="output compact">
          {rrlResult?.log_excerpt || 'Run BIND RRL test to collect log hits.'}
        </pre>
      </section>
      )}

      {isSectionVisible('controls') && (
      <section className="card" id="controls">
        <div className="card-title">Controls</div>
        <div className="hint">
          Toggle safety knobs and apply immediately. Changes restart the affected
          services.
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="section-title">Unbound (resolver)</div>
        <div className="control-note">
          Dropped (ratelimited):{' '}
          {availabilityMetrics ? availabilityMetrics.totals.ratelimited : '—'} • IP
          ratelimited:{' '}
          {availabilityMetrics ? availabilityMetrics.totals.ip_ratelimited : '—'}
        </div>
        <div className="grid">
          <label>
            ratelimit
            <input
              type="number"
              min={0}
              max={10000}
              value={unboundCtl.ratelimit}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, ratelimit: Number(e.target.value) })
              }
              disabled={controlsBusy}
            />
          </label>
          <label>
            ip-ratelimit
            <input
              type="number"
              min={0}
              max={10000}
              value={unboundCtl.ip_ratelimit}
              onChange={(e) =>
                setUnboundCtl({
                  ...unboundCtl,
                  ip_ratelimit: Number(e.target.value),
                })
              }
              disabled={controlsBusy}
            />
          </label>
          <label>
            unwanted-reply-threshold
            <input
              type="number"
              min={0}
              max={100000}
              value={unboundCtl.unwanted_reply_threshold}
              onChange={(e) =>
                setUnboundCtl({
                  ...unboundCtl,
                  unwanted_reply_threshold: Number(e.target.value),
                })
              }
              disabled={controlsBusy}
            />
          </label>
          <label>
            serve-expired-ttl
            <input
              type="number"
              min={0}
              max={86400}
              value={unboundCtl.serve_expired_ttl}
              onChange={(e) =>
                setUnboundCtl({
                  ...unboundCtl,
                  serve_expired_ttl: Number(e.target.value),
                })
              }
              disabled={controlsBusy || !unboundCtl.serve_expired}
            />
          </label>
          <label>
            msg-cache-size
            <input
              value={unboundCtl.msg_cache_size}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, msg_cache_size: e.target.value })
              }
              placeholder="e.g. 50m"
              disabled={controlsBusy}
            />
          </label>
          <label>
            rrset-cache-size
            <input
              value={unboundCtl.rrset_cache_size}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, rrset_cache_size: e.target.value })
              }
              placeholder="e.g. 100m"
              disabled={controlsBusy}
            />
          </label>
        </div>
        <div className="toggle-row">
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={unboundCtl.serve_expired}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, serve_expired: e.target.checked })
              }
              disabled={controlsBusy}
            />
            serve-expired
          </label>
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={unboundCtl.prefetch}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, prefetch: e.target.checked })
              }
              disabled={controlsBusy}
            />
            prefetch
          </label>
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={unboundCtl.aggressive_nsec}
              onChange={(e) =>
                setUnboundCtl({ ...unboundCtl, aggressive_nsec: e.target.checked })
              }
              disabled={controlsBusy}
            />
            aggressive-nsec
          </label>
        </div>

        <div className="section-title">BIND (authoritative)</div>
        <div className="grid">
          <label>
            RRL responses/sec
            <input
              type="number"
              min={1}
              max={1000}
              value={bindCtl.rrl_responses_per_second}
              onChange={(e) =>
                setBindCtl({
                  ...bindCtl,
                  rrl_responses_per_second: Number(e.target.value),
                })
              }
              disabled={controlsBusy || !bindCtl.rrl_enabled}
            />
          </label>
          <label>
            RRL window
            <input
              type="number"
              min={1}
              max={60}
              value={bindCtl.rrl_window}
              onChange={(e) =>
                setBindCtl({ ...bindCtl, rrl_window: Number(e.target.value) })
              }
              disabled={controlsBusy || !bindCtl.rrl_enabled}
            />
          </label>
          <label>
            RRL slip
            <input
              type="number"
              min={0}
              max={10}
              value={bindCtl.rrl_slip}
              onChange={(e) =>
                setBindCtl({ ...bindCtl, rrl_slip: Number(e.target.value) })
              }
              disabled={controlsBusy || !bindCtl.rrl_enabled}
            />
          </label>
        </div>
        <div className="toggle-row">
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={bindCtl.rrl_enabled}
              onChange={(e) =>
                setBindCtl({ ...bindCtl, rrl_enabled: e.target.checked })
              }
              disabled={controlsBusy}
            />
            RRL enabled
          </label>
          <label className="pill-toggle warning">
            <input
              type="checkbox"
              checked={bindCtl.recursion}
              onChange={(e) =>
                setBindCtl({ ...bindCtl, recursion: e.target.checked })
              }
              disabled={controlsBusy}
            />
            recursion (avoid open resolver)
          </label>
        </div>
        <div className="actions">
          <button onClick={loadControls} disabled={controlsBusy || missingLabKey}>
            Load Controls
          </button>
          <button onClick={applyControls} disabled={controlsBusy || missingLabKey}>
            Apply Controls
          </button>
        </div>
        <div className="status">{controlsStatus || 'Ready.'}</div>
      </section>
      )}

      {isSectionVisible('amplification') && (
      <section className="card" id="amplification">
        <div className="card-title">DNSSEC Amplification / EDNS</div>
        <div className="hint">
          <div>
            Compare response sizes, TC bit, TCP fallback, and latency for large
            DNSSEC responses. Use a zone apex for DNSKEY/RRSIG tests.
          </div>
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="grid">
          <label>
            Name (zone apex)
            <input
              value={ampName}
              onChange={(e) => setAmpName(e.target.value)}
              disabled={ampBusy}
            />
          </label>
          <label>
            Samples per qtype
            <input
              type="number"
              min={1}
              max={40}
              value={ampCount}
              onChange={(e) => setAmpCount(Number(e.target.value))}
              disabled={ampBusy}
            />
          </label>
        </div>
        <div className="toggle-row">
          <div className="toggle-group">
            <div className="toggle-label">QTYPE</div>
            {['DNSKEY', 'ANY', 'TXT', 'RRSIG', 'A', 'AAAA', 'SOA'].map((q) => (
              <label key={q} className="pill-toggle">
                <input
                  type="checkbox"
                  checked={ampQtypes.includes(q)}
                  onChange={() => toggleAmpQtype(q)}
                  disabled={ampBusy}
                />
                {q}
              </label>
            ))}
          </div>
          <div className="toggle-group">
            <div className="toggle-label">EDNS UDP</div>
            {[1232, 4096].map((size) => (
              <label key={size} className="pill-toggle">
                <input
                  type="checkbox"
                  checked={ampEdnsSizes.includes(size)}
                  onChange={() => toggleAmpEdns(size)}
                  disabled={ampBusy}
                />
                {size}
              </label>
            ))}
          </div>
          <div className="toggle-group">
            <div className="toggle-label">Options</div>
            <label className="pill-toggle">
              <input
                type="checkbox"
                checked={ampDnssec}
                onChange={(e) => setAmpDnssec(e.target.checked)}
                disabled={ampBusy}
              />
              DNSSEC DO
            </label>
            <label className="pill-toggle">
              <input
                type="checkbox"
                checked={ampTcpFallback}
                onChange={(e) => setAmpTcpFallback(e.target.checked)}
                disabled={ampBusy}
              />
              TCP fallback
            </label>
          </div>
        </div>
        <div className="actions">
          <button onClick={runAmplificationTest} disabled={ampBusy || missingLabKey}>
            Run Amplification Test
          </button>
        </div>
        <div className="status">{ampStatus || 'Ready.'}</div>
        <div className="result-table">
          <div className="result-row header">
            <div>EDNS</div>
            <div>QTYPE</div>
            <div>TC%</div>
            <div>TCP%</div>
            <div>P95 ms</div>
            <div>UDP avg/max</div>
            <div>TCP avg/max</div>
            <div>RCODES</div>
          </div>
          {ampResults.length === 0 && (
            <div className="result-row empty">
              <div>No results yet.</div>
            </div>
          )}
          {sortedAmpResults.map((row) => (
            <div key={`${row.edns_size}-${row.qtype}`} className="result-row">
              <div>{row.edns_size}</div>
              <div>{row.qtype}</div>
              <div>{formatPercent(row.tc_rate)}</div>
              <div>{formatPercent(row.tcp_rate)}</div>
              <div>{row.p95_latency_ms}</div>
              <div>
                {row.avg_udp_size.toFixed(0)} / {row.max_udp_size}
              </div>
              <div>
                {row.avg_tcp_size.toFixed(0)} / {row.max_tcp_size}
              </div>
              <div>{formatKeyValues(row.rcode_counts)}</div>
            </div>
          ))}
        </div>

        <div className="section-title">Mix Load (80% A/AAAA, 10% NXDOMAIN, 10% DNSKEY)</div>
        <div className="grid">
          <label>
            Zone
            <input
              value={mixZone}
              onChange={(e) => setMixZone(e.target.value)}
              disabled={mixBusy}
            />
          </label>
          <label>
            Count
            <input
              type="number"
              min={1}
              max={500}
              value={mixCount}
              onChange={(e) => setMixCount(Number(e.target.value))}
              disabled={mixBusy}
            />
          </label>
          <label>
            EDNS size
            <select
              value={mixEdns}
              onChange={(e) => setMixEdns(Number(e.target.value))}
              disabled={mixBusy}
            >
              <option value={1232}>1232</option>
              <option value={4096}>4096</option>
            </select>
          </label>
        </div>
        <div className="toggle-row">
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={mixDnssec}
              onChange={(e) => setMixDnssec(e.target.checked)}
              disabled={mixBusy}
            />
            DNSSEC DO
          </label>
          <label className="pill-toggle">
            <input
              type="checkbox"
              checked={mixTcpFallback}
              onChange={(e) => setMixTcpFallback(e.target.checked)}
              disabled={mixBusy}
            />
            TCP fallback
          </label>
        </div>
        <div className="actions">
          <button onClick={runMixLoad} disabled={mixBusy || missingLabKey}>
            Run Mix Load
          </button>
        </div>
        <div className="status">{mixStatus || 'Ready.'}</div>
        <div className="metrics-grid">
          <div className="metric">
            <div className="metric-label">P95 latency</div>
            <div className="metric-value">
              {mixResult ? `${mixResult.p95_latency_ms} ms` : '—'}
            </div>
            <div className="metric-sub">
              Avg latency: {mixResult ? `${mixResult.avg_latency_ms} ms` : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">TC / TCP</div>
            <div className="metric-value">
              {mixResult ? formatPercent(mixResult.tc_rate) : '—'}
            </div>
            <div className="metric-sub">
              TCP: {mixResult ? formatPercent(mixResult.tcp_rate) : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">UDP size</div>
            <div className="metric-value">
              {mixResult ? `${mixResult.avg_udp_size.toFixed(0)} B` : '—'}
            </div>
            <div className="metric-sub">
              Max: {mixResult ? `${mixResult.max_udp_size} B` : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">TCP size</div>
            <div className="metric-value">
              {mixResult ? `${mixResult.avg_tcp_size.toFixed(0)} B` : '—'}
            </div>
            <div className="metric-sub">
              Max: {mixResult ? `${mixResult.max_tcp_size} B` : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">RCODES</div>
            <div className="metric-value">{mixResult ? 'mix' : '—'}</div>
            <div className="metric-sub">
              {mixResult ? formatKeyValues(mixResult.rcode_counts) : '—'}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">Query mix</div>
            <div className="metric-value">{mixResult ? '80/10/10' : '—'}</div>
            <div className="metric-sub">
              {mixResult ? formatKeyValues(mixResult.query_mix) : '—'}
            </div>
          </div>
        </div>
      </section>
      )}

      {isSectionVisible('configs') && (
      <section className="card" id="configs">
        <div className="card-title">Config Files (Lab API)</div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="config-tabs">
          <button
            className={configGroup === 'authoritative' ? 'active' : ''}
            onClick={() => setConfigGroup('authoritative')}
            disabled={isBusy}
          >
            Authoritative
          </button>
          <button
            className={configGroup === 'resolver' ? 'active' : ''}
            onClick={() => setConfigGroup('resolver')}
            disabled={isBusy}
          >
            Resolver
          </button>
        </div>
        <div className="config-server-tabs">
          {configGroup === 'authoritative' ? (
            <>
              <button
                className={configServer === 'child' ? 'active' : ''}
                onClick={() => setConfigServer('child')}
                disabled={isBusy}
              >
                Child (bind)
              </button>
              <button
                className={configServer === 'parent' ? 'active' : ''}
                onClick={() => setConfigServer('parent')}
                disabled={isBusy}
              >
                Parent (bind_parent)
              </button>
            </>
          ) : (
            <>
              <button
                className={configServer === 'resolver' ? 'active' : ''}
                onClick={() => setConfigServer('resolver')}
                disabled={isBusy}
              >
                Resolver
              </button>
              <button
                className={configServer === 'plain' ? 'active' : ''}
                onClick={() => setConfigServer('plain')}
                disabled={isBusy}
              >
                Resolver Plain
              </button>
            </>
          )}
        </div>

        <div className="config-layout">
          <div className="config-pane config-pane-list">
            <div className="config-toolbar">
              <input
                className="config-search"
                placeholder="Filter files (e.g., named.conf, zones, unbound)"
                value={configSearch}
                onChange={(e) => setConfigSearch(e.target.value)}
                disabled={isBusy}
              />
              <div className="config-count">
                {visibleConfigFiles.length} files
              </div>
            </div>
            <div className="config-list config-scroll">
              {visibleConfigFiles.length === 0 && (
                <div className="config-empty">No files loaded yet.</div>
              )}
              {visibleConfigFiles.map((f) => (
                <button
                  key={f.path}
                  className={`config-item ${
                    configPath === f.path ? 'active' : ''
                  }`}
                  onClick={() => setConfigPath(f.path)}
                  disabled={isBusy}
                >
                  <span>{f.path}</span>
                  <span className="config-size">{f.size} B</span>
                </button>
              ))}
            </div>
          </div>

          <div className="config-pane config-pane-viewer">
            <div className="config-viewer-header">
              <div>
                <div className="config-viewer-title">
                  {configPath || 'Select a config file'}
                </div>
                <div className="config-viewer-meta">
                  {selectedConfig
                    ? `${selectedConfig.size} bytes`
                    : 'No file selected'}
                </div>
              </div>
              <div className="config-viewer-actions">
                <button onClick={viewConfigFile} disabled={isBusy || !configPath}>
                  View File
                </button>
                <button onClick={exportConfigBundle} disabled={isBusy || !configContent}>
                  Export Bundle
                </button>
              </div>
            </div>
            <pre className="output config-output config-viewer">
              {configContent ? (
                <code>
                  {configContent.split('\n').map((line, index) => (
                    <span key={`${index}-${line}`} className={configLineClass(line)}>
                      {line}
                      {'\n'}
                    </span>
                  ))}
                </code>
              ) : (
                'No config loaded.'
              )}
            </pre>
            <div className="status">{configStatus || 'Ready.'}</div>
          </div>
        </div>

        <div className="actions">
          <button onClick={loadConfigList} disabled={isBusy}>
            Load Files
          </button>
          <button onClick={viewConfigFile} disabled={isBusy || !configPath}>
            Reload File
          </button>
        </div>
      </section>
      )}

      {isSectionVisible('capture') && (
      <section className="card" id="capture">
        <div className="card-title">Packet Capture (Lab API)</div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="grid">
          <label>
            Target
            <select
              value={captureTarget}
              onChange={(e) =>
                setCaptureTarget(e.target.value as CaptureTarget)
              }
              disabled={isBusy}
            >
              <option value="resolver">resolver</option>
              <option value="authoritative">authoritative</option>
            </select>
          </label>
          <label>
            Filter
            <select
              value={captureFilter}
              onChange={(e) =>
                setCaptureFilter(e.target.value as CaptureFilter)
              }
              disabled={isBusy}
            >
              <option value="dns">DNS (port 53)</option>
              <option value="dns+dot">DNS + DoT (53, 853)</option>
              <option value="all">All traffic</option>
            </select>
          </label>
        </div>

        <div className="actions">
          <button onClick={startCapture} disabled={isBusy || missingLabKey}>
            Start Capture
          </button>
          <button onClick={stopCapture} disabled={isBusy || missingLabKey}>
            Stop Capture
          </button>
          <button onClick={loadCaptures} disabled={isBusy || missingLabKey}>
            Refresh List
          </button>
        </div>

        <div className="status">
          {captureStatus ||
            `Resolver: ${
              captureRunning.resolver ? 'running' : 'idle'
            }, Authoritative: ${
              captureRunning.authoritative ? 'running' : 'idle'
            }.`}
        </div>

        <div className="capture-list">
          {captureFiles.length === 0 && (
            <div className="config-empty">No captures yet.</div>
          )}
          {captureFiles.map((f) => (
            <div key={f.file} className="capture-item">
              <div>
                <div className="capture-name">{f.file}</div>
                <div className="capture-meta">
                  {f.target} • {formatBytes(f.size)} •{' '}
                  {new Date(f.mtime).toLocaleString()}
                </div>
              </div>
              <button
                onClick={() => downloadCapture(f.file)}
                disabled={isBusy || missingLabKey}
              >
                Download
              </button>
            </div>
          ))}
        </div>
      </section>
      )}
    </div>
  );
}
