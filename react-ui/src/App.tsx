import { useEffect, useMemo, useRef, useState } from 'react';
import './index.css';

type Client = 'trusted' | 'untrusted' | 'mgmt';
type Backend = 'client' | 'lab_api';

type ResolverKind = 'valid' | 'plain';
type SectionId =
  | 'all'
  | 'overview'
  | 'topology'
  | 'runbook'
  | 'dig'
  | 'output'
  | 'dnssec'
  | 'privacy'
  | 'email'
  | 'availability'
  | 'scenarios'
  | 'perf'
  | 'limits'
  | 'amplification'
  | 'controls'
  | 'configs'
  | 'capture';

type RunbookId = 'topology' | 'smoke' | 'capture' | 'verify' | 'mail' | 'dnssec';

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

type CmdResponse = {
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

type RunbookStep = {
  step: string;
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type RunbookResponse = {
  ok: boolean;
  runbook: RunbookId;
  steps: RunbookStep[];
};

type HealthResponse = {
  ok: boolean;
  profile?: string;
  default_dns_server?: string;
};

type RegistryNode = {
  name: string;
  role: string;
  ip: string;
  port: number;
  ok: boolean;
  latency_ms?: number;
  agent_role: string;
  agent_version?: string;
  agent_hostname?: string;
};

type NodesResponse = {
  ok: boolean;
  nodes: RegistryNode[];
  errors?: Record<string, string>;
};

type TopologyHealth = {
  health: NodeHealth;
  detail?: string;
};

type ScenarioId = 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'S6';

type ScenarioPerfRow = {
  availabilityPct: string;
  avgLatency: string;
  p50: string;
  p95: string;
  p99: string;
  qpsMax: string;
  baselineQps: string;
  errorRate: string;
  cacheHit: string;
  nxdomain: string;
  servfail: string;
  upstreamQps: string;
  notes: string;
};

type ScenarioResourceRow = {
  cpu: string;
  ram: string;
  memPct: string;
  ratelimitedPct: string;
  upstreamQps: string;
  amplificationUdp: string;
  amplificationTcp: string;
  avgUdpSize: string;
  avgTcpSize: string;
  tcRate: string;
  tcpRate: string;
  notes: string;
};

type ScenarioSecurityRow = {
  dnssecOkPct: string;
  bogusPct: string;
  dotSuccessPct: string;
  dohSuccessPct: string;
  certErrorsPct: string;
  qnameMin: string;
  ecsLeakage: string;
  notes: string;
};

type ConfigGroup = 'authoritative' | 'resolver';
type ConfigServer = 'child' | 'parent' | 'resolver' | 'plain';
type PrivacyTab = 'overview' | 'dot' | 'doh' | 'logs';
type EmailTlsMode = 'none' | 'starttls' | 'tls';
type EmailAuthType = 'AUTO' | 'LOGIN' | 'PLAIN' | 'CRAM-MD5';

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

type DemoAggressiveNsecPhase = {
  aggressive_nsec: boolean;
  dig_first: CmdResponse;
  dig_last: CmdResponse;
  loop: CmdResponse;
  stats_before: Record<string, number>;
  stats_after: Record<string, number>;
  delta: Record<string, number>;
  capture_file?: string | null;
};

type DemoAggressiveNsecResponse = {
  ok: boolean;
  zone: string;
  count: number;
  qps: number;
  profile: string;
  resolver: string;
  phases: DemoAggressiveNsecPhase[];
  artifact_json?: string;
  artifact_zip?: string;
  notes?: string[];
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

type EmailSendResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type EmailUserResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type EmailLogResponse = {
  ok: boolean;
  file: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type EmailMessageSummary = {
  id: string;
  source: 'uid' | 'file';
  mailbox: string;
  subject: string;
  from_addr: string;
  to_addr: string;
  date: string;
};

type EmailMessageListResponse = {
  ok: boolean;
  mailbox: string;
  messages: EmailMessageSummary[];
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

type EmailMessageViewResponse = {
  ok: boolean;
  mailbox: string;
  message_id: string;
  source: 'uid' | 'file';
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  content: string;
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
  p99_ms?: number;
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
  availability_ratio?: number;
  avg_ms?: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms?: number;
  cpu_pct?: number;
  mem_mb?: number;
  mem_pct?: number;
  ratelimited_ratio?: number;
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

type TrafficMode = 'valid' | 'nxdomain' | 'mix';

type TrafficGenRequest = {
  profile: Client;
  resolver: ResolverKind;
  zone: string;
  qtype: string;
  duration_s: number;
  qps: number;
  mode: TrafficMode;
  nxdomain_ratio: number;
  timeout_s: number;
  max_inflight: number;
  seed?: number;
};

type TrafficGenResponse = {
  ok: boolean;
  target_ip: string;
  network: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
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

const TOPOLOGY_NODE_MAP = new Map(
  TOPOLOGY_NODES.map((node) => [node.name, node])
);

const SCENARIOS: { id: ScenarioId; label: string; note: string; detail: string }[] = [
  {
    id: 'S1',
    label: 'S1 Baseline (no DNSSEC)',
    note: 'punkt odniesienia',
    detail: 'Plain resolver, DNSSEC off in queries.',
  },
  {
    id: 'S2',
    label: 'S2 DNSSEC validating',
    note: 'integralność odpowiedzi',
    detail: 'Validating resolver with DNSSEC enabled.',
  },
  {
    id: 'S3',
    label: 'S3 Aggressive NSEC',
    note: 'mniej zapytań do auth przy NXDOMAIN',
    detail: 'Aggressive NSEC enabled; run NXDOMAIN proof.',
  },
  {
    id: 'S4',
    label: 'S4 NSEC3',
    note: 'ochrona przed enumeracją',
    detail: 'Switch signing to NSEC3 (offline).',
  },
  {
    id: 'S5',
    label: 'S5 DoT/DoH',
    note: 'prywatność kosztem narzutu',
    detail: 'Measure DoT/DoH overhead using privacy checks.',
  },
  {
    id: 'S6',
    label: 'S6 Limits + anti-amplification',
    note: 'stabilność w warunkach ataku',
    detail: 'Enable RRL and rate limits before load/amp tests.',
  },
];

const DEFAULT_PERF_TABLE: Record<ScenarioId, ScenarioPerfRow> = SCENARIOS.reduce(
  (acc, scenario) => {
    acc[scenario.id] = {
      availabilityPct: '',
      avgLatency: '',
      p50: '',
      p95: '',
      p99: '',
      qpsMax: '',
      baselineQps: '',
      errorRate: '',
      cacheHit: '',
      nxdomain: '',
      servfail: '',
      upstreamQps: '',
      notes: scenario.note,
    };
    return acc;
  },
  {} as Record<ScenarioId, ScenarioPerfRow>
);

const DEFAULT_RESOURCE_TABLE: Record<ScenarioId, ScenarioResourceRow> =
  SCENARIOS.reduce(
    (acc, scenario) => {
      acc[scenario.id] = {
        cpu: '',
        ram: '',
        memPct: '',
        ratelimitedPct: '',
        upstreamQps: '',
        amplificationUdp: '',
        amplificationTcp: '',
        avgUdpSize: '',
        avgTcpSize: '',
        tcRate: '',
        tcpRate: '',
        notes: scenario.note,
      };
      return acc;
    },
    {} as Record<ScenarioId, ScenarioResourceRow>
  );

const DEFAULT_SECURITY_TABLE: Record<ScenarioId, ScenarioSecurityRow> =
  SCENARIOS.reduce(
    (acc, scenario) => {
      acc[scenario.id] = {
        dnssecOkPct: '',
        bogusPct: '',
        dotSuccessPct: '',
        dohSuccessPct: '',
        certErrorsPct: '',
        qnameMin: '',
        ecsLeakage: '',
        notes: scenario.note,
      };
      return acc;
    },
    {} as Record<ScenarioId, ScenarioSecurityRow>
  );

const MVP_UI_NOTES = [
  {
    title: 'Nodes',
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

const QUICK_LINKS = [
  {
    title: 'Grafana',
    url: 'http://127.0.0.1:3000',
    desc: 'Dashboards + metrics',
  },
  {
    title: 'Kibana',
    url: 'http://127.0.0.1:5601',
    desc: 'Logs + saved searches',
  },
  {
    title: 'Prometheus',
    url: 'http://127.0.0.1:9090',
    desc: 'Scrape targets',
  },
  {
    title: 'Lab API',
    url: 'http://127.0.0.1:8000/docs',
    desc: 'Control-plane endpoints',
  },
];

const SECTION_TABS: { id: SectionId; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'overview', label: 'Overview' },
  { id: 'topology', label: 'Nodes' },
  { id: 'runbook', label: 'Runbook' },
  { id: 'dig', label: 'Dig' },
  { id: 'output', label: 'Output' },
  { id: 'dnssec', label: 'DNSSEC' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'email', label: 'Email' },
  { id: 'availability', label: 'Availability' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'perf', label: 'Perf' },
  { id: 'limits', label: 'Service Limits' },
  { id: 'amplification', label: 'Amplification' },
  { id: 'controls', label: 'Controls' },
  { id: 'configs', label: 'Configs' },
  { id: 'capture', label: 'Capture' },
];

const RUNBOOKS: { id: RunbookId; title: string; desc: string; note?: string }[] = [
  {
    id: 'topology',
    title: 'Topology snapshot',
    desc: 'Runs docker network listing, network inspect, and container IP mapping.',
  },
  {
    id: 'smoke',
    title: 'DNS behavior smoke tests',
    desc: 'Runs the manual.md recursion, segmentation, and DNSSEC checks.',
    note: 'Uses the trusted/untrusted client containers and the toolbox.',
  },
  {
    id: 'capture',
    title: 'Traffic capture snapshot',
    desc: 'Starts resolver + authoritative capture, runs a query, then previews the PCAPs.',
    note: 'From manual.md section 2 (live traffic capture).',
  },
  {
    id: 'verify',
    title: 'DNSSEC verification checks',
    desc: 'Checks DS in the parent and validates answers via the resolver.',
    note: 'From dns.md verification checks.',
  },
  {
    id: 'mail',
    title: 'Mail DNS records',
    desc: 'Queries MX/SPF/DKIM records for example.test via the resolver.',
    note: 'From dns.md mail DNS records section.',
  },
  {
    id: 'dnssec',
    title: 'DNSSEC maintenance',
    desc: 'Runs DS recompute, trust-anchor export, and restarts the resolver.',
    note: 'Matches dns.md manual maintenance steps.',
  },
];

const DEFAULT_RUNBOOK_QUEUE: RunbookId[] = ['capture', 'verify', 'mail'];
const RUNBOOK_VISIBILITY_KEY = 'runbookVisibility';
const SHOW_RUNBOOK_QUEUE = false;

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

function formatPercentValue(value?: number): string {
  if (value === undefined || Number.isNaN(value)) {
    return '';
  }
  const abs = Math.abs(value);
  if (abs >= 10) {
    return value.toFixed(1);
  }
  if (abs >= 1) {
    return value.toFixed(2);
  }
  if (abs >= 0.1) {
    return value.toFixed(3);
  }
  return value.toFixed(4);
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
  return 'Not checked';
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
  const [runbookBusy, setRunbookBusy] = useState(false);
  const [runbookStatus, setRunbookStatus] = useState('');
  const [runbookResults, setRunbookResults] = useState<
    Record<RunbookId, RunbookResponse | null>
  >({
    topology: null,
    smoke: null,
    capture: null,
    verify: null,
    mail: null,
    dnssec: null,
  });
  const [runbookHidden, setRunbookHidden] = useState<
    Record<RunbookId, boolean>
  >(() => {
    if (typeof window === 'undefined') {
      return {
        topology: false,
        smoke: false,
        capture: false,
        verify: false,
        mail: false,
        dnssec: false,
      };
    }
    try {
      const stored = window.localStorage.getItem(RUNBOOK_VISIBILITY_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as Partial<Record<RunbookId, boolean>>;
        return {
          topology: Boolean(parsed.topology),
          smoke: Boolean(parsed.smoke),
          capture: Boolean(parsed.capture),
          verify: Boolean(parsed.verify),
          mail: Boolean(parsed.mail),
          dnssec: Boolean(parsed.dnssec),
        };
      }
    } catch {
      // Ignore local storage errors.
    }
    return {
      topology: false,
      smoke: false,
      capture: false,
      verify: false,
      mail: false,
      dnssec: false,
    };
  });
  const [runbookQueue, setRunbookQueue] =
    useState<RunbookId[]>(DEFAULT_RUNBOOK_QUEUE);
  const [proofBusy, setProofBusy] = useState(false);
  const [proofStatus, setProofStatus] = useState('');
  const [proofOutput, setProofOutput] = useState('');
  const [proofCaptureFile, setProofCaptureFile] = useState('');
  const [proofArtifactFile, setProofArtifactFile] = useState('');
  const [proofCount, setProofCount] = useState(100);
  const [proofQps, setProofQps] = useState(50);
  const [proofCaptureTarget, setProofCaptureTarget] =
    useState<CaptureTarget>('resolver');
  const [privacyBusy, setPrivacyBusy] = useState(false);
  const [privacyStatus, setPrivacyStatus] = useState('');
  const [privacyOutput, setPrivacyOutput] = useState('');
  const [emailBusy, setEmailBusy] = useState(false);
  const [emailStatus, setEmailStatus] = useState('');
  const [emailUserAddress, setEmailUserAddress] = useState('user@example.test');
  const [emailUserPassword, setEmailUserPassword] = useState('');
  const [emailUserOutput, setEmailUserOutput] = useState('');
  const [emailOutput, setEmailOutput] = useState('');
  const [emailLog, setEmailLog] = useState('');
  const [emailLogFile, setEmailLogFile] = useState('');
  const [emailLogTail, setEmailLogTail] = useState(200);
  const [emailLogFilter, setEmailLogFilter] = useState('dkim');
  const [emailImapUser, setEmailImapUser] = useState('user@example.test');
  const [emailImapMailbox, setEmailImapMailbox] = useState('INBOX');
  const [emailImapLimit, setEmailImapLimit] = useState(40);
  const [emailInboxMessages, setEmailInboxMessages] = useState<EmailMessageSummary[]>([]);
  const [emailInboxSelected, setEmailInboxSelected] =
    useState<EmailMessageSummary | null>(null);
  const [emailInboxContent, setEmailInboxContent] = useState('');
  const [emailInboxRaw, setEmailInboxRaw] = useState('');
  const [emailFrom, setEmailFrom] = useState('user@example.test');
  const [emailTo, setEmailTo] = useState('user@example.test');
  const [emailSubject, setEmailSubject] = useState('DNS lab test');
  const [emailBody, setEmailBody] = useState('Hello from the DNS lab.');
  const [emailServer, setEmailServer] = useState('mail.example.test');
  const [emailPort, setEmailPort] = useState(25);
  const [emailTlsMode, setEmailTlsMode] = useState<EmailTlsMode>('none');
  const [emailUseAuth, setEmailUseAuth] = useState(false);
  const [emailAuthUser, setEmailAuthUser] = useState('user@example.test');
  const [emailAuthPass, setEmailAuthPass] = useState('');
  const [emailAuthType, setEmailAuthType] = useState<EmailAuthType>('AUTO');
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
  const [trafficProfile, setTrafficProfile] = useState<Client>('trusted');
  const [trafficResolver, setTrafficResolver] = useState<ResolverKind>('valid');
  const [trafficZone, setTrafficZone] = useState('example.test');
  const [trafficQtype, setTrafficQtype] = useState('A');
  const [trafficMode, setTrafficMode] = useState<TrafficMode>('nxdomain');
  const [trafficQps, setTrafficQps] = useState(50);
  const [trafficDuration, setTrafficDuration] = useState(30);
  const [trafficRatio, setTrafficRatio] = useState(0.7);
  const [trafficTimeout, setTrafficTimeout] = useState(1.0);
  const [trafficMaxInflight, setTrafficMaxInflight] = useState(200);
  const [trafficBusy, setTrafficBusy] = useState(false);
  const [trafficStatus, setTrafficStatus] = useState('');
  const [trafficOutput, setTrafficOutput] = useState('');
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
  const [readmeText, setReadmeText] = useState<string>('Loading README...');
  const [readmeError, setReadmeError] = useState<string>('');
  const [topologyHealth, setTopologyHealth] = useState<
    Record<string, TopologyHealth>
  >({});
  const [scenarioStatus, setScenarioStatus] = useState('');
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [scenarioBusy, setScenarioBusy] = useState(false);
  const [scenarioPerfTable, setScenarioPerfTable] =
    useState<Record<ScenarioId, ScenarioPerfRow>>(DEFAULT_PERF_TABLE);
  const [scenarioResourceTable, setScenarioResourceTable] =
    useState<Record<ScenarioId, ScenarioResourceRow>>(DEFAULT_RESOURCE_TABLE);
  const [scenarioSecurityTable, setScenarioSecurityTable] =
    useState<Record<ScenarioId, ScenarioSecurityRow>>(DEFAULT_SECURITY_TABLE);
  const [analysisNotes, setAnalysisNotes] = useState('');

  const isAuthError = (err: Error) =>
    err.message.includes('HTTP 401') || err.message.includes('HTTP 403');

  const [registryNodes, setRegistryNodes] = useState<RegistryNode[]>([]);
  const [registryErrors, setRegistryErrors] = useState<Record<string, string>>(
    {}
  );

  const scrollToConfigs = () => {
    const target = document.getElementById('configs');
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      window.location.hash = 'configs';
    }
  };

  const formatRoleLabel = (value: string) =>
    value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

  const buildNodeInfoFromRegistry = (node: RegistryNode): NodeInfo => {
    const base = TOPOLOGY_NODE_MAP.get(node.name);
    const meta = [
      ...(base?.meta || []),
      node.agent_role ? `agent: ${node.agent_role}` : '',
      node.agent_version ? `agent version: ${node.agent_version}` : '',
      node.agent_hostname ? `agent host: ${node.agent_hostname}` : '',
    ].filter(Boolean);
    return {
      name: node.name,
      role: base?.role || formatRoleLabel(node.role || node.name),
      ip: node.ip || base?.ip || 'unknown',
      ports: base?.ports || `${node.port}/tcp`,
      health: node.ok ? 'up' : 'down',
      tags: base?.tags || [node.agent_role || 'node'],
      meta,
    };
  };

  const renderNodeCard = (node: NodeInfo) => {
    const nodeHealth = topologyHealth[node.name]?.health ?? node.health;
    const healthDetail = topologyHealth[node.name]?.detail;
    const healthTitle = healthDetail
      ? `Health: ${healthDetail}. Click to open config viewer.`
      : 'Click to open config viewer.';
    return (
      <div key={node.name} className="node-card">
        <div className="node-header">
          <div className="node-title">{node.name}</div>
          <button
            type="button"
            className={`status-dot action ${healthClass(nodeHealth)}`}
            onClick={scrollToConfigs}
            title={healthTitle}
          >
            {healthLabel(nodeHealth)}
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
    );
  };

  const refreshTopologyHealth = async () => {
    const updates: Record<string, TopologyHealth> = {};
    for (const node of TOPOLOGY_NODES) {
      updates[node.name] = { health: 'unknown', detail: 'Not checked' };
    }

    const markNode = (name: string, ok: boolean, detail?: string) => {
      updates[name] = {
        health: ok ? 'up' : 'down',
        detail: detail || (ok ? 'ok' : 'failed'),
      };
    };

    const markUnknown = (name: string, detail: string) => {
      updates[name] = { health: 'unknown', detail };
    };

    await Promise.all([
      (async () => {
        try {
          const res = await getJson<HealthResponse>(
            `${API_BASE}/trusted/health`,
            clientHeaders
          );
          markNode(
            'client',
            Boolean(res.ok),
            res.ok ? `profile=${res.profile || 'trusted'}` : 'health check failed'
          );
        } catch (err) {
          const error = err as Error;
          if (isAuthError(error)) {
            markUnknown('client', 'missing client API key');
          } else {
            markNode('client', false, error.message);
          }
        }
      })(),
      (async () => {
        try {
          const res = await getJson<HealthResponse>(
            `${API_BASE}/untrusted/health`,
            clientHeaders
          );
          markNode(
            'untrusted',
            Boolean(res.ok),
            res.ok ? `profile=${res.profile || 'untrusted'}` : 'health check failed'
          );
        } catch (err) {
          const error = err as Error;
          if (isAuthError(error)) {
            markUnknown('untrusted', 'missing client API key');
          } else {
            markNode('untrusted', false, error.message);
          }
        }
      })(),
      (async () => {
        try {
          const res = await getJson<{ ok: boolean }>(
            `${LAB_API_BASE}/health`,
            labHeaders
          );
          markNode('lab_api', Boolean(res.ok), res.ok ? 'ok' : 'health check failed');
        } catch (err) {
          markNode('lab_api', false, (err as Error).message);
        }
      })(),
    ]);

    if (missingLabKey) {
      markUnknown('authoritative_parent', 'missing lab API key');
      markUnknown('authoritative_child', 'missing lab API key');
      markUnknown('resolver', 'missing lab API key');
      markUnknown('resolver_plain', 'missing lab API key');
      markUnknown('dot_proxy', 'missing lab API key');
      markUnknown('doh_proxy', 'missing lab API key');
      setRegistryNodes([]);
      setRegistryErrors({ lab_api: 'missing lab API key' });
      setTopologyHealth((prev) => ({ ...prev, ...updates }));
      return;
    }

    try {
      const nodes = await getJson<NodesResponse>(`${LAB_API_BASE}/nodes`, labHeaders);
      setRegistryNodes(nodes.nodes || []);
      setRegistryErrors(nodes.errors || {});
      for (const node of nodes.nodes || []) {
        if (!node.name) continue;
        const detail = node.ok
          ? `tcp ${node.latency_ms?.toFixed(1) ?? '?'}ms`
          : 'check failed';
        markNode(node.name, node.ok, detail);
      }
    } catch (err) {
      const error = err as Error;
      if (isAuthError(error)) {
        markUnknown('authoritative_parent', 'missing lab API key');
        markUnknown('authoritative_child', 'missing lab API key');
        markUnknown('resolver', 'missing lab API key');
        markUnknown('resolver_plain', 'missing lab API key');
        setRegistryNodes([]);
        setRegistryErrors({ lab_api: 'missing lab API key' });
      } else {
        markUnknown('authoritative_parent', error.message);
        markUnknown('authoritative_child', error.message);
        markUnknown('resolver', error.message);
        markUnknown('resolver_plain', error.message);
        setRegistryNodes([]);
        setRegistryErrors({ lab_api: error.message });
      }
    }

    try {
      const dot = await postJson<PrivacyCheckResponse>(
        `${LAB_API_BASE}/privacy/dot-check`,
        { name: PRIVACY_EXISTING_NAME, qtype: 'A' },
        labHeaders
      );
      markNode(
        'dot_proxy',
        Boolean(dot.ok),
        dot.ok ? `dot ${dot.elapsed_ms}ms` : dot.detail || 'check failed'
      );
    } catch (err) {
      const error = err as Error;
      if (isAuthError(error)) {
        markUnknown('dot_proxy', 'missing lab API key');
      } else {
        markNode('dot_proxy', false, error.message);
      }
    }

    try {
      const doh = await postJson<PrivacyCheckResponse>(
        `${LAB_API_BASE}/privacy/doh-check`,
        { name: PRIVACY_EXISTING_NAME, qtype: 'A' },
        labHeaders
      );
      markNode(
        'doh_proxy',
        Boolean(doh.ok),
        doh.ok ? `doh ${doh.elapsed_ms}ms` : doh.detail || 'check failed'
      );
    } catch (err) {
      const error = err as Error;
      if (isAuthError(error)) {
        markUnknown('doh_proxy', 'missing lab API key');
      } else {
        markNode('doh_proxy', false, error.message);
      }
    }

    setTopologyHealth((prev) => ({ ...prev, ...updates }));
  };

  const updatePerfCell = (
    scenarioId: ScenarioId,
    key: keyof ScenarioPerfRow,
    value: string
  ) => {
    setScenarioPerfTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], [key]: value },
    }));
  };

  const patchPerfRow = (
    scenarioId: ScenarioId,
    patch: Partial<ScenarioPerfRow>
  ) => {
    setScenarioPerfTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], ...patch },
    }));
  };

  const updateResourceCell = (
    scenarioId: ScenarioId,
    key: keyof ScenarioResourceRow,
    value: string
  ) => {
    setScenarioResourceTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], [key]: value },
    }));
  };

  const patchResourceRow = (
    scenarioId: ScenarioId,
    patch: Partial<ScenarioResourceRow>
  ) => {
    setScenarioResourceTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], ...patch },
    }));
  };

  const updateSecurityCell = (
    scenarioId: ScenarioId,
    key: keyof ScenarioSecurityRow,
    value: string
  ) => {
    setScenarioSecurityTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], [key]: value },
    }));
  };

  const patchSecurityRow = (
    scenarioId: ScenarioId,
    patch: Partial<ScenarioSecurityRow>
  ) => {
    setScenarioSecurityTable((prev) => ({
      ...prev,
      [scenarioId]: { ...prev[scenarioId], ...patch },
    }));
  };

  const downloadCsv = (filename: string, rows: Array<Array<string>>) => {
    const escapeCell = (value: string) => {
      const normalized = value ?? '';
      const needsQuote = /[",\n]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return needsQuote ? `"${escaped}"` : escaped;
    };
    const content = rows.map((row) => row.map(escapeCell).join(',')).join('\n');
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const exportPerfCsv = () => {
    const header = [
      'Konfiguracja',
      'Availability (%)',
      'Avg latency (ms)',
      'p50 (ms)',
      'p95 (ms)',
      'p99 (ms)',
      'QPS max',
      'Baseline QPS',
      'Error rate (%)',
      'Cache hit (%)',
      'NXDOMAIN (%)',
      'SERVFAIL (%)',
      'Upstream QPS',
      'Uwagi',
    ];
    const rows = SCENARIOS.map((scenario) => {
      const row = scenarioPerfTable[scenario.id];
      return [
        scenario.label,
        row.availabilityPct,
        row.avgLatency,
        row.p50,
        row.p95,
        row.p99,
        row.qpsMax,
        row.baselineQps,
        row.errorRate,
        row.cacheHit,
        row.nxdomain,
        row.servfail,
        row.upstreamQps,
        row.notes,
      ];
    });
    const stamp = new Date().toISOString().slice(0, 10);
    downloadCsv(`scenario-perf-${stamp}.csv`, [header, ...rows]);
  };

  const exportResourceCsv = () => {
    const header = [
      'Konfiguracja',
      'CPU (%)',
      'RAM (MB)',
      'Mem (%)',
      'Rate-limited (%)',
      'Upstream QPS',
      'Amplifikacja UDP (B)',
      'Amplifikacja TCP (B)',
      'Avg UDP (B)',
      'Avg TCP (B)',
      'TC rate (%)',
      'TCP fallback (%)',
      'Uwagi',
    ];
    const rows = SCENARIOS.map((scenario) => {
      const row = scenarioResourceTable[scenario.id];
      return [
        scenario.label,
        row.cpu,
        row.ram,
        row.memPct,
        row.ratelimitedPct,
        row.upstreamQps,
        row.amplificationUdp,
        row.amplificationTcp,
        row.avgUdpSize,
        row.avgTcpSize,
        row.tcRate,
        row.tcpRate,
        row.notes,
      ];
    });
    const stamp = new Date().toISOString().slice(0, 10);
    downloadCsv(`scenario-resources-${stamp}.csv`, [header, ...rows]);
  };

  const exportSecurityCsv = () => {
    const header = [
      'Konfiguracja',
      'DNSSEC OK (%)',
      'BOGUS (%)',
      'DoT success (%)',
      'DoH success (%)',
      'Cert errors (%)',
      'QNAME minimization',
      'ECS leakage',
      'Uwagi',
    ];
    const rows = SCENARIOS.map((scenario) => {
      const row = scenarioSecurityTable[scenario.id];
      return [
        scenario.label,
        row.dnssecOkPct,
        row.bogusPct,
        row.dotSuccessPct,
        row.dohSuccessPct,
        row.certErrorsPct,
        row.qnameMin,
        row.ecsLeakage,
        row.notes,
      ];
    });
    const stamp = new Date().toISOString().slice(0, 10);
    downloadCsv(`scenario-security-${stamp}.csv`, [header, ...rows]);
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
  const trafficModeOptions: { value: TrafficMode; label: string }[] = [
    { value: 'nxdomain', label: 'NXDOMAIN burst' },
    { value: 'valid', label: 'Valid names only' },
    { value: 'mix', label: 'Mixed (ratio)' },
  ];
  const trafficQtypeOptions = [
    'A',
    'AAAA',
    'TXT',
    'MX',
    'NS',
    'SOA',
    'SRV',
    'CAA',
    'DNSKEY',
    'DS',
    'RRSIG',
    'NSEC',
    'NSEC3',
    'NSEC3PARAM',
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
  const registrySummary = useMemo(() => {
    const total = registryNodes.length;
    const up = registryNodes.filter((node) => node.ok).length;
    return { total, up };
  }, [registryNodes]);
  const registryNodeNames = useMemo(
    () => new Set(registryNodes.map((node) => node.name)),
    [registryNodes]
  );
  const extraNodes = useMemo(
    () => TOPOLOGY_NODES.filter((node) => !registryNodeNames.has(node.name)),
    [registryNodeNames]
  );
  const registryErrorList = useMemo(
    () => Object.values(registryErrors).filter(Boolean),
    [registryErrors]
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
    refreshTopologyHealth();
  }, []);

  useEffect(() => {
    let cancelled = false;
    const loadReadme = async () => {
      try {
        const res = await fetch('/readme.md');
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const text = await res.text();
        if (!cancelled) {
          setReadmeText(text.trim());
          setReadmeError('');
        }
      } catch {
        if (!cancelled) {
          setReadmeText('');
          setReadmeError('README.md not available.');
        }
      }
    };
    loadReadme();
    return () => {
      cancelled = true;
    };
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

  useEffect(() => {
    try {
      window.localStorage.setItem(
        RUNBOOK_VISIBILITY_KEY,
        JSON.stringify(runbookHidden)
      );
    } catch {
      // Ignore local storage errors.
    }
  }, [runbookHidden]);

  const runDig = async () => {
    await runDigWithRequest(req, 'Running dig...');
  };

  const runDigWithCapture = async () => {
    if (missingLabKey) {
      setStatus('Missing Lab API key.');
      return;
    }
    setIsBusy(true);
    setStatus('Starting resolver + authoritative captures...');
    setOutput(null);

    const startedTargets: CaptureTarget[] = [];
    const captureFiles: string[] = [];

    try {
      const resolverCapture = await postJson<CaptureStartResponse>(
        `${LAB_API_BASE}/capture/start`,
        { target: 'resolver', filter: captureFilter },
        labHeaders
      );
      startedTargets.push('resolver');
      captureFiles.push(resolverCapture.file);

      const authCapture = await postJson<CaptureStartResponse>(
        `${LAB_API_BASE}/capture/start`,
        { target: 'authoritative', filter: captureFilter },
        labHeaders
      );
      startedTargets.push('authoritative');
      captureFiles.push(authCapture.file);

      setStatus('Captures running. Executing dig...');
      const result = await executeDigRequest(req);
      setOutput(result.output);
      const captureNote =
        captureFiles.length > 0 ? ` • Captures: ${captureFiles.join(', ')}` : '';
      setStatus(
        result.ok
          ? `${formatStatusLabel(result.rcode, result.ad)}${captureNote}`
          : `Completed with errors${captureNote}`
      );
    } catch (err) {
      setOutput(null);
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setStatus,
        (value) => setOutput({ ok: false, command: 'diagnostics', text: value })
      );
    } finally {
      for (const target of startedTargets) {
        try {
          await postJson<CaptureStopResponse>(
            `${LAB_API_BASE}/capture/stop`,
            { target },
            labHeaders
          );
        } catch {
          // ignore stop errors
        }
      }
      if (startedTargets.length > 0) {
        await loadCaptures();
      }
      if (outputRef.current) {
        outputRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      setIsBusy(false);
    }
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

  const runScenario = async (scenarioId: ScenarioId) => {
    if (scenarioBusy) {
      return;
    }
    setScenarioBusy(true);
    setScenarioStatus(`Applying ${scenarioId}...`);
    setActiveScenario(scenarioId);
    setActiveSection('scenarios');
    document.getElementById('scenarios')?.scrollIntoView({
      behavior: 'smooth',
      block: 'start',
    });

    let scenarioReq: DigRequest = { ...req };
    let scenarioPerfTarget: PerfTarget = perfTarget;
    let scenarioAmpDnssec = ampDnssec;
    let nextUnbound: UnboundControls | null = null;
    let nextBind: BindControls | null = null;
    let dotResult: PrivacyCheckResponse | null = null;
    let dohResult: PrivacyCheckResponse | null = null;
    let indicatorSnapshot: IndicatorState | null = null;
    let dnssecCheck:
      | {
          ad?: boolean;
          rcode?: string;
        }
      | null = null;

    try {
      if (scenarioId === 'S1') {
        scenarioReq = {
          ...scenarioReq,
          client: 'trusted',
          resolver: 'plain',
          dnssec: false,
          name: 'www.example.test',
          qtype: 'A',
        };
        scenarioPerfTarget = 'resolver_plain';
        scenarioAmpDnssec = false;
        setReq(scenarioReq);
        setPerfTarget(scenarioPerfTarget);
        setAmpDnssec(false);
        setMixDnssec(false);
      } else if (scenarioId === 'S2') {
        scenarioReq = {
          ...scenarioReq,
          client: 'trusted',
          resolver: 'valid',
          dnssec: true,
          name: 'www.example.test',
          qtype: 'A',
        };
        scenarioPerfTarget = 'resolver_valid';
        scenarioAmpDnssec = true;
        setReq(scenarioReq);
        setPerfTarget(scenarioPerfTarget);
        setAmpDnssec(true);
        setMixDnssec(true);
      } else if (scenarioId === 'S3') {
        scenarioReq = {
          ...scenarioReq,
          client: 'trusted',
          resolver: 'valid',
          dnssec: true,
        };
        scenarioPerfTarget = 'resolver_valid';
        setReq(scenarioReq);
        setPerfTarget(scenarioPerfTarget);
        nextUnbound = { ...unboundCtl, aggressive_nsec: true };
        setUnboundCtl(nextUnbound);
      } else if (scenarioId === 'S4') {
        scenarioReq = {
          ...scenarioReq,
          client: 'trusted',
          resolver: 'valid',
          dnssec: true,
        };
        scenarioPerfTarget = 'resolver_valid';
        setReq(scenarioReq);
        setPerfTarget(scenarioPerfTarget);
        if (missingLabKey) {
          setScenarioStatus('S4 requires Lab API key to switch signing mode.');
          return;
        }
        try {
          await switchSigningMode('nsec3');
        } catch (err) {
          setScenarioStatus((err as Error).message);
          return;
        }
      } else if (scenarioId === 'S5') {
        setPrivacyTab('dot');
      } else if (scenarioId === 'S6') {
        nextUnbound = {
          ...unboundCtl,
          ratelimit: 100,
          ip_ratelimit: 25,
          aggressive_nsec: true,
        };
        nextBind = {
          ...bindCtl,
          rrl_enabled: true,
          rrl_responses_per_second: 10,
          rrl_window: 5,
          rrl_slip: 2,
        };
        setUnboundCtl(nextUnbound);
        setBindCtl(nextBind);
      }

      if (missingLabKey) {
        setScenarioStatus('Missing Lab API key. Settings applied only.');
        return;
      }

      if (nextUnbound || nextBind) {
        setScenarioStatus('Applying Controls...');
        await applyControls({
          unbound: nextUnbound ?? unboundCtl,
          bind: nextBind ?? bindCtl,
        });
      }

      if (scenarioId === 'S3') {
        setScenarioStatus('Running aggressive NSEC proof (cold)...');
        await runAggressiveNsecProofCold();
      } else if (scenarioId === 'S5') {
        setScenarioStatus('Running DoT check...');
        dotResult = await runPrivacyCheck('dot');
        setScenarioStatus('Running DoH check...');
        dohResult = await runPrivacyCheck('doh');
      }

      setScenarioStatus('Refreshing indicators...');
      indicatorSnapshot = await loadIndicators();
      if (scenarioReq.dnssec) {
        setScenarioStatus('Checking DNSSEC validation...');
        try {
          dnssecCheck = await executeLabDig({
            ...scenarioReq,
            dnssec: true,
            trace: false,
            short: false,
          });
        } catch {
          dnssecCheck = null;
        }
      }

      setScenarioStatus('Running baseline (availability + probe)...');
      let baseline = await runBaseline(scenarioReq);
      if (!baseline && scenarioId === 'S4') {
        setScenarioStatus('Baseline failed after NSEC3 switch. Retrying in 5s...');
        await new Promise((resolve) => setTimeout(resolve, 5000));
        setScenarioStatus('Retrying baseline (availability + probe)...');
        baseline = await runBaseline(scenarioReq);
      }
      const baselineFailed = !baseline;
      if (baselineFailed) {
        setScenarioStatus(
          'Baseline failed. Some table fields will be empty. Check Availability status.'
        );
      }

      setScenarioStatus('Running dnsperf (throughput + latency)...');
      const dnsperf = await runDnsperf(scenarioPerfTarget);

      setScenarioStatus('Running amplification test...');
      const ampResults = await runAmplificationTest({
        profile: scenarioReq.client,
        resolver: scenarioReq.resolver,
        dnssec: scenarioAmpDnssec,
        name: ampName,
      });

      const perfPatch: Partial<ScenarioPerfRow> = {};
      if (baseline) {
        perfPatch.availabilityPct =
          baseline.availability_ratio !== undefined
            ? (baseline.availability_ratio * 100).toFixed(2)
            : '';
        perfPatch.avgLatency =
          baseline.avg_ms !== undefined && baseline.avg_ms > 0
            ? baseline.avg_ms.toFixed(2)
            : '';
        perfPatch.p50 =
          typeof baseline.p50_ms === 'number' && baseline.p50_ms > 0
            ? baseline.p50_ms.toFixed(1)
            : '';
        perfPatch.p95 =
          typeof baseline.p95_ms === 'number' && baseline.p95_ms > 0
            ? baseline.p95_ms.toFixed(1)
            : '';
        perfPatch.p99 =
          typeof baseline.p99_ms === 'number' && baseline.p99_ms > 0
            ? baseline.p99_ms.toFixed(1)
            : '';
        perfPatch.baselineQps =
          typeof baseline.qps === 'number' ? baseline.qps.toFixed(2) : '';
        perfPatch.cacheHit =
          typeof baseline.cache_hit_ratio === 'number'
            ? (baseline.cache_hit_ratio * 100).toFixed(2)
            : '';
        perfPatch.nxdomain =
          typeof baseline.nxdomain_ratio === 'number'
            ? (baseline.nxdomain_ratio * 100).toFixed(2)
            : '';
        perfPatch.servfail =
          typeof baseline.servfail_ratio === 'number'
            ? (baseline.servfail_ratio * 100).toFixed(2)
            : '';
        perfPatch.upstreamQps =
          baseline.upstream_qps !== undefined
            ? baseline.upstream_qps.toFixed(2)
            : '';
      }
      if (dnsperf) {
        perfPatch.qpsMax = dnsperf.qps !== undefined ? dnsperf.qps.toFixed(2) : '';
        if (dnsperf.avg_latency_ms !== undefined) {
          perfPatch.avgLatency = dnsperf.avg_latency_ms.toFixed(2);
        }
        if (
          dnsperf.queries_sent !== undefined &&
          dnsperf.queries_lost !== undefined &&
          dnsperf.queries_sent > 0
        ) {
          const errRate = (dnsperf.queries_lost / dnsperf.queries_sent) * 100;
          perfPatch.errorRate = errRate.toFixed(2);
        }
      }
      patchPerfRow(scenarioId, perfPatch);

      const resourcePatch: Partial<ScenarioResourceRow> = {};
      if (baseline) {
        resourcePatch.cpu =
          baseline.cpu_pct !== undefined
            ? formatPercentValue(baseline.cpu_pct)
            : '';
        resourcePatch.ram =
          baseline.mem_mb !== undefined ? baseline.mem_mb.toFixed(1) : '';
        resourcePatch.memPct =
          baseline.mem_pct !== undefined
            ? formatPercentValue(baseline.mem_pct)
            : '';
        resourcePatch.ratelimitedPct =
          baseline.ratelimited_ratio !== undefined
            ? formatPercentValue(baseline.ratelimited_ratio * 100)
            : '';
        resourcePatch.upstreamQps =
          baseline.upstream_qps !== undefined
            ? baseline.upstream_qps.toFixed(2)
            : '';
      }
      if (ampResults && ampResults.length > 0) {
        const maxUdp = Math.max(...ampResults.map((row) => row.max_udp_size));
        const maxTcp = Math.max(...ampResults.map((row) => row.max_tcp_size));
        const avgUdp =
          ampResults.reduce((sum, row) => sum + row.avg_udp_size, 0) /
          ampResults.length;
        const avgTcp =
          ampResults.reduce((sum, row) => sum + row.avg_tcp_size, 0) /
          ampResults.length;
        const avgTcRate =
          ampResults.reduce((sum, row) => sum + row.tc_rate, 0) /
          ampResults.length;
        const avgTcpRate =
          ampResults.reduce((sum, row) => sum + row.tcp_rate, 0) /
          ampResults.length;
        resourcePatch.amplificationUdp = Number.isFinite(maxUdp)
          ? String(Math.round(maxUdp))
          : '';
        resourcePatch.amplificationTcp = Number.isFinite(maxTcp)
          ? String(Math.round(maxTcp))
          : '';
        resourcePatch.avgUdpSize = Number.isFinite(avgUdp) ? avgUdp.toFixed(1) : '';
        resourcePatch.avgTcpSize = Number.isFinite(avgTcp) ? avgTcp.toFixed(1) : '';
        resourcePatch.tcRate = Number.isFinite(avgTcRate)
          ? (avgTcRate * 100).toFixed(2)
          : '';
        resourcePatch.tcpRate = Number.isFinite(avgTcpRate)
          ? (avgTcpRate * 100).toFixed(2)
          : '';
      }
      patchResourceRow(scenarioId, resourcePatch);

      const securityPatch: Partial<ScenarioSecurityRow> = {};
      if (dnssecCheck?.ad === true) {
        securityPatch.dnssecOkPct = '100';
        securityPatch.bogusPct = '0';
      } else if (dnssecCheck?.ad === false && scenarioReq.dnssec) {
        securityPatch.dnssecOkPct = '0';
      }
      if (dotResult) {
        securityPatch.dotSuccessPct =
          dotResult.ok && dotResult.rcode === 'NOERROR' ? '100' : '0';
      }
      if (dohResult) {
        securityPatch.dohSuccessPct =
          dohResult.ok && dohResult.rcode === 'NOERROR' ? '100' : '0';
      }
      if (indicatorSnapshot?.qnameMinim !== undefined) {
        securityPatch.qnameMin = formatIndicator(indicatorSnapshot.qnameMinim);
      }
      if (Object.keys(securityPatch).length > 0) {
        patchSecurityRow(scenarioId, securityPatch);
      }

      setScenarioStatus(
        baselineFailed
          ? `Scenario ${scenarioId} completed. Baseline failed; some fields are empty.`
          : `Scenario ${scenarioId} completed. Results written to tables.`
      );
    } catch (err) {
      setScenarioStatus((err as Error).message);
    } finally {
      setScenarioBusy(false);
    }
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

  const runAggressiveNsecProofCold = async () => {
    if (missingLabKey) {
      setProofStatus('Missing Lab API key.');
      return;
    }
    setProofBusy(true);
    setProofStatus('Running aggressive NSEC demo (OFF → ON)...');
    setProofOutput('');
    setProofCaptureFile('');
    setProofArtifactFile('');

    try {
      const result = await postJson<DemoAggressiveNsecResponse>(
        `${LAB_API_BASE}/demo/aggressive-nsec`,
        {
          profile: 'trusted',
          resolver: 'valid',
          zone: 'example.test',
          count: proofCount,
          qps: proofQps,
          capture: true,
          capture_target: proofCaptureTarget,
          cold_restart: true,
          restore: true,
          zip: true,
        },
        labHeaders
      );

      const capture =
        result.phases.find((phase) => phase.aggressive_nsec && phase.capture_file)
          ?.capture_file ||
        result.phases.find((phase) => phase.capture_file)?.capture_file ||
        '';
      setProofCaptureFile(capture || '');
      const artifact = result.artifact_zip || result.artifact_json || '';
      setProofArtifactFile(artifact);

      const lines: string[] = [];
      lines.push(`# Aggressive NSEC demo (${result.zone})`);
      lines.push(`queries: ${result.count}, qps: ${result.qps}`);
      if (artifact) {
        lines.push(`artifact: ${artifact}`);
      }
      if (result.notes && result.notes.length > 0) {
        lines.push('');
        lines.push('Notes:');
        result.notes.forEach((note) => lines.push(`- ${note}`));
      }

      result.phases.forEach((phase) => {
        const label = phase.aggressive_nsec ? 'ON' : 'OFF';
        lines.push('');
        lines.push(`## Phase ${label}`);
        lines.push(`delta.queries: ${phase.delta.queries ?? '—'}`);
        lines.push(`delta.cache_hits: ${phase.delta.cache_hits ?? '—'}`);
        lines.push(`delta.cache_miss: ${phase.delta.cache_miss ?? '—'}`);
        lines.push(`delta.nxdomain: ${phase.delta.nxdomain ?? '—'}`);
        lines.push(
          `delta.aggressive_nxdomain: ${phase.delta.aggressive_nxdomain ?? '—'}`
        );
        lines.push(
          `delta.recursivereplies: ${phase.delta.recursivereplies ?? '—'}`
        );
        if (phase.capture_file) {
          lines.push(`capture: ${phase.capture_file}`);
        }
        lines.push('');
        lines.push(`dig first: ${phase.dig_first.command}`);
        lines.push(
          phase.dig_first.stdout.trim() ||
            phase.dig_first.stderr.trim() ||
            'no output'
        );
        lines.push('');
        lines.push(`dig last: ${phase.dig_last.command}`);
        lines.push(
          phase.dig_last.stdout.trim() ||
            phase.dig_last.stderr.trim() ||
            'no output'
        );
      });

      setProofOutput(lines.join('\n'));
      setProofStatus(
        result.ok
          ? 'Aggressive NSEC demo completed.'
          : 'Aggressive NSEC demo completed with warnings.'
      );
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
    await refreshTopologyHealth();
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

  const loadIndicators = async (): Promise<IndicatorState | null> => {
    if (missingLabKey) {
      setIndicators({
        loading: false,
        message: 'Missing Lab API key.',
      });
      return null;
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

    const nextIndicators: IndicatorState = {
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
    };
    setIndicators(nextIndicators);
    return nextIndicators;
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

  const runbookLabel = (id: RunbookId) =>
    RUNBOOKS.find((entry) => entry.id === id)?.title || id;

  const updateRunbookQueue = (index: number, value: RunbookId) => {
    setRunbookQueue((prev) => prev.map((item, i) => (i === index ? value : item)));
  };

  const toggleRunbookHidden = (id: RunbookId) => {
    setRunbookHidden((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const runRunbookSequence = async (ids: RunbookId[]) => {
    if (missingLabKey) {
      setRunbookStatus('Missing Lab API key.');
      return;
    }
    if (runbookBusy) {
      return;
    }
    setRunbookBusy(true);
    try {
      for (let i = 0; i < ids.length; i += 1) {
        const id = ids[i];
        const label = runbookLabel(id);
        setRunbookStatus(`Running ${label} (${i + 1}/${ids.length})...`);
        const result = await postJson<RunbookResponse>(
          `${LAB_API_BASE}/runbook/${id}`,
          {},
          labHeaders
        );
        setRunbookResults((prev) => ({ ...prev, [id]: result }));
        setRunbookStatus(
          result.ok
            ? `${label} completed (${i + 1}/${ids.length}).`
            : `${label} completed with failures (${i + 1}/${ids.length}).`
        );
        if (!result.ok) {
          break;
        }
      }
    } catch (err) {
      setRunbookStatus((err as Error).message);
    } finally {
      setRunbookBusy(false);
    }
  };

  const runRunbook = async (id: RunbookId) => {
    if (missingLabKey) {
      setRunbookStatus('Missing Lab API key.');
      return;
    }
    const label = runbookLabel(id);
    setRunbookBusy(true);
    setRunbookStatus(`Running ${label}...`);
    try {
      const result = await postJson<RunbookResponse>(
        `${LAB_API_BASE}/runbook/${id}`,
        {},
        labHeaders
      );
      setRunbookResults((prev) => ({ ...prev, [id]: result }));
      setRunbookStatus(
        result.ok
          ? `${label} completed.`
          : `${label} completed with failures.`
      );
    } catch (err) {
      setRunbookStatus((err as Error).message);
    } finally {
      setRunbookBusy(false);
    }
  };

  const clearRunbook = (id: RunbookId) => {
    setRunbookResults((prev) => ({ ...prev, [id]: null }));
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

  const downloadDemoArtifact = async (file: string) => {
    setIsBusy(true);
    setProofStatus(`Downloading artifact ${file}...`);
    try {
      const res = await fetch(
        `${LAB_API_BASE}/demo/download?file=${encodeURIComponent(file)}`,
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
      setProofStatus(`Artifact downloaded: ${file}`);
    } catch (err) {
      setProofStatus(`Artifact download failed: ${(err as Error).message}`);
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

  const runPrivacyCheck = async (
    kind: 'dot' | 'doh'
  ): Promise<PrivacyCheckResponse | null> => {
    if (missingLabKey) {
      setPrivacyStatus('Missing Lab API key.');
      return null;
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
      return result;
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setPrivacyStatus,
        setPrivacyOutput
      );
      return null;
    } finally {
      setPrivacyBusy(false);
    }
  };

  const formatCommandOutput = (
    command: string,
    stdout: string,
    stderr: string
  ) => {
    const blocks = [`Command:\n${command}`];
    if (stdout.trim()) {
      blocks.push(`STDOUT:\n${stdout.trimEnd()}`);
    }
    if (stderr.trim()) {
      blocks.push(`STDERR:\n${stderr.trimEnd()}`);
    }
    return blocks.join('\n\n');
  };

  const createMailbox = async () => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    if (!emailUserAddress.trim() || !emailUserPassword.trim()) {
      setEmailStatus('Provide mailbox address and password.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Creating mailbox...');
    setEmailUserOutput('');
    try {
      const res = await postJson<EmailUserResponse>(
        `${LAB_API_BASE}/email/user/add`,
        {
          email: emailUserAddress.trim(),
          password: emailUserPassword,
        },
        labHeaders
      );
      setEmailUserOutput(formatCommandOutput(res.command, res.stdout, res.stderr));
      setEmailStatus(res.ok ? 'Mailbox ready.' : 'Mailbox setup failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const updateMailboxPassword = async () => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    if (!emailUserAddress.trim() || !emailUserPassword.trim()) {
      setEmailStatus('Provide mailbox address and new password.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Updating mailbox password...');
    setEmailUserOutput('');
    try {
      const res = await postJson<EmailUserResponse>(
        `${LAB_API_BASE}/email/user/update`,
        {
          email: emailUserAddress.trim(),
          password: emailUserPassword,
        },
        labHeaders
      );
      setEmailUserOutput(formatCommandOutput(res.command, res.stdout, res.stderr));
      setEmailStatus(res.ok ? 'Mailbox password updated.' : 'Password update failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const deleteMailbox = async () => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    if (!emailUserAddress.trim()) {
      setEmailStatus('Provide mailbox address to delete.');
      return;
    }
    const confirmed = window.confirm(
      `Delete mailbox ${emailUserAddress.trim()}? This cannot be undone.`
    );
    if (!confirmed) {
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Deleting mailbox...');
    setEmailUserOutput('');
    try {
      const res = await postJson<EmailUserResponse>(
        `${LAB_API_BASE}/email/user/delete`,
        { email: emailUserAddress.trim() },
        labHeaders
      );
      setEmailUserOutput(formatCommandOutput(res.command, res.stdout, res.stderr));
      setEmailStatus(res.ok ? 'Mailbox deleted.' : 'Mailbox delete failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const sendEmail = async () => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Sending mail...');
    setEmailOutput('');
    try {
      const payload: Record<string, unknown> = {
        to: emailTo,
        from: emailFrom,
        subject: emailSubject,
        body: emailBody,
        server: emailServer,
        port: emailPort,
        tls_mode: emailTlsMode,
      };
      if (emailUseAuth) {
        payload.auth_user = emailAuthUser;
        payload.auth_password = emailAuthPass;
        payload.auth_type = emailAuthType;
      }
      const res = await postJson<EmailSendResponse>(
        `${LAB_API_BASE}/email/send`,
        payload,
        labHeaders
      );
      setEmailOutput(formatCommandOutput(res.command, res.stdout, res.stderr));
      setEmailStatus(res.ok ? 'Mail sent.' : 'Mail send failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const loadEmailLogs = async (filterOverride?: string) => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Loading mail logs...');
    try {
      const filterValue = filterOverride ?? emailLogFilter;
      const params = new URLSearchParams({
        tail: String(emailLogTail),
      });
      if (filterValue.trim()) {
        params.set('grep', filterValue.trim());
      }
      const res = await getJson<EmailLogResponse>(
        `${LAB_API_BASE}/email/logs?${params.toString()}`,
        labHeaders
      );
      setEmailLogFile(res.file);
      setEmailLog(formatCommandOutput(res.command, res.stdout, res.stderr));
      setEmailStatus(res.ok ? 'Logs loaded.' : 'Mail log read failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const loadInboxList = async () => {
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Loading inbox messages...');
    setEmailInboxRaw('');
    try {
      const res = await postJson<EmailMessageListResponse>(
        `${LAB_API_BASE}/email/inbox/list`,
        {
          user: emailImapUser,
          mailbox: emailImapMailbox,
          limit: emailImapLimit,
        },
        labHeaders
      );
      const messages = res.messages ?? [];
      setEmailInboxMessages(messages);
      const existing = emailInboxSelected
        ? messages.find(
            (msg) =>
              msg.id === emailInboxSelected.id &&
              msg.source === emailInboxSelected.source
          )
        : undefined;
      const nextSelected = existing ?? messages[0] ?? null;
      setEmailInboxSelected(nextSelected);
      if (!existing) {
        setEmailInboxContent('');
      }
      if (!res.ok) {
        setEmailInboxRaw(formatCommandOutput(res.command, res.stdout, res.stderr));
      }
      setEmailStatus(res.ok ? 'Inbox list loaded.' : 'Inbox list failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
    }
  };

  const viewInboxMessage = async (message?: EmailMessageSummary | null) => {
    const target = message ?? emailInboxSelected;
    if (!target) {
      setEmailStatus('Select a message to view.');
      return;
    }
    if (missingLabKey) {
      setEmailStatus('Missing Lab API key.');
      return;
    }
    setEmailBusy(true);
    setEmailStatus('Loading message...');
    setEmailInboxContent('');
    try {
      const res = await postJson<EmailMessageViewResponse>(
        `${LAB_API_BASE}/email/inbox/view`,
        {
          user: emailImapUser,
          mailbox: target.mailbox || emailImapMailbox,
          message_id: target.id,
          source: target.source,
          max_lines: 240,
        },
        labHeaders
      );
      setEmailInboxContent(res.content || res.stdout || '');
      setEmailStatus(res.ok ? 'Message loaded.' : 'Message load failed.');
    } catch (err) {
      setEmailStatus((err as Error).message);
    } finally {
      setEmailBusy(false);
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

  const runDnsperf = async (
    overrideTarget?: PerfTarget
  ): Promise<DnsperfSummary | null> => {
    if (missingLabKey) {
      setDnsperfStatus('Missing Lab API key.');
      return null;
    }
    const target = overrideTarget ?? perfTarget;
    setDnsperfBusy(true);
    setDnsperfStatus('Running dnsperf...');
    setDnsperfOutput('');
    setDnsperfSummary(null);
    try {
      const body: DnsperfRequest = {
        target,
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
      return result.summary ?? null;
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setDnsperfStatus,
        setDnsperfOutput
      );
      return null;
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

  const runTrafficGen = async () => {
    if (missingLabKey) {
      setTrafficStatus('Missing Lab API key.');
      return;
    }
    setTrafficBusy(true);
    setTrafficStatus('Running traffic generator...');
    setTrafficOutput('');
    try {
      const body: TrafficGenRequest = {
        profile: trafficProfile,
        resolver: trafficResolver,
        zone: trafficZone.trim() || 'example.test',
        qtype: trafficQtype,
        duration_s: trafficDuration,
        qps: trafficQps,
        mode: trafficMode,
        nxdomain_ratio: trafficRatio,
        timeout_s: trafficTimeout,
        max_inflight: trafficMaxInflight,
      };
      const result = await postJson<TrafficGenResponse>(
        `${LAB_API_BASE}/traffic/generate`,
        body,
        labHeaders
      );
      const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
      setTrafficOutput(`${result.command}\n\n${text}`.trim());
      setTrafficStatus(
        result.ok
          ? `Traffic completed (target ${result.target_ip}).`
          : `Traffic completed with errors (target ${result.target_ip}).`
      );
    } catch (err) {
      await maybeAttachStartupDiagnostics(
        (err as Error).message,
        setTrafficStatus,
        setTrafficOutput
      );
    } finally {
      setTrafficBusy(false);
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

  const runBaseline = async (
    overrideReq?: DigRequest
  ): Promise<BaselineSummary | null> => {
    if (missingLabKey) {
      setBaselineStatus('Missing Lab API key.');
      return null;
    }
    const activeReq = overrideReq ?? req;
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
        `${LAB_API_BASE}/availability/resolver-stats?resolver=${activeReq.resolver}`,
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
        profile: activeReq.client,
        resolver: activeReq.resolver,
        name: activeReq.name,
        qtype: activeReq.qtype,
        count: baselineProbeCount,
      };
      const probe = await postJson<AvailabilityProbeResponse>(
        `${LAB_API_BASE}/availability/probe`,
        probeBody,
        labHeaders
      );
      const rcodeCounts = probe.rcode_counts ?? {};
      const okCount =
        (rcodeCounts.NOERROR ?? 0) + (rcodeCounts.NXDOMAIN ?? 0);
      const availabilityRatio =
        probe.count > 0 ? okCount / probe.count : undefined;

      const elapsed = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
      const totalDelta = after.totals.queries - before.totals.queries;
      const qps = totalDelta / elapsed;

      const summary: BaselineSummary = {
        duration_s: elapsed,
        qps,
        total_queries: totalDelta,
        cache_hit_ratio: after.ratios.cache_hit,
        nxdomain_ratio: after.ratios.nxdomain,
        servfail_ratio: after.ratios.servfail,
        availability_ratio: availabilityRatio,
        avg_ms: probe.avg_ms,
        p50_ms: probe.p50_ms ?? probe.avg_ms,
        p95_ms: probe.p95_ms ?? probe.max_ms,
        p99_ms: probe.p99_ms ?? probe.max_ms,
        cpu_pct: stats.cpu_pct,
        mem_mb: stats.mem_bytes ? stats.mem_bytes / (1024 * 1024) : undefined,
        mem_pct: stats.mem_pct,
        ratelimited_ratio: after.ratios.ratelimited,
        upstream_qps:
          upstreamQueries !== undefined ? upstreamQueries / elapsed : undefined,
        upstream_queries: upstreamQueries,
        capture_file: captureFile ?? undefined,
      };
      setBaselineSummary(summary);
      if (captureFile) {
        setBaselineCaptureFile(captureFile);
      }
      setBaselineStatus('Baseline completed.');
      return summary;
    } catch (err) {
      setBaselineStatus((err as Error).message);
      return null;
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

  const runAmplificationTest = async (override?: {
    profile?: Client;
    resolver?: ResolverKind;
    dnssec?: boolean;
    name?: string;
  }): Promise<AmplificationResult[] | null> => {
    if (missingLabKey) {
      setAmpStatus('Missing Lab API key.');
      return null;
    }
    if (ampQtypes.length === 0 || ampEdnsSizes.length === 0) {
      setAmpStatus('Select at least one qtype and EDNS size.');
      return null;
    }
    setAmpBusy(true);
    setAmpStatus('Running amplification test...');
    try {
      const body: AmplificationTestRequest = {
        profile: override?.profile ?? req.client,
        resolver: override?.resolver ?? req.resolver,
        name: override?.name ?? ampName,
        qtypes: ampQtypes,
        edns_sizes: ampEdnsSizes,
        count_per_qtype: ampCount,
        dnssec: override?.dnssec ?? ampDnssec,
        tcp_fallback: ampTcpFallback,
      };
      const result = await postJson<AmplificationTestResponse>(
        `${LAB_API_BASE}/amplification/test`,
        body,
        labHeaders
      );
      setAmpResults(result.results);
      setAmpStatus(`Completed (${result.results.length} rows).`);
      return result.results;
    } catch (err) {
      setAmpStatus((err as Error).message);
      setAmpResults([]);
      return null;
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

  const applyControls = async (override?: {
    unbound?: UnboundControls;
    bind?: BindControls;
  }) => {
    if (missingLabKey) {
      setControlsStatus('Missing Lab API key.');
      return;
    }
    setControlsBusy(true);
    setControlsStatus('Applying controls...');
    try {
      const payload = {
        unbound: override?.unbound ?? unboundCtl,
        bind: override?.bind ?? bindCtl,
      };
      const result = await postJson<ControlsStatusResponse>(
        `${LAB_API_BASE}/controls/apply`,
        payload,
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
          <div className="eyebrow">DNS Security System</div>
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
            <div className="overview-label">Core Nodes</div>
            <div className="overview-value">
              {registrySummary.total
                ? `${registrySummary.up}/${registrySummary.total} up`
                : 'Not loaded'}
            </div>
            <div className="overview-sub">
              {registryErrorList.length
                ? registryErrorList[0]
                : 'From agent registry'}
            </div>
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
        <div className="quick-links">
          {QUICK_LINKS.map((link) => (
            <a
              key={link.title}
              className="quick-link"
              href={link.url}
              target="_blank"
              rel="noreferrer"
            >
              <div className="quick-title">{link.title}</div>
              <div className="quick-desc">{link.desc}</div>
            </a>
          ))}
        </div>
      </section>
      )}

      {isSectionVisible('topology') && (
      <section className="card" id="topology">
        <div className="card-title">Nodes</div>
        <div className="topology-subtitle">Core DNS nodes (agents)</div>
        <div className="topology-grid">
          {registryNodes.length ? (
            registryNodes.map((node) => renderNodeCard(buildNodeInfoFromRegistry(node)))
          ) : (
            <div className="status">No agent data. Check Lab API key.</div>
          )}
        </div>
        <div className="topology-subtitle">Services</div>
        <div className="topology-grid">
          {extraNodes.map((node) => renderNodeCard(node))}
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
          <div className="readme-panel">
            <div className="readme-title">README.md</div>
            {readmeError ? (
              <div className="readme-error">{readmeError}</div>
            ) : (
              <pre className="readme-content">{readmeText}</pre>
            )}
          </div>
        </div>
      </section>
      )}

      {isSectionVisible('runbook') && (
      <section className="card" id="runbook">
        <div className="card-title">Runbook (manual.md + dns.md)</div>
        <div className="hint">
          <div>
            Executes the documented manual steps via the lab API with an allow-listed
            command set (topology snapshot, smoke tests, DNSSEC maintenance).
          </div>
          <div>
            Use the results as evidence screenshots for the report where needed.
          </div>
        </div>
        {SHOW_RUNBOOK_QUEUE && (
          <div className="runbook-queue">
            <div className="runbook-queue-title">Next runs</div>
            <div className="runbook-queue-grid">
              <label>
                Run 1
                <select
                  value={runbookQueue[0]}
                  onChange={(e) =>
                    updateRunbookQueue(0, e.target.value as RunbookId)
                  }
                >
                  {RUNBOOKS.map((entry) => (
                    <option key={`runbook-queue-1-${entry.id}`} value={entry.id}>
                      {entry.title}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Run 2
                <select
                  value={runbookQueue[1]}
                  onChange={(e) =>
                    updateRunbookQueue(1, e.target.value as RunbookId)
                  }
                >
                  {RUNBOOKS.map((entry) => (
                    <option key={`runbook-queue-2-${entry.id}`} value={entry.id}>
                      {entry.title}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Run 3
                <select
                  value={runbookQueue[2]}
                  onChange={(e) =>
                    updateRunbookQueue(2, e.target.value as RunbookId)
                  }
                >
                  {RUNBOOKS.map((entry) => (
                    <option key={`runbook-queue-3-${entry.id}`} value={entry.id}>
                      {entry.title}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="actions">
              <button
                onClick={() => runRunbookSequence(runbookQueue)}
                disabled={runbookBusy || missingLabKey}
              >
                Run Next 3
              </button>
            </div>
          </div>
        )}
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="preset-grid">
          {RUNBOOKS.map((runbook) => {
            const result = runbookResults[runbook.id];
            const isHidden = runbookHidden[runbook.id];
            return (
              <div key={runbook.id} className="preset">
                <div className="preset-title">{runbook.title}</div>
                <div className="preset-desc">{runbook.desc}</div>
                {runbook.note && (
                  <div className="preset-note">{runbook.note}</div>
                )}
                <div className="actions">
                  <button
                    onClick={() => runRunbook(runbook.id)}
                    disabled={runbookBusy || missingLabKey}
                  >
                    Run
                  </button>
                  <button
                    onClick={() => clearRunbook(runbook.id)}
                    disabled={runbookBusy || !result}
                  >
                    Clear
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleRunbookHidden(runbook.id)}
                  >
                    {isHidden ? 'Show' : 'Hide'}
                  </button>
                </div>
                {result?.steps?.length ? (
                  isHidden ? (
                    <div className="status">Results hidden.</div>
                  ) : (
                    <div className="step-list">
                      {result.steps.map((step, index) => {
                        const detail = [step.stdout?.trim(), step.stderr?.trim()]
                          .filter(Boolean)
                          .join('\n');
                        return (
                          <div
                            key={`${runbook.id}-${index}`}
                            className={`step-item ${step.ok ? 'ok' : 'fail'}`}
                          >
                            <div className="step-header">
                              <div className="step-label">
                                {index + 1}. {step.step}
                              </div>
                              <span
                                className={`step-badge ${step.ok ? 'ok' : 'fail'}`}
                              >
                                {step.ok ? 'OK' : 'FAIL'}
                              </span>
                            </div>
                            <div className="step-command">{step.command}</div>
                            {detail && <pre className="step-output">{detail}</pre>}
                          </div>
                        );
                      })}
                    </div>
                  )
                ) : (
                  <div className="status">No results yet.</div>
                )}
              </div>
            );
          })}
        </div>
        <div className="status">
          {runbookStatus ||
            'Pick a runbook to execute the corresponding manual steps.'}
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

          <label>
            Capture filter
            <select
              value={captureFilter}
              onChange={(e) => setCaptureFilter(e.target.value as CaptureFilter)}
            >
              <option value="dns">dns (53)</option>
              <option value="dns+dot">dns+dot (53, 853)</option>
              <option value="all">all traffic</option>
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
          <button onClick={runDigWithCapture} disabled={isBusy || missingLabKey}>
            Run Dig + Capture
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

        <div className="section-title">CLI shortcuts (host / WSL)</div>
        <div className="hint">
          Use the host-mapped resolvers. On Windows, run via WSL or install BIND tools
          so <code>dig</code> / <code>delv</code> are available.
        </div>
        <pre className="output compact">{`# Validating resolver (host)
dig @127.0.0.1 -p 5300 ${req.name} ${req.qtype} +dnssec
delv @127.0.0.1 -p 5300 ${req.name} ${req.qtype}

# Plain resolver (host)
dig @127.0.0.1 -p 5301 ${req.name} ${req.qtype}`}</pre>

        <div className="section-title">PowerShell shortcuts (host)</div>
        <div className="hint">
          Use <code>nslookup</code> to target host-mapped ports (5300/5301).
          KSK/ZSK are DNSKEY records; check DNSKEY flags (257 = KSK, 256 = ZSK).
        </div>
        <pre className="output compact">{`# Validating resolver (host)
nslookup -port=5300 -type=A ${req.name} 127.0.0.1
nslookup -port=5300 -type=SOA example.test 127.0.0.1
nslookup -port=5300 -type=DNSKEY example.test 127.0.0.1
nslookup -port=5300 -type=DS example.test 127.0.0.1

# Plain resolver (host)
nslookup -port=5301 -type=A ${req.name} 127.0.0.1
nslookup -port=5301 -type=SOA example.test 127.0.0.1`}</pre>

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
            <div className="preset-title">Aggressive NSEC Proof (Cold)</div>
            <div className="preset-desc">
              Runs an OFF → ON aggressive-NSEC demo (NXDOMAIN batch) and stores
              a JSON/ZIP artifact with stats + sample dig output.
            </div>
            <div className="preset-note">
              This proof intentionally uses two non-existent names. NXDOMAIN is expected.
            </div>
            <div className="grid">
              <label>
                NXDOMAIN count
                <input
                  type="number"
                  min={10}
                  max={200}
                  value={proofCount}
                  onChange={(e) => setProofCount(Number(e.target.value))}
                  disabled={isBusy || proofBusy}
                />
              </label>
              <label>
                QPS
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={proofQps}
                  onChange={(e) => setProofQps(Number(e.target.value))}
                  disabled={isBusy || proofBusy}
                />
              </label>
              <label>
                Capture target
                <select
                  value={proofCaptureTarget}
                  onChange={(e) =>
                    setProofCaptureTarget(e.target.value as CaptureTarget)
                  }
                  disabled={isBusy || proofBusy}
                >
                  <option value="resolver">Resolver</option>
                  <option value="authoritative">Authoritative</option>
                </select>
              </label>
            </div>
            <div className="actions">
              <button
                onClick={runAggressiveNsecProofCold}
                disabled={isBusy || proofBusy || missingLabKey}
              >
                Run Proof (Cold)
              </button>
              <button
                onClick={() => proofCaptureFile && downloadCapture(proofCaptureFile)}
                disabled={
                  isBusy || proofBusy || missingLabKey || !proofCaptureFile
                }
              >
                Download PCAP
              </button>
              <button
                onClick={() =>
                  proofArtifactFile && downloadDemoArtifact(proofArtifactFile)
                }
                disabled={
                  isBusy || proofBusy || missingLabKey || !proofArtifactFile
                }
              >
                Download Artifact
              </button>
            </div>
          </div>
      </div>
      <div className="status">
        {proofStatus ||
          'Run the demo to capture traffic, compare stats, and download the artifact.'}
      </div>
      {proofArtifactFile && (
        <div className="actions">
          <button
            onClick={() => downloadDemoArtifact(proofArtifactFile)}
            disabled={isBusy || proofBusy || missingLabKey}
          >
            Download Artifact ({proofArtifactFile})
          </button>
        </div>
      )}
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

    {isSectionVisible('scenarios') && (
    <section className="card" id="scenarios">
      <div className="card-title">Scenarios + Table Templates</div>
      <div className="hint">
        Use the scenarios below to configure the lab, run tests, and record results
        directly into the comparison tables. Each scenario can be applied to prefill
        key UI settings; some require you to click Apply Controls or switch signing.
      </div>
      <div className="scenario-grid">
        {SCENARIOS.map((scenario) => (
          <div
            key={scenario.id}
            className={`scenario-card ${
              activeScenario === scenario.id ? 'active' : ''
            }`}
          >
            <div className="scenario-title">
              {scenario.label}
              {activeScenario === scenario.id && (
                <span className="scenario-pill">Applied</span>
              )}
            </div>
            <div className="scenario-desc">{scenario.detail}</div>
            <div className="scenario-note">{scenario.note}</div>
            <button
              type="button"
              onClick={() => runScenario(scenario.id)}
              disabled={scenarioBusy || isBusy || signingBusy || controlsBusy || missingLabKey}
            >
              Apply Scenario
            </button>
          </div>
        ))}
      </div>
      <div className="status">
        {scenarioStatus ||
          'Apply a scenario, run the relevant tests (Availability, Perf, Amplification), then fill the tables.'}
      </div>

      <div className="table-header">
        <div className="section-title">Wydajność i dostępność</div>
        <button type="button" onClick={exportPerfCsv}>
          Download CSV
        </button>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Konfiguracja</th>
              <th>Availability (%)</th>
              <th>Avg latency (ms)</th>
              <th>p50 (ms)</th>
              <th>p95 (ms)</th>
              <th>p99 (ms)</th>
              <th>QPS max</th>
              <th>Baseline QPS</th>
              <th>Error rate (%)</th>
              <th>Cache hit (%)</th>
              <th>NXDOMAIN (%)</th>
              <th>SERVFAIL (%)</th>
              <th>Upstream QPS</th>
              <th>Uwagi</th>
            </tr>
          </thead>
          <tbody>
            {SCENARIOS.map((scenario) => (
              <tr
                key={`perf-${scenario.id}`}
                className={activeScenario === scenario.id ? 'active' : ''}
              >
                <td>{scenario.label}</td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].availabilityPct}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'availabilityPct', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].avgLatency}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'avgLatency', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].p50}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'p50', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].p95}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'p95', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].p99}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'p99', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].qpsMax}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'qpsMax', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].baselineQps}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'baselineQps', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].errorRate}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'errorRate', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].cacheHit}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'cacheHit', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].nxdomain}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'nxdomain', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].servfail}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'servfail', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].upstreamQps}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'upstreamQps', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioPerfTable[scenario.id].notes}
                    onChange={(e) =>
                      updatePerfCell(scenario.id, 'notes', e.target.value)
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="table-header">
        <div className="section-title">Zasoby i podatność na nadużycia</div>
        <button type="button" onClick={exportResourceCsv}>
          Download CSV
        </button>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Konfiguracja</th>
              <th>CPU (%)</th>
              <th>RAM (MB)</th>
              <th>Mem (%)</th>
              <th>Rate-limited (%)</th>
              <th>Upstream QPS</th>
              <th>Amplifikacja UDP (B)</th>
              <th>Amplifikacja TCP (B)</th>
              <th>Avg UDP (B)</th>
              <th>Avg TCP (B)</th>
              <th>TC rate (%)</th>
              <th>TCP fallback (%)</th>
              <th>Uwagi</th>
            </tr>
          </thead>
          <tbody>
            {SCENARIOS.map((scenario) => (
              <tr
                key={`resource-${scenario.id}`}
                className={activeScenario === scenario.id ? 'active' : ''}
              >
                <td>{scenario.label}</td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].cpu}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'cpu', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].ram}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'ram', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].memPct}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'memPct', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].ratelimitedPct}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'ratelimitedPct', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].upstreamQps}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'upstreamQps', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].amplificationUdp}
                    onChange={(e) =>
                      updateResourceCell(
                        scenario.id,
                        'amplificationUdp',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].amplificationTcp}
                    onChange={(e) =>
                      updateResourceCell(
                        scenario.id,
                        'amplificationTcp',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].avgUdpSize}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'avgUdpSize', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].avgTcpSize}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'avgTcpSize', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].tcRate}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'tcRate', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].tcpRate}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'tcpRate', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioResourceTable[scenario.id].notes}
                    onChange={(e) =>
                      updateResourceCell(scenario.id, 'notes', e.target.value)
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="table-header">
        <div className="section-title">Bezpieczeństwo i poprawność</div>
        <button type="button" onClick={exportSecurityCsv}>
          Download CSV
        </button>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Konfiguracja</th>
              <th>DNSSEC OK (%)</th>
              <th>BOGUS (%)</th>
              <th>DoT success (%)</th>
              <th>DoH success (%)</th>
              <th>Cert errors (%)</th>
              <th>QNAME minimization</th>
              <th>ECS leakage</th>
              <th>Uwagi</th>
            </tr>
          </thead>
          <tbody>
            {SCENARIOS.map((scenario) => (
              <tr
                key={`security-${scenario.id}`}
                className={activeScenario === scenario.id ? 'active' : ''}
              >
                <td>{scenario.label}</td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].dnssecOkPct}
                    onChange={(e) =>
                      updateSecurityCell(scenario.id, 'dnssecOkPct', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].bogusPct}
                    onChange={(e) =>
                      updateSecurityCell(scenario.id, 'bogusPct', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].dotSuccessPct}
                    onChange={(e) =>
                      updateSecurityCell(
                        scenario.id,
                        'dotSuccessPct',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].dohSuccessPct}
                    onChange={(e) =>
                      updateSecurityCell(
                        scenario.id,
                        'dohSuccessPct',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].certErrorsPct}
                    onChange={(e) =>
                      updateSecurityCell(
                        scenario.id,
                        'certErrorsPct',
                        e.target.value
                      )
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].qnameMin}
                    onChange={(e) =>
                      updateSecurityCell(scenario.id, 'qnameMin', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].ecsLeakage}
                    onChange={(e) =>
                      updateSecurityCell(scenario.id, 'ecsLeakage', e.target.value)
                    }
                  />
                </td>
                <td>
                  <input
                    className="data-input"
                    value={scenarioSecurityTable[scenario.id].notes}
                    onChange={(e) =>
                      updateSecurityCell(scenario.id, 'notes', e.target.value)
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="section-title">5.6. Analiza efektywności</div>
      <textarea
        className="analysis-notes"
        value={analysisNotes}
        onChange={(e) => setAnalysisNotes(e.target.value)}
        placeholder="Wnioski, obserwacje, porównania scenariuszy..."
      />
    </section>
    )}

      {isSectionVisible('email') && (
      <section className="card" id="email">
        <div className="card-title">Mail Delivery Lab</div>
        <div className="hint">
          <div>
            Send test emails through the internal mail server and inspect DKIM/SPF
            results in the mail logs.
          </div>
          <div>
            Create a mailbox below (or run{' '}
            <code>docker compose exec mailserver setup email add user@example.test</code>).
          </div>
        </div>
        {missingLabKey && (
          <div className="alert">
            <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
            <code>.env.local</code> to match <code>LAB_API_KEY</code> from
            <code>docker-compose.yml</code>.
          </div>
        )}
        <div className="mail-layout">
          <div className="mail-stack">
            <div className="mail-card">
              <div className="mail-card-title">Mailbox setup</div>
              <div className="mail-card-sub">
                Create a mailbox in the mail server to receive messages.
              </div>
              <div className="grid">
                <label>
                  Mailbox address
                  <input
                    value={emailUserAddress}
                    onChange={(e) => setEmailUserAddress(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  Mailbox password
                  <input
                    type="password"
                    value={emailUserPassword}
                    onChange={(e) => setEmailUserPassword(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
              </div>
              <div className="actions">
                <button onClick={createMailbox} disabled={emailBusy || missingLabKey}>
                  Create Mailbox
                </button>
                <button
                  onClick={updateMailboxPassword}
                  disabled={emailBusy || missingLabKey}
                >
                  Update Password
                </button>
                <button
                  className="button-danger"
                  onClick={deleteMailbox}
                  disabled={emailBusy || missingLabKey}
                >
                  Delete Mailbox
                </button>
              </div>
              <pre className="output compact">
                {emailUserOutput || 'No mailbox actions yet.'}
              </pre>
            </div>

            <div className="mail-card">
              <div className="mail-card-title">Compose &amp; Send</div>
              <div className="grid">
                <label>
                  From
                  <input
                    value={emailFrom}
                    onChange={(e) => setEmailFrom(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  To
                  <input
                    value={emailTo}
                    onChange={(e) => setEmailTo(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  Server
                  <input
                    value={emailServer}
                    onChange={(e) => setEmailServer(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  Port
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={emailPort}
                    onChange={(e) => setEmailPort(Number(e.target.value))}
                    disabled={emailBusy}
                  />
                </label>
              </div>
              <div className="grid">
                <label>
                  TLS mode
                  <select
                    value={emailTlsMode}
                    onChange={(e) =>
                      setEmailTlsMode(e.target.value as EmailTlsMode)
                    }
                    disabled={emailBusy}
                  >
                    <option value="none">None (port 25)</option>
                    <option value="starttls">STARTTLS (port 587)</option>
                    <option value="tls">TLS (port 465)</option>
                  </select>
                </label>
                <label>
                  Subject
                  <input
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
              </div>
              <label>
                Body
                <textarea
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  disabled={emailBusy}
                />
              </label>
              <div className="toggle-row">
                <label className="pill-toggle">
                  <input
                    type="checkbox"
                    checked={emailUseAuth}
                    onChange={(e) => setEmailUseAuth(e.target.checked)}
                    disabled={emailBusy}
                  />
                  SMTP auth
                </label>
              </div>
              <div className="grid">
                <label>
                  Auth user
                  <input
                    value={emailAuthUser}
                    onChange={(e) => setEmailAuthUser(e.target.value)}
                    disabled={emailBusy || !emailUseAuth}
                  />
                </label>
                <label>
                  Auth password
                  <input
                    type="password"
                    value={emailAuthPass}
                    onChange={(e) => setEmailAuthPass(e.target.value)}
                    disabled={emailBusy || !emailUseAuth}
                  />
                </label>
                <label>
                  Auth type
                  <select
                    value={emailAuthType}
                    onChange={(e) => setEmailAuthType(e.target.value as EmailAuthType)}
                    disabled={emailBusy || !emailUseAuth}
                  >
                    <option value="AUTO">AUTO</option>
                    <option value="LOGIN">LOGIN</option>
                    <option value="PLAIN">PLAIN</option>
                    <option value="CRAM-MD5">CRAM-MD5</option>
                  </select>
                </label>
              </div>
              <div className="actions">
                <button onClick={sendEmail} disabled={emailBusy || missingLabKey}>
                  Send Email
                </button>
              </div>
              <pre className="output compact">
                {emailOutput || 'No send output yet.'}
              </pre>
            </div>
          </div>

          <div className="mail-stack">
            <div className="mail-card">
              <div className="mail-card-title">Inbox (IMAP)</div>
              <div className="mail-card-sub">
                List incoming messages and preview a selected mail.
              </div>
              <div className="grid">
                <label>
                  IMAP user
                  <input
                    value={emailImapUser}
                    onChange={(e) => setEmailImapUser(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  IMAP mailbox
                  <input
                    value={emailImapMailbox}
                    onChange={(e) => setEmailImapMailbox(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  Message limit
                  <input
                    type="number"
                    min={5}
                    max={200}
                    value={emailImapLimit}
                    onChange={(e) => setEmailImapLimit(Number(e.target.value))}
                    disabled={emailBusy}
                  />
                </label>
              </div>
              <div className="actions">
                <button
                  onClick={loadInboxList}
                  disabled={emailBusy || missingLabKey}
                >
                  List Messages
                </button>
                <button
                  onClick={() => viewInboxMessage(null)}
                  disabled={
                    emailBusy || missingLabKey || !emailInboxSelected
                  }
                >
                  View Selected
                </button>
              </div>
              <div className="inbox-list">
                {emailInboxMessages.length > 0 ? (
                  emailInboxMessages.map((msg) => {
                    const isActive =
                      emailInboxSelected?.id === msg.id &&
                      emailInboxSelected?.source === msg.source;
                    return (
                      <button
                        type="button"
                        key={`${msg.source}:${msg.id}`}
                        className={`inbox-item ${isActive ? 'active' : ''}`}
                        onClick={() => {
                          setEmailInboxSelected(msg);
                          viewInboxMessage(msg);
                        }}
                        disabled={emailBusy}
                      >
                        <div className="inbox-item-subject">
                          {msg.subject || '(no subject)'}
                        </div>
                        <div className="inbox-item-meta">
                          <span>{msg.from_addr || 'unknown sender'}</span>
                          <span>{msg.date || 'unknown date'}</span>
                        </div>
                      </button>
                    );
                  })
                ) : (
                  <div className="inbox-empty">No messages loaded yet.</div>
                )}
              </div>
              <div className="inbox-viewer">
                <div className="inbox-viewer-meta">
                  {emailInboxSelected ? (
                    <>
                      <div>
                        <strong>Subject:</strong>{' '}
                        {emailInboxSelected.subject || '(no subject)'}
                      </div>
                      <div>
                        <strong>From:</strong>{' '}
                        {emailInboxSelected.from_addr || 'unknown sender'}
                      </div>
                      <div>
                        <strong>To:</strong>{' '}
                        {emailInboxSelected.to_addr || 'unknown recipient'}
                      </div>
                      <div>
                        <strong>Date:</strong>{' '}
                        {emailInboxSelected.date || 'unknown date'}
                      </div>
                    </>
                  ) : (
                    <div>No message selected.</div>
                  )}
                </div>
                <pre className="output compact">
                  {emailInboxContent || 'Select a message to view.'}
                </pre>
              </div>
              {emailInboxRaw && (
                <pre className="output compact">{emailInboxRaw}</pre>
              )}
            </div>

            <div className="mail-card">
              <div className="mail-card-title">Outbox / Logs</div>
              <div className="mail-card-sub">
                Tail delivery logs for DKIM/SPF and SMTP status.
              </div>
              <div className="grid">
                <label>
                  Log filter
                  <input
                    value={emailLogFilter}
                    onChange={(e) => setEmailLogFilter(e.target.value)}
                    disabled={emailBusy}
                  />
                </label>
                <label>
                  Log tail (lines)
                  <input
                    type="number"
                    min={10}
                    max={1000}
                    value={emailLogTail}
                    onChange={(e) => setEmailLogTail(Number(e.target.value))}
                    disabled={emailBusy}
                  />
                </label>
              </div>
              <div className="actions">
                <button
                  onClick={() => loadEmailLogs()}
                  disabled={emailBusy || missingLabKey}
                >
                  Load Logs
                </button>
                <button
                  onClick={() => {
                    setEmailLogFilter('postfix');
                    loadEmailLogs('postfix');
                  }}
                  disabled={emailBusy || missingLabKey}
                >
                  Load Postfix
                </button>
                <button
                  onClick={() => {
                    setEmailLogFilter('dkim');
                    loadEmailLogs('dkim');
                  }}
                  disabled={emailBusy || missingLabKey}
                >
                  Load DKIM
                </button>
              </div>
              <div className="email-log-meta">
                {emailLogFile ? `File: ${emailLogFile}` : 'No log loaded.'}
              </div>
              <pre className="output compact">{emailLog || 'No log output yet.'}</pre>
            </div>
          </div>
        </div>
        <div className="status">{emailStatus || 'Ready.'}</div>
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
          <button onClick={() => runBaseline()} disabled={baselineBusy || missingLabKey}>
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
          <button onClick={() => runDnsperf()} disabled={dnsperfBusy || missingLabKey}>
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

        <div className="section-title">Traffic generator (controlled QPS)</div>
        <div className="hint">
          <div>
            Runs a lightweight Python generator in a throwaway container. Build the
            image once on the host: <code>docker build -t dns-traffic-gen ./tools/traffic_gen</code>.
          </div>
          <div>
            Target: <code>{trafficResolver}</code> via{' '}
            <code>{resolverIpByClient[trafficResolver][trafficProfile]}</code>
          </div>
        </div>
        <div className="grid">
          <label>
            Profile
            <select
              value={trafficProfile}
              onChange={(e) => setTrafficProfile(e.target.value as Client)}
              disabled={trafficBusy}
            >
              <option value="trusted">trusted</option>
              <option value="untrusted">untrusted</option>
              <option value="mgmt">mgmt</option>
            </select>
          </label>
          <label>
            Resolver
            <select
              value={trafficResolver}
              onChange={(e) => setTrafficResolver(e.target.value as ResolverKind)}
              disabled={trafficBusy}
            >
              <option value="valid">valid</option>
              <option value="plain">plain</option>
            </select>
          </label>
          <label>
            Zone
            <input
              value={trafficZone}
              onChange={(e) => setTrafficZone(e.target.value)}
              disabled={trafficBusy}
            />
          </label>
          <label>
            QTYPE
            <select
              value={trafficQtype}
              onChange={(e) => setTrafficQtype(e.target.value)}
              disabled={trafficBusy}
            >
              {trafficQtypeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </label>
          <label>
            Mode
            <select
              value={trafficMode}
              onChange={(e) => setTrafficMode(e.target.value as TrafficMode)}
              disabled={trafficBusy}
            >
              {trafficModeOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            NXDOMAIN ratio
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={trafficRatio}
              onChange={(e) => setTrafficRatio(Number(e.target.value))}
              disabled={trafficBusy || trafficMode !== 'mix'}
            />
          </label>
          <label>
            Duration (s)
            <input
              type="number"
              min={1}
              max={300}
              value={trafficDuration}
              onChange={(e) => setTrafficDuration(Number(e.target.value))}
              disabled={trafficBusy}
            />
          </label>
          <label>
            QPS
            <input
              type="number"
              min={1}
              max={500}
              value={trafficQps}
              onChange={(e) => setTrafficQps(Number(e.target.value))}
              disabled={trafficBusy}
            />
          </label>
          <label>
            Timeout (s)
            <input
              type="number"
              min={0.2}
              max={10}
              step={0.1}
              value={trafficTimeout}
              onChange={(e) => setTrafficTimeout(Number(e.target.value))}
              disabled={trafficBusy}
            />
          </label>
          <label>
            Max inflight
            <input
              type="number"
              min={1}
              max={800}
              value={trafficMaxInflight}
              onChange={(e) => setTrafficMaxInflight(Number(e.target.value))}
              disabled={trafficBusy}
            />
          </label>
        </div>
        <div className="actions">
          <button onClick={runTrafficGen} disabled={trafficBusy || missingLabKey}>
            Run traffic
          </button>
        </div>
        <div className="status">{trafficStatus || 'Ready.'}</div>
        <pre className="output">
          {trafficOutput || 'No traffic output yet.'}
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
          <button onClick={() => applyControls()} disabled={controlsBusy || missingLabKey}>
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
          <button
            onClick={() => runAmplificationTest()}
            disabled={ampBusy || missingLabKey}
          >
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
