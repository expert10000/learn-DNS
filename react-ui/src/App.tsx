import { useEffect, useMemo, useRef, useState } from 'react';
import './index.css';

type Client = 'trusted' | 'untrusted' | 'mgmt';
type Backend = 'client' | 'lab_api';

type ResolverKind = 'valid' | 'plain';

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

type OutputView = {
  ok: boolean;
  command: string;
  text: string;
};

type ConfigGroup = 'authoritative' | 'resolver';
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

const DEFAULT_REQUEST: DigRequest = {
  client: 'trusted',
  resolver: 'valid',
  name: 'www.example.test',
  qtype: 'A',
  dnssec: true,
  trace: false,
  short: false,
};

const API_BASE = (import.meta.env.VITE_API_BASE || '/api').replace(/\/+$/, '');
const LAB_API_BASE = (import.meta.env.VITE_LAB_API_BASE || '/lab-api').replace(
  /\/+$/,
  ''
);
const LAB_API_KEY = import.meta.env.VITE_LAB_API_KEY || '';

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

function indicatorClass(value?: boolean): string {
  if (value === undefined) {
    return 'unknown';
  }
  return value ? 'enabled' : 'disabled';
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
  const [output, setOutput] = useState<OutputView | null>(null);
  const [status, setStatus] = useState<string>('');
  const outputRef = useRef<HTMLDivElement | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [configFiles, setConfigFiles] = useState<ConfigFile[]>([]);
  const [configPath, setConfigPath] = useState<string>('');
  const [configContent, setConfigContent] = useState<string>('');
  const [configStatus, setConfigStatus] = useState<string>('');
  const [configGroup, setConfigGroup] = useState<ConfigGroup>('authoritative');
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
  const [proofBusy, setProofBusy] = useState(false);
  const [proofStatus, setProofStatus] = useState('');
  const [proofOutput, setProofOutput] = useState('');
  const [proofCaptureFile, setProofCaptureFile] = useState('');
  const [proofColdCache, setProofColdCache] = useState(true);
  const [proofFlushCache, setProofFlushCache] = useState(false);
  const [privacyBusy, setPrivacyBusy] = useState(false);
  const [privacyStatus, setPrivacyStatus] = useState('');
  const [privacyOutput, setPrivacyOutput] = useState('');
  const [indicators, setIndicators] = useState<IndicatorState>({
    loading: false,
    message: 'Not loaded.',
  });

  const clientBase = `${API_BASE}/${req.client}`;
  const missingLabKey = useMemo(() => LAB_API_KEY.trim().length === 0, []);
  const labHeaders: Record<string, string> = {};
  if (LAB_API_KEY.trim()) {
    labHeaders['x-api-key'] = LAB_API_KEY;
  }
  const groupPrefix = configGroup === 'authoritative' ? 'bind/' : 'unbound/';
  const groupedFiles = configFiles.filter((f) => f.path.startsWith(groupPrefix));
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

  useEffect(() => {
    if (groupedFiles.length === 0) {
      return;
    }
    if (!configPath || !configPath.startsWith(groupPrefix)) {
      setConfigPath(groupedFiles[0].path);
    }
  }, [groupPrefix, groupedFiles, configPath]);

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
        { ...body, server }
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
      setStatus((err as Error).message);
      setOutput(null);
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
        `Aggressive NSEC demo completed. Q1: ${formatStatusLabel(
          first.rcode,
          first.ad
        )}, Q2: ${formatStatusLabel(second.rcode, second.ad)}`
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
        summaryText = [
          '# Capture summary',
          `file: ${summary.file}`,
          `total DNS packets: ${summary.total_packets}`,
          `upstream queries (resolver -> authoritative): ${summary.upstream_queries}`,
        ].join('\n');
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
      setProofStatus((err as Error).message);
      setProofOutput('');
    } finally {
      setProofBusy(false);
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
        }>(`${clientBase}/health`);
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
      setStatus((err as Error).message);
      setOutput(null);
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
      const firstInGroup = result.files.find((f) =>
        f.path.startsWith(groupPrefix)
      );
      if (firstInGroup) {
        setConfigPath(firstInGroup.path);
      }
      setConfigStatus(`Loaded ${result.files.length} files.`);
    } catch (err) {
      setConfigStatus((err as Error).message);
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
      setConfigStatus((err as Error).message);
      setConfigContent('');
    } finally {
      setIsBusy(false);
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
    try {
      const result = await postJson<SigningSwitchResponse>(
        `${LAB_API_BASE}/signing/switch`,
        { mode } satisfies SigningSwitchRequest,
        labHeaders
      );
      const combined = result.steps
        .map((step) => {
          const stdout = step.stdout?.trim();
          const stderr = step.stderr?.trim();
          const details = [stdout, stderr].filter(Boolean).join('\n');
          return [`# ${step.step}`, step.command, details].filter(Boolean).join('\n');
        })
        .join('\n\n');
      setSigningOutput(combined || 'No output.');
      setSigningStatus(
        result.ok
          ? `Switched to ${mode.toUpperCase()}`
          : `Switch failed (mode ${mode.toUpperCase()})`
      );
      await loadIndicators();
    } catch (err) {
      setSigningStatus((err as Error).message);
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
      setPrivacyStatus((err as Error).message);
    } finally {
      setPrivacyBusy(false);
    }
  };

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>DNS Security Lab</h1>
          <p>React UI on Win11, talking to per-client APIs and the lab API.</p>
        </div>
        <div className="pill">
          API: {backend === 'client' ? clientBase : LAB_API_BASE} • Resolver: {resolverLabel}
        </div>
      </header>

      {backend === 'lab_api' && missingLabKey && (
        <div className="alert">
          <strong>Missing Lab API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
          <code>.env.local</code> to match <code>LAB_API_KEY</code> from
          <code>docker-compose.yml</code>.
        </div>
      )}

      <section className="card">
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

      <section className="card" ref={outputRef}>
        <div className="card-title">Output</div>
        <pre className="output">
          {output ? `${output.command}\n\n${output.text}` : 'No output yet.'}
        </pre>
      </section>

      <section className="card">
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
          <button onClick={loadIndicators} disabled={isBusy || missingLabKey}>
            Refresh Indicators
          </button>
        </div>
        <div className="status">
          {signingStatus ||
            'Use the switch buttons to change between inline NSEC and offline NSEC3.'}
        </div>
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

    <section className="card">
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

      <section className="card">
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

        <div className="config-list">
          {groupedFiles.length === 0 && (
            <div className="config-empty">No files loaded yet.</div>
          )}
          {groupedFiles.map((f) => (
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

        <div className="actions">
          <button onClick={loadConfigList} disabled={isBusy}>
            Load Files
          </button>
          <button onClick={viewConfigFile} disabled={isBusy || !configPath}>
            View File
          </button>
        </div>

        <div className="status">{configStatus || 'Ready.'}</div>
        <pre className="output">
          {configContent || 'No config loaded.'}
        </pre>
      </section>

      <section className="card">
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
    </div>
  );
}
