import { useEffect, useMemo, useState } from 'react';
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
  childDetail?: string;
  parentDetail?: string;
  aggressiveDetail?: string;
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

function parseNsec3FromZone(content: string) {
  const hasRecord = content
    .split('\n')
    .some(
      (line) =>
        line.trim().length > 0 &&
        !line.trim().startsWith(';') &&
        /\bNSEC3PARAM\b/i.test(line)
    );
  return {
    enabled: hasRecord,
    detail: `NSEC3PARAM record: ${hasRecord ? 'present' : 'missing'}`,
  };
}

function parseAggressiveNsec(content: string) {
  const match = content.match(/aggressive-nsec\s*:\s*(yes|no)/i);
  if (!match) {
    return { enabled: false, detail: 'setting not found' };
  }
  const enabled = match[1].toLowerCase() === 'yes';
  return { enabled, detail: `aggressive-nsec: ${match[1].toLowerCase()}` };
}

export default function App() {
  const [req, setReq] = useState<DigRequest>(DEFAULT_REQUEST);
  const [backend, setBackend] = useState<Backend>('client');
  const [output, setOutput] = useState<OutputView | null>(null);
  const [status, setStatus] = useState<string>('');
  const [isBusy, setIsBusy] = useState(false);
  const [configFiles, setConfigFiles] = useState<ConfigFile[]>([]);
  const [configPath, setConfigPath] = useState<string>('');
  const [configContent, setConfigContent] = useState<string>('');
  const [configStatus, setConfigStatus] = useState<string>('');
  const [configGroup, setConfigGroup] = useState<ConfigGroup>('authoritative');
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
      setIsBusy(false);
    }
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
      setIsBusy(false);
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
    let childDetail = '';
    let parentDetail = '';
    let aggressiveDetail = '';

    try {
      const child = await getJson<ConfigFileResponse>(
        `${LAB_API_BASE}/config/file?path=${encodeURIComponent(
          'bind/zones/db.example.test'
        )}`,
        labHeaders
      );
      const parsed = parseNsec3FromZone(child.content);
      childEnabled = parsed.enabled;
      childDetail = parsed.detail;
    } catch (err) {
      childEnabled = undefined;
      childDetail = (err as Error).message;
    }

    try {
      const parent = await getJson<ConfigFileResponse>(
        `${LAB_API_BASE}/config/file?path=${encodeURIComponent(
          'bind_parent/zones/db.test'
        )}`,
        labHeaders
      );
      const parsed = parseNsec3FromZone(parent.content);
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
    } catch (err) {
      aggressiveEnabled = undefined;
      aggressiveDetail = (err as Error).message;
    }

    setIndicators({
      loading: false,
      message: 'Indicators updated.',
      nsec3Child: childEnabled,
      nsec3Parent: parentEnabled,
      aggressiveNsec: aggressiveEnabled,
      childDetail,
      parentDetail,
      aggressiveDetail,
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

      <section className="card">
        <div className="card-title">Output</div>
        <pre className="output">
          {output ? `${output.command}\n\n${output.text}` : 'No output yet.'}
        </pre>
      </section>

      <section className="card">
        <div className="card-title">NSEC3 / Aggressive NSEC</div>
        <div className="hint">
          <div>
            <strong>NSEC3 signing:</strong> enabled on <code>test.</code> and{' '}
            <code>example.test</code> via <code>NSEC3PARAM</code> records in the
            zone files.
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
        </div>
        <div className="indicator-meta">
          <div>Child: {indicators.childDetail || 'not checked'}</div>
          <div>Parent: {indicators.parentDetail || 'not checked'}</div>
          <div>Aggressive: {indicators.aggressiveDetail || 'not checked'}</div>
          <div>
            Status: {indicators.message}{' '}
            {indicators.updatedAt ? `(${indicators.updatedAt})` : ''}
          </div>
        </div>
        <div className="actions">
          <button onClick={loadIndicators} disabled={isBusy || missingLabKey}>
            Refresh Indicators
          </button>
        </div>
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
            </div>
          </div>
          <div className="preset">
            <div className="preset-title">Aggressive NSEC Demo</div>
            <div className="preset-desc">
              Runs two NXDOMAIN queries; the second should be synthesized from cached
              NSEC3.
            </div>
            <div className="actions">
              <button onClick={runAggressiveNsecDemo} disabled={isBusy}>
                Run Demo
              </button>
            </div>
          </div>
        </div>
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
