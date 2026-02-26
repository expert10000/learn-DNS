import { useEffect, useMemo, useState } from 'react';
import './index.css';

type Client = 'trusted' | 'untrusted' | 'mgmt';
type Backend = 'client' | 'lab_api';

type DigRequest = {
  client: Client;
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

  const clientBase = `${API_BASE}/${req.client}`;
  const missingLabKey = useMemo(() => LAB_API_KEY.trim().length === 0, []);
  const labHeaders: Record<string, string> = {};
  if (LAB_API_KEY.trim()) {
    labHeaders['x-api-key'] = LAB_API_KEY;
  }
  const groupPrefix = configGroup === 'authoritative' ? 'bind/' : 'unbound/';
  const groupedFiles = configFiles.filter((f) => f.path.startsWith(groupPrefix));

  useEffect(() => {
    if (groupedFiles.length === 0) {
      return;
    }
    if (!configPath || !configPath.startsWith(groupPrefix)) {
      setConfigPath(groupedFiles[0].path);
    }
  }, [groupPrefix, groupedFiles, configPath]);

  const runDig = async () => {
    setIsBusy(true);
    setStatus('Running dig...');
    try {
      const { client, ...body } = req;
      if (backend === 'client') {
        const result = await postJson<ClientDigResponse>(
          `${clientBase}/dig`,
          body
        );
        setOutput({
          ok: result.ok,
          command: result.cmd.join(' '),
          text: result.output,
        });
        setStatus(result.ok ? `OK (AD=${result.ad ? 'yes' : 'no'})` : 'Completed');
      } else {
        const result = await postJson<LabDigResponse>(
          `${LAB_API_BASE}/dig`,
          { profile: client, ...body },
          labHeaders
        );
        const text = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ''}`;
        setOutput({ ok: result.ok, command: result.command, text });
        setStatus(result.ok ? 'OK' : 'Completed with errors');
      }
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
        <div className="pill">API: {backend === 'client' ? clientBase : LAB_API_BASE}</div>
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
              {['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CNAME', 'DNSKEY', 'DS'].map(
                (t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                )
              )}
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
