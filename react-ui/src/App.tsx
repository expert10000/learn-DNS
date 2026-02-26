import { useMemo, useState } from 'react';
import './index.css';

type Profile = 'trusted' | 'untrusted' | 'mgmt';

type DigRequest = {
  profile: Profile;
  name: string;
  qtype: string;
  dnssec: boolean;
  trace: boolean;
  short: boolean;
};

type CmdResponse = {
  ok: boolean;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
};

const DEFAULT_REQUEST: DigRequest = {
  profile: 'trusted',
  name: 'www.example.test',
  qtype: 'A',
  dnssec: true,
  trace: false,
  short: false,
};

const API_KEY = import.meta.env.VITE_LAB_API_KEY || '';
const API_BASE = import.meta.env.VITE_API_BASE || '/api';

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'x-api-key': API_KEY,
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

export default function App() {
  const [req, setReq] = useState<DigRequest>(DEFAULT_REQUEST);
  const [output, setOutput] = useState<CmdResponse | null>(null);
  const [status, setStatus] = useState<string>('');
  const [isBusy, setIsBusy] = useState(false);

  const missingKey = useMemo(() => API_KEY.trim().length === 0, []);

  const runDig = async () => {
    setIsBusy(true);
    setStatus('Running dig...');
    try {
      const result = await postJson<CmdResponse>('/dig', req);
      setOutput(result);
      setStatus(result.ok ? 'OK' : 'Completed with errors');
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
      const result = await getJson<{ ok: boolean }>('/health');
      setStatus(result.ok ? 'API healthy' : 'API unhealthy');
    } catch (err) {
      setStatus((err as Error).message);
    } finally {
      setIsBusy(false);
    }
  };

  const viewLogs = async (service: 'bind' | 'unbound') => {
    setIsBusy(true);
    setStatus(`Fetching ${service} logs...`);
    try {
      const result = await getJson<CmdResponse>(`/logs/${service}?tail=200`);
      setOutput(result);
      setStatus(result.ok ? 'Logs fetched' : 'Log fetch failed');
    } catch (err) {
      setStatus((err as Error).message);
      setOutput(null);
    } finally {
      setIsBusy(false);
    }
  };

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>DNS Security Lab</h1>
          <p>React UI on Win11, talking to the lab API.</p>
        </div>
        <div className="pill">API: {API_BASE}</div>
      </header>

      {missingKey && (
        <div className="alert">
          <strong>Missing API key.</strong> Set <code>VITE_LAB_API_KEY</code> in
          <code>.env.local</code> to match <code>LAB_API_KEY</code> from
          <code>docker-compose.yml</code>.
        </div>
      )}

      <section className="card">
        <div className="card-title">Dig Request</div>
        <div className="grid">
          <label>
            Profile
            <select
              value={req.profile}
              onChange={(e) =>
                setReq({ ...req, profile: e.target.value as Profile })
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
          {output
            ? `${output.command}\n\n${output.stdout}${output.stderr ? `\n${output.stderr}` : ''}`
            : 'No output yet.'}
        </pre>
      </section>
    </div>
  );
}
