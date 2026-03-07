import os
import re
import json
import math
import subprocess
import http.client
import secrets
import socket
import ssl
import struct
import time
import threading
import base64
import shlex
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlencode, urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="dns-security-lab API", version="1.0")

API_KEY = os.getenv("LAB_API_KEY", "")
ALLOW_DOCKER = os.getenv("LAB_API_ALLOW_DOCKER", "0").lower() in ("1", "true", "yes")
RATE_LIMIT_PER_MIN = int(os.getenv("LAB_API_RATE_LIMIT_PER_MIN", "120"))
RATE_LIMIT_WINDOW_S = int(os.getenv("LAB_API_RATE_LIMIT_WINDOW_S", "60"))
AUDIT_LOG_PATH = os.getenv("LAB_API_AUDIT_LOG", "/var/log/lab_api/audit.log")
AUTH_AGENT_URL = os.getenv("AUTH_AGENT_URL", "")
RESOLVER_AGENT_URL = os.getenv("RESOLVER_AGENT_URL", "")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")

_rate_lock = threading.Lock()
_rate_hits: dict[str, list[float]] = {}

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _agent_request(
    base_url: str, path: str, params: Optional[dict[str, str | int]] = None
) -> dict:
    if not base_url:
        raise HTTPException(status_code=503, detail="Agent URL not configured")
    url = urlparse(base_url)
    host = url.hostname
    port = url.port or 80
    if not host:
        raise HTTPException(status_code=500, detail="Invalid agent URL")
    query = f"{path}?{urlencode(params)}" if params else path
    headers = {}
    if AGENT_API_KEY:
        headers["x-agent-key"] = AGENT_API_KEY
    try:
        conn = http.client.HTTPConnection(host, port, timeout=4)
        conn.request("GET", query, headers=headers)
        res = conn.getresponse()
        data = res.read()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Agent error: {exc}") from exc
    if res.status >= 400:
        detail = data.decode("utf-8", errors="replace")
        raise HTTPException(status_code=res.status, detail=detail)
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail="Agent returned invalid JSON") from exc

def _agent_for_config(path: str) -> Optional[str]:
    if path.startswith("unbound/"):
        return RESOLVER_AGENT_URL
    if path.startswith("bind/") or path.startswith("bind_parent/"):
        return AUTH_AGENT_URL
    return None

def _collect_nodes() -> tuple[list["NodeInfo"], dict[str, str]]:
    nodes: list[NodeInfo] = []
    errors: dict[str, str] = {}
    for label, url in (("authoritative", AUTH_AGENT_URL), ("resolver", RESOLVER_AGENT_URL)):
        if not url:
            errors[label] = "Agent URL not configured"
            continue
        try:
            data = _agent_request(url, "/status")
        except HTTPException as exc:
            errors[label] = str(exc.detail)
            continue
        agent_meta = data.get("agent") or {}
        agent_role = data.get("role") or label
        agent_version = agent_meta.get("version")
        agent_hostname = agent_meta.get("hostname")
        for check in data.get("checks", []) or []:
            try:
                port = int(check.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            name = str(check.get("name", "")) or agent_role
            nodes.append(
                NodeInfo(
                    name=name,
                    role=name,
                    ip=str(check.get("host", "")),
                    port=port,
                    ok=bool(check.get("ok", False)),
                    latency_ms=check.get("latency_ms"),
                    agent_role=agent_role,
                    agent_version=agent_version,
                    agent_hostname=agent_hostname,
                )
            )
    return nodes, errors

def _tail_file(path: Path, lines: int) -> str:
    if lines <= 0:
        return ""
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            size = end
            block = 1024
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                read_size = block if size >= block else size
                f.seek(size - read_size)
                data = f.read(read_size) + data
                size -= read_size
            return b"\n".join(data.splitlines()[-lines:]).decode(
                "utf-8", errors="replace"
            )
    except Exception:
        return ""

def _latest_log_file(base: Path) -> Optional[Path]:
    if not base.exists():
        return None
    candidates = sorted(
        [p for p in base.rglob("*") if p.is_file()],
        key=lambda p: p.stat().st_size,
        reverse=True,
    )
    return candidates[0] if candidates else None

def _client_ip(request: Request) -> str:
    return (
        request.headers.get("x-real-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

def _rate_limit_key(request: Request) -> str:
    return _client_ip(request)

def _rate_limit_check(request: Request) -> Optional[JSONResponse]:
    if RATE_LIMIT_PER_MIN <= 0:
        return None
    path = request.url.path
    if path in ("/health", "/openapi.json") or path.startswith("/docs"):
        return None
    now = time.time()
    key = _rate_limit_key(request)
    with _rate_lock:
        hits = _rate_hits.get(key, [])
        cutoff = now - RATE_LIMIT_WINDOW_S
        hits = [ts for ts in hits if ts >= cutoff]
        if len(hits) >= RATE_LIMIT_PER_MIN:
            _rate_hits[key] = hits
            return JSONResponse(
                status_code=429, content={"detail": "Rate limit exceeded"}
            )
        hits.append(now)
        _rate_hits[key] = hits
    return None

def audit_log(request: Request, action: str, detail: dict):
    try:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "ip": _client_ip(request),
            "path": request.url.path,
            "action": action,
            "detail": detail,
        }
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    blocked = _rate_limit_check(request)
    if blocked:
        return blocked
    return await call_next(request)

# Choose resolver IP by "segment" so Unbound ACLs behave like real clients
RESOLVER_BY_PROFILE = {
    "valid": {
        "trusted": "172.32.0.20",    # client_net
        "untrusted": "172.33.0.20",  # untrusted_net
        "mgmt": "172.30.0.20",       # mgmt_net
    },
    "plain": {
        "trusted": "172.32.0.21",    # client_net
        "untrusted": "172.33.0.21",  # untrusted_net
        "mgmt": "172.30.0.21",       # mgmt_net
    },
}

NAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?$"
)

CONFIG_ROOT = Path("/config")
CONFIG_DIRS = {
    "bind": CONFIG_ROOT / "bind",
    "bind_parent": CONFIG_ROOT / "bind_parent",
    "unbound": CONFIG_ROOT / "unbound",
}
MAX_CONFIG_BYTES = 200_000

CAPTURE_DIR = Path("/captures")
DEMO_DIR = CAPTURE_DIR / "demo"
CAPTURE_TARGETS = {
    "resolver": os.getenv("CAPTURE_RESOLVER_CONTAINER", "dns_resolver"),
    "authoritative": os.getenv(
        "CAPTURE_AUTHORITATIVE_CONTAINER", "dns_authoritative_child"
    ),
}
CAPTURE_FILTERS = {
    "dns": "port 53",
    "dns+dot": "port 53 or port 853",
    "all": "",
}

AUTH_PARENT_IP = os.getenv("AUTH_PARENT_IP", "172.31.0.10")
AUTH_CHILD_IP = os.getenv("AUTH_CHILD_IP", "172.31.0.11")
RESOLVER_CORE_IP = os.getenv("RESOLVER_CORE_IP", "172.31.0.20")
DOT_RESOLVER_IP = os.getenv("DOT_RESOLVER_IP", "172.30.0.20")
DOT_RESOLVER_PORT = int(os.getenv("DOT_RESOLVER_PORT", "853"))
DOH_PROXY_HOST = os.getenv("DOH_PROXY_HOST", "172.30.0.80")
DOH_PROXY_PORT = int(os.getenv("DOH_PROXY_PORT", "443"))
DOH_PROXY_PATH = os.getenv("DOH_PROXY_PATH", "/dns-query")

SIGNING_SWITCHER_CONTAINER = os.getenv(
    "SIGNING_SWITCHER_CONTAINER", "dns_signing_switcher"
)
SIGNING_PARENT_CONTAINER = os.getenv(
    "SIGNING_PARENT_CONTAINER", "dns_authoritative_parent"
)
SIGNING_CHILD_CONTAINER = os.getenv(
    "SIGNING_CHILD_CONTAINER", "dns_authoritative_child"
)
RESOLVER_CONTAINER = os.getenv("SIGNING_RESOLVER_CONTAINER", "dns_resolver")
DS_RECOMPUTE_CONTAINER = os.getenv("DS_RECOMPUTE_CONTAINER", "dns_ds_recompute")
ANCHOR_EXPORT_CONTAINER = os.getenv("ANCHOR_EXPORT_CONTAINER", "dns_anchor_export")
RESOLVER_PLAIN_CONTAINER = os.getenv(
    "RESOLVER_PLAIN_CONTAINER", "dns_resolver_plain"
)
DS_RECOMPUTE_CONTAINER = os.getenv("DS_RECOMPUTE_CONTAINER", "dns_ds_recompute")
ANCHOR_EXPORT_CONTAINER = os.getenv(
    "ANCHOR_EXPORT_CONTAINER", "dns_anchor_export"
)
CLIENT_TRUSTED_CONTAINER = os.getenv("CLIENT_TRUSTED_CONTAINER", "dns_client")
CLIENT_UNTRUSTED_CONTAINER = os.getenv("CLIENT_UNTRUSTED_CONTAINER", "dns_untrusted")
CLIENT_MGMT_CONTAINER = os.getenv("CLIENT_MGMT_CONTAINER", "dns_mgmt_client")
TOOLBOX_CONTAINER = os.getenv("TOOLBOX_CONTAINER", "dns_toolbox")
PERF_TOOLS_CONTAINER = os.getenv("PERF_TOOLS_CONTAINER", "dns_perf_tools")
MAILSERVER_CONTAINER = os.getenv("MAILSERVER_CONTAINER", "dns_mailserver")
SWAKS_CONTAINER = os.getenv("SWAKS_CONTAINER", "dns_swaks")

CLIENT_CONTAINER_BY_PROFILE = {
    "trusted": CLIENT_TRUSTED_CONTAINER,
    "untrusted": CLIENT_UNTRUSTED_CONTAINER,
    "mgmt": CLIENT_MGMT_CONTAINER,
}

MAX_LOAD_COUNT = 600
MAX_LOAD_QPS = 100
MAX_FLOOD_QPS = 200
MAX_FLOOD_OUTSTANDING = 500
MAX_FLOOD_STEP_SECONDS = 120
MAX_FLOOD_TOTAL_SECONDS = 600
MAX_FLOOD_STEPS = 20
MAX_RRL_COUNT = 800
MAX_PROBE_COUNT = 30
MAX_AMP_COUNT = 40
MAX_MIX_COUNT = 500
MAX_DNSPERF_QPS = 200
MAX_DNSPERF_DURATION = 300
MAX_DNSPERF_QUERIES = 5000
MAX_DNSPERF_THREADS = 8
MAX_DNSPERF_CLIENTS = 50
MAX_RESPERF_MAX_QPS = 300
MAX_RESPERF_RAMP_QPS = 50
MAX_RESPERF_CLIENTS = 50
MAX_RESPERF_QUERIES = 2000
DEFAULT_PERF_QUERY_FILE = "/work/tests/perf/queries.txt"
MAX_PERF_QUERY_LINES = 1000
MAX_PERF_QUERY_CHARS = 20000
MAX_EMAIL_BODY_CHARS = 10000
MAX_EMAIL_SUBJECT_CHARS = 200
MAX_MAIL_LOG_LINES = 1000
MAX_MAIL_LOG_GREP_CHARS = 120
MAX_IMAP_LINES = 500
MAX_DEMO_NX_COUNT = 200
MAX_DEMO_QPS = 200
DEFAULT_DEMO_NX_COUNT = 100
DEFAULT_DEMO_QPS = 50

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
MAILBOX_RE = re.compile(r"^[A-Za-z0-9._-]+$")

class DigRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    name: str = Field(..., examples=["example.org"])
    qtype: Literal[
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "DNSKEY",
        "MX",
        "NS",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "RRSIG",
        "SOA",
        "SRV",
        "TXT",
        "ANY",
    ] = "A"
    dnssec: bool = False
    trace: bool = False
    short: bool = False

class CmdResponse(BaseModel):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class ConfigFile(BaseModel):
    path: str
    size: int

class ConfigListResponse(BaseModel):
    ok: bool
    files: list[ConfigFile]

class ConfigFileResponse(BaseModel):
    ok: bool
    path: str
    size: int
    truncated: bool
    content: str

class AgentAggregateResponse(BaseModel):
    ok: bool
    agents: dict

class NodeInfo(BaseModel):
    name: str
    role: str
    ip: str
    port: int
    ok: bool
    latency_ms: Optional[float] = None
    agent_role: str
    agent_version: Optional[str] = None
    agent_hostname: Optional[str] = None

class NodesResponse(BaseModel):
    ok: bool
    nodes: list[NodeInfo]
    errors: dict[str, str] = {}

class StartupDiagnosticsResponse(BaseModel):
    ok: bool
    issues: list[str]
    details: dict[str, str]

class MaintenanceResponse(BaseModel):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class CaptureStartRequest(BaseModel):
    target: Literal["resolver", "authoritative"]
    filter: Literal["dns", "dns+dot", "all"] = "dns"

class CaptureStartResponse(BaseModel):
    ok: bool
    target: Literal["resolver", "authoritative"]
    file: str
    filter: str
    command: str

class CaptureStopRequest(BaseModel):
    target: Literal["resolver", "authoritative"]

class CaptureStopResponse(BaseModel):
    ok: bool
    target: Literal["resolver", "authoritative"]
    file: Optional[str] = None

class CaptureFileInfo(BaseModel):
    file: str
    size: int
    mtime: str
    target: Literal["resolver", "authoritative"]

class CaptureListResponse(BaseModel):
    ok: bool
    files: list[CaptureFileInfo]
    running: dict[str, bool]

class CaptureSummaryResponse(BaseModel):
    ok: bool
    file: str
    target: Literal["resolver", "authoritative"]
    total_packets: int
    upstream_queries: int
    command_total: str
    command_upstream: str
    stdout_total: str
    stdout_upstream: str
    stderr_total: str
    stderr_upstream: str

class DemoAggressiveNsecRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    zone: str = "example.test"
    count: int = DEFAULT_DEMO_NX_COUNT
    qps: int = DEFAULT_DEMO_QPS
    capture: bool = True
    capture_target: Literal["resolver", "authoritative"] = "resolver"
    cold_restart: bool = True
    restore: bool = True
    zip: bool = True

class DemoAggressiveNsecPhase(BaseModel):
    aggressive_nsec: bool
    dig_first: CmdResponse
    dig_last: CmdResponse
    loop: CmdResponse
    stats_before: dict[str, float]
    stats_after: dict[str, float]
    delta: dict[str, float]
    capture_file: Optional[str] = None

class DemoAggressiveNsecResponse(BaseModel):
    ok: bool
    zone: str
    count: int
    qps: int
    profile: str
    resolver: str
    phases: list[DemoAggressiveNsecPhase]
    artifact_json: Optional[str] = None
    artifact_zip: Optional[str] = None
    notes: list[str] = []

class CaptureHealthResponse(BaseModel):
    ok: bool
    target: Literal["resolver", "authoritative"]
    running: bool
    pid: Optional[int] = None
    detail: str = ""

class SigningSwitchRequest(BaseModel):
    mode: Literal["nsec", "nsec3"]

class SigningStep(BaseModel):
    step: str
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class SigningSwitchResponse(BaseModel):
    ok: bool
    mode: Literal["nsec", "nsec3"]
    steps: list[SigningStep]

class RunbookStep(BaseModel):
    step: str
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class RunbookResponse(BaseModel):
    ok: bool
    runbook: str
    steps: list[RunbookStep]

class ResolverRestartResponse(BaseModel):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class ResolverFlushRequest(BaseModel):
    zone: str = "example.test"

class ResolverFlushResponse(BaseModel):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

class PrivacyCheckRequest(BaseModel):
    name: str = "www.example.test"
    qtype: Literal["A", "AAAA"] = "A"

class PrivacyCheckResponse(BaseModel):
    ok: bool
    kind: Literal["dot", "doh"]
    endpoint: str
    method: str
    name: str
    qtype: str
    rcode: Optional[str] = None
    response_bytes: int = 0
    elapsed_ms: int = 0
    detail: Optional[str] = None

class EmailSendRequest(BaseModel):
    to_addr: str = Field(..., alias="to")
    from_addr: str = Field(..., alias="from")
    subject: str = "DNS lab test"
    body: str = "Hello from the DNS lab."
    server: str = "mail.example.test"
    port: int = 25
    tls_mode: Literal["none", "starttls", "tls"] = "none"
    auth_user: Optional[str] = None
    auth_password: Optional[str] = None
    auth_type: Literal["AUTO", "LOGIN", "PLAIN", "CRAM-MD5"] = "AUTO"

    class Config:
        allow_population_by_field_name = True

class EmailUserAddRequest(BaseModel):
    email: str
    password: str

class EmailUserUpdateRequest(BaseModel):
    email: str
    password: str

class EmailUserDeleteRequest(BaseModel):
    email: str

class EmailLogResponse(BaseModel):
    ok: bool
    file: str
    command: str
    exit_code: int
    stdout: str
    stderr: str

class EmailImapCheckRequest(BaseModel):
    user: str
    mailbox: str = "INBOX"
    limit: int = 40

class EmailMessageSummary(BaseModel):
    id: str
    source: Literal["uid", "file"]
    mailbox: str
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    date: str = ""

class EmailMessageListRequest(BaseModel):
    user: str
    mailbox: str = "INBOX"
    limit: int = 40

class EmailMessageListResponse(BaseModel):
    ok: bool
    mailbox: str
    messages: list[EmailMessageSummary]
    command: str
    exit_code: int
    stdout: str
    stderr: str

class EmailMessageViewRequest(BaseModel):
    user: str
    mailbox: str = "INBOX"
    message_id: str
    source: Literal["uid", "file"] = "uid"
    max_lines: int = 200

class EmailMessageViewResponse(BaseModel):
    ok: bool
    mailbox: str
    message_id: str
    source: Literal["uid", "file"]
    command: str
    exit_code: int
    stdout: str
    stderr: str
    content: str

class AmplificationTestRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    name: str = "example.test"
    qtypes: list[
        Literal[
            "DNSKEY",
            "ANY",
            "TXT",
            "RRSIG",
            "A",
            "AAAA",
            "SOA",
        ]
    ] = ["DNSKEY", "ANY", "TXT", "RRSIG"]
    edns_sizes: list[int] = [1232, 4096]
    count_per_qtype: int = 10
    dnssec: bool = True
    tcp_fallback: bool = True

class AmplificationResult(BaseModel):
    edns_size: int
    qtype: str
    count: int
    rcode_counts: dict[str, int]
    tc_rate: float
    tcp_rate: float
    avg_latency_ms: float
    p95_latency_ms: float
    avg_udp_size: float
    max_udp_size: int
    avg_tcp_size: float
    max_tcp_size: int

class AmplificationTestResponse(BaseModel):
    ok: bool
    target: str
    name: str
    results: list[AmplificationResult]

class AvailabilityMetricsResponse(BaseModel):
    ok: bool
    totals: dict[str, int]
    ratios: dict[str, float]
    avg_recursion_ms: float
    raw: str

class ResolverStatsResponse(BaseModel):
    ok: bool
    resolver: Literal["valid", "plain"]
    container: str
    cpu_pct: Optional[float] = None
    mem_bytes: Optional[int] = None
    mem_limit_bytes: Optional[int] = None
    mem_pct: Optional[float] = None

class AvailabilityProbeRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    name: str = "www.example.test"
    qtype: Literal[
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "DNSKEY",
        "MX",
        "NS",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "RRSIG",
        "SOA",
        "SRV",
        "TXT",
        "ANY",
    ] = "A"
    count: int = 5

class AvailabilityProbeResponse(BaseModel):
    ok: bool
    target: str
    name: str
    qtype: str
    count: int
    min_ms: float
    max_ms: float
    avg_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    rcode_counts: dict[str, int]

class FloodTestRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    name: str = "www.example.test"
    qtype: Literal[
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "DNSKEY",
        "MX",
        "NS",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "RRSIG",
        "SOA",
        "SRV",
        "TXT",
        "ANY",
    ] = "A"
    qps_start: int = 10
    qps_end: int = 100
    qps_step: int = 10
    step_seconds: int = 30
    max_outstanding: int = 200
    timeout_ms: int = 1000
    stop_loss_pct: float = 2.0
    stop_p95_ms: int = 200
    stop_servfail_pct: float = 2.0
    stop_cpu_pct: float = 85.0

class FloodStepResult(BaseModel):
    step: int
    qps: int
    actual_qps: float
    duration_s: int
    sent: int
    responses: int
    timeouts: int
    loss_pct: float
    rcode_counts: dict[str, int]
    avg_ms: int
    p95_ms: int
    max_ms: int
    servfail_pct: float
    cpu_pct: Optional[float] = None
    stop_reason: Optional[str] = None

class FloodTestResponse(BaseModel):
    ok: bool
    target: str
    name: str
    qtype: str
    steps: list[FloodStepResult]
    stopped_early: bool
    stop_reason: Optional[str] = None

class RrlTestRequest(BaseModel):
    name: str = "example.test"
    qtype: Literal[
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "DNSKEY",
        "MX",
        "NS",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "RRSIG",
        "SOA",
        "SRV",
        "TXT",
        "ANY",
    ] = "A"
    count: int = 300
    log_tail: int = 200

class RrlTestResponse(BaseModel):
    ok: bool
    rrl_enabled: bool
    config_excerpt: str
    log_excerpt: str
    matches: list[str]

class LoadTestRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    name: str = "www.example.test"
    qtype: Literal[
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "DNSKEY",
        "MX",
        "NS",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "RRSIG",
        "SOA",
        "SRV",
        "TXT",
        "ANY",
    ] = "A"
    count: int = 200
    qps: int = 20

class MixLoadRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    resolver: Literal["valid", "plain"] = "valid"
    zone: str = "example.test"
    count: int = 200
    edns_size: int = 1232
    dnssec: bool = True
    tcp_fallback: bool = True

class MixLoadResponse(BaseModel):
    ok: bool
    target: str
    count: int
    edns_size: int
    rcode_counts: dict[str, int]
    query_mix: dict[str, int]
    tc_rate: float
    tcp_rate: float
    avg_latency_ms: float
    p95_latency_ms: float
    avg_udp_size: float
    max_udp_size: int
    avg_tcp_size: float
    max_tcp_size: int

class DnsperfRequest(BaseModel):
    target: Literal[
        "resolver_valid",
        "resolver_plain",
        "authoritative_parent",
        "authoritative_child",
    ] = "resolver_valid"
    duration_s: int = 20
    qps: int = 50
    max_queries: int = 500
    threads: int = 2
    clients: int = 2
    queries: Optional[str] = None

class DnsperfSummary(BaseModel):
    queries_sent: Optional[int] = None
    queries_completed: Optional[int] = None
    queries_lost: Optional[int] = None
    qps: Optional[float] = None
    avg_latency_ms: Optional[float] = None
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None

class DnsperfResponse(BaseModel):
    ok: bool
    target: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    summary: Optional[DnsperfSummary] = None

class ResperfRequest(BaseModel):
    target: Literal[
        "resolver_valid",
        "resolver_plain",
        "authoritative_parent",
        "authoritative_child",
    ] = "resolver_valid"
    max_qps: int = 200
    ramp_qps: int = 15
    clients: int = 15
    queries_per_step: int = 200
    plot_file: Optional[str] = None
    queries: Optional[str] = None

class ResperfResponse(BaseModel):
    ok: bool
    target: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    plot_file: Optional[str] = None

class UnboundControls(BaseModel):
    ratelimit: int
    ip_ratelimit: int
    unwanted_reply_threshold: int
    serve_expired: bool
    serve_expired_ttl: int
    prefetch: bool
    msg_cache_size: str
    rrset_cache_size: str
    aggressive_nsec: bool

class BindControls(BaseModel):
    rrl_enabled: bool
    rrl_responses_per_second: int
    rrl_window: int
    rrl_slip: int
    recursion: bool

class ControlsStatusResponse(BaseModel):
    ok: bool
    unbound: UnboundControls
    bind: BindControls

class ControlsUpdateRequest(BaseModel):
    unbound: Optional[UnboundControls] = None
    bind: Optional[BindControls] = None

def require_key(x_api_key: Optional[str]):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server missing LAB_API_KEY env")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

def require_docker():
    if not ALLOW_DOCKER:
        raise HTTPException(status_code=503, detail="Docker access disabled")

def validate_name(name: str) -> str:
    name = name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid DNS name format")
    return name

def validate_email(addr: str) -> str:
    addr = addr.strip()
    if not EMAIL_RE.match(addr):
        raise HTTPException(status_code=400, detail="Invalid email format")
    local, domain = addr.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid email length")
    if not NAME_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid email domain")
    return addr

def validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid host")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    if not NAME_RE.match(host):
        raise HTTPException(status_code=400, detail="Invalid host")
    return host

def validate_port(port: int) -> int:
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Invalid port")
    return port

def validate_mailbox(name: str) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Invalid mailbox")
    if not MAILBOX_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid mailbox name")
    return name

def redact_auth_password(cmd: str) -> str:
    return re.sub(r"(--auth-password\s+)(\S+)", r"\1****", cmd)

def run_cmd(args: list[str], timeout_s: int = 8) -> CmdResponse:
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout_s)
        return CmdResponse(
            ok=(p.returncode == 0),
            command=" ".join(args),
            exit_code=p.returncode,
            stdout=p.stdout,
            stderr=p.stderr,
        )
    except subprocess.TimeoutExpired as e:
        return CmdResponse(
            ok=False,
            command=" ".join(args),
            exit_code=124,
            stdout=e.stdout or "",
            stderr=(e.stderr or "") + "\nTIMEOUT",
        )

def perf_target_ip(target: str) -> str:
    targets = {
        "resolver_valid": "172.32.0.20",
        "resolver_plain": "172.32.0.21",
        "authoritative_parent": "172.31.0.10",
        "authoritative_child": "172.31.0.11",
    }
    if target not in targets:
        raise HTTPException(status_code=400, detail="Invalid perf target")
    return targets[target]

def sanitize_perf_queries(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    if len(raw) > MAX_PERF_QUERY_CHARS:
        raise HTTPException(status_code=400, detail="Query list too large")
    lines: list[str] = []
    for line in raw.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith(";"):
            continue
        lines.append(clean)
        if len(lines) > MAX_PERF_QUERY_LINES:
            raise HTTPException(status_code=400, detail="Too many query lines")
    if not lines:
        return None
    return "\n".join(lines) + "\n"

def write_perf_queries(container: str, content: str) -> str:
    token = secrets.token_hex(4)
    path = f"/tmp/perf_queries_{token}.txt"
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = f"printf '%s' '{encoded}' | base64 -d > {path}"
    res = docker_exec(container, cmd, timeout_s=6)
    if not res.ok:
        raise HTTPException(status_code=500, detail="Failed to stage perf queries")
    return path

def sanitize_plot_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    clean = name.strip()
    if not clean:
        return None
    if "/" in clean or "\\" in clean or ".." in clean:
        raise HTTPException(status_code=400, detail="Invalid plot file name")
    if not re.match(r"^[A-Za-z0-9._-]+$", clean):
        raise HTTPException(status_code=400, detail="Invalid plot file name")
    return clean

def parse_dnsperf_summary(output: str) -> Optional[DnsperfSummary]:
    if not output:
        return None
    summary = DnsperfSummary()
    int_fields = {
        "queries_sent": r"Queries sent:\s+(\d+)",
        "queries_completed": r"Queries completed:\s+(\d+)",
        "queries_lost": r"Queries lost:\s+(\d+)",
    }
    for key, pattern in int_fields.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            setattr(summary, key, int(match.group(1)))
    float_fields = {
        "qps": r"Queries per second:\s+([0-9.]+)",
        "avg_latency_ms": r"Average latency:\s+([0-9.]+)\s*ms",
    }
    for key, pattern in float_fields.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            setattr(summary, key, float(match.group(1)))
    avg_latency_seconds = re.search(
        r"Average Latency\s*\(s\):\s*([0-9.]+)",
        output,
        re.IGNORECASE,
    )
    if avg_latency_seconds:
        summary.avg_latency_ms = float(avg_latency_seconds.group(1)) * 1000.0
    minmax = re.search(
        r"Latency Min/Max:\s+([0-9.]+)\s*/\s*([0-9.]+)\s*ms",
        output,
        re.IGNORECASE,
    )
    if minmax:
        summary.min_latency_ms = float(minmax.group(1))
        summary.max_latency_ms = float(minmax.group(2))
    minmax_seconds = re.search(
        r"Average Latency\s*\(s\):\s*[0-9.]+\s*\(min\s*([0-9.]+),\s*max\s*([0-9.]+)\)",
        output,
        re.IGNORECASE,
    )
    if minmax_seconds:
        summary.min_latency_ms = float(minmax_seconds.group(1)) * 1000.0
        summary.max_latency_ms = float(minmax_seconds.group(2)) * 1000.0
    if any(
        getattr(summary, field) is not None
        for field in summary.model_fields.keys()
    ):
        return summary
    return None

def _dns_qtype(value: str) -> int:
    return {
        "A": 1,
        "AAAA": 28,
        "CAA": 257,
        "CNAME": 5,
        "DS": 43,
        "DNSKEY": 48,
        "MX": 15,
        "NS": 2,
        "NSEC": 47,
        "NSEC3": 50,
        "NSEC3PARAM": 51,
        "RRSIG": 46,
        "SOA": 6,
        "SRV": 33,
        "TXT": 16,
        "ANY": 255,
    }[value]

def _encode_name(name: str) -> bytes:
    labels = name.strip().rstrip(".").split(".") if name.strip() else []
    if not labels:
        return b"\x00"
    out = bytearray()
    for label in labels:
        if not label:
            continue
        part = label.encode("ascii", errors="ignore")
        if len(part) > 63:
            raise HTTPException(status_code=400, detail="Label too long")
        out.append(len(part))
        out.extend(part)
    out.append(0)
    return bytes(out)

def _build_query(
    name: str, qtype: str, edns_size: Optional[int] = None, dnssec: bool = False
) -> tuple[int, bytes]:
    qid = secrets.randbelow(65535)
    flags = 0x0100
    qdcount = 1
    arcount = 0
    if edns_size is None and dnssec:
        edns_size = 1232
    if edns_size:
        arcount = 1
    header = struct.pack("!HHHHHH", qid, flags, qdcount, 0, 0, arcount)
    qname = _encode_name(name)
    qtype_id = _dns_qtype(qtype)
    question = qname + struct.pack("!HH", qtype_id, 1)
    additional = b""
    if edns_size:
        do_flag = 0x8000 if dnssec else 0x0000
        ttl = do_flag
        additional = b"\x00" + struct.pack("!HHIH", 41, edns_size, ttl, 0)
    return qid, header + question + additional

def _parse_rcode(response: bytes) -> Optional[str]:
    if len(response) < 4:
        return None
    flags = struct.unpack("!H", response[2:4])[0]
    rcode = flags & 0x000F
    return {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }.get(rcode, f"RCODE={rcode}")

def _parse_tc(response: bytes) -> bool:
    if len(response) < 4:
        return False
    flags = struct.unpack("!H", response[2:4])[0]
    return bool(flags & 0x0200)

def _udp_query(
    server: str,
    name: str,
    qtype: str,
    edns_size: Optional[int] = None,
    dnssec: bool = False,
) -> tuple[float, Optional[str], int, bool]:
    _, query = _build_query(name, qtype, edns_size=edns_size, dnssec=dnssec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    start = time.perf_counter()
    try:
        sock.sendto(query, (server, 53))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
    rcode = _parse_rcode(response)
    tc = _parse_tc(response)
    return elapsed_ms, rcode, len(response), tc

def _tcp_query(
    server: str,
    name: str,
    qtype: str,
    edns_size: Optional[int] = None,
    dnssec: bool = False,
) -> tuple[float, Optional[str], int, bool]:
    _, query = _build_query(name, qtype, edns_size=edns_size, dnssec=dnssec)
    start = time.perf_counter()
    with socket.create_connection((server, 53), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(struct.pack("!H", len(query)) + query)
        head = sock.recv(2)
        if len(head) != 2:
            raise TimeoutError("Short TCP response")
        resp_len = struct.unpack("!H", head)[0]
        response = bytearray()
        while len(response) < resp_len:
            chunk = sock.recv(resp_len - len(response))
            if not chunk:
                break
            response.extend(chunk)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
    rcode = _parse_rcode(bytes(response))
    tc = _parse_tc(bytes(response))
    return elapsed_ms, rcode, len(response), tc

def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    items = sorted(values)
    idx = int((len(items) - 1) * 0.95)
    return float(items[idx])

def _parse_unbound_stats(raw: str) -> dict[str, float]:
    stats: dict[str, float] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            if "." in value:
                stats[key] = float(value)
            else:
                stats[key] = float(int(value))
        except ValueError:
            continue
    return stats

def _pick_stat(stats: dict[str, float], keys: list[str]) -> float:
    for key in keys:
        if key in stats:
            return stats[key]
    return 0.0

def _read_unbound_stats(container: str) -> dict[str, float]:
    res = docker_exec(
        container,
        "/opt/unbound/sbin/unbound-control -c /opt/unbound/etc/unbound/unbound.conf stats_noreset",
        timeout_s=8,
    )
    if res.exit_code != 0:
        raise HTTPException(status_code=502, detail=res.stderr or "Failed to read stats")
    return _parse_unbound_stats(res.stdout)

def _extract_unbound_counters(stats: dict[str, float]) -> dict[str, float]:
    return {
        "queries": _pick_stat(stats, ["total.num.queries", "num.queries"]),
        "cache_hits": _pick_stat(stats, ["total.num.cachehits", "num.cachehits"]),
        "cache_miss": _pick_stat(stats, ["total.num.cachemiss", "num.cachemiss"]),
        "nxdomain": _pick_stat(
            stats,
            [
                "num.answer.rcode.NXDOMAIN",
                "total.num.query.rcode.NXDOMAIN",
                "num.query.rcode.NXDOMAIN",
            ],
        ),
        "servfail": _pick_stat(
            stats,
            [
                "num.answer.rcode.SERVFAIL",
                "total.num.query.rcode.SERVFAIL",
                "num.query.rcode.SERVFAIL",
            ],
        ),
        "aggressive_nxdomain": _pick_stat(
            stats,
            ["num.query.aggressive.NXDOMAIN", "total.num.query.aggressive.NXDOMAIN"],
        ),
        "recursivereplies": _pick_stat(
            stats, ["total.num.recursivereplies", "num.recursivereplies"]
        ),
    }

def _diff_counters(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    keys = set(before.keys()) | set(after.keys())
    return {key: after.get(key, 0.0) - before.get(key, 0.0) for key in keys}

UNBOUND_CONFIGS = [
    Path("/config/unbound/unbound.conf"),
    Path("/config/unbound/unbound.plain.conf"),
]
BIND_CONFIGS = [
    Path("/config/bind/named.conf"),
    Path("/config/bind_parent/named.conf"),
]

def _read_text(path: Path) -> str:
    if not path.exists():
        raise HTTPException(status_code=500, detail=f"Missing config: {path}")
    return path.read_text(encoding="utf-8", errors="replace")

def _write_text(path: Path, data: str):
    path.write_text(data, encoding="utf-8", newline="\n")

def _parse_unbound_value(lines: list[str], key: str) -> Optional[str]:
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.lower().startswith(f"{key}:"):
            return raw.split(":", 1)[1].strip()
    return None

def _parse_bool(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in ("yes", "true", "1", "on")

def _parse_int(value: Optional[str]) -> int:
    if value is None:
        return 0
    try:
        return int(value.strip())
    except ValueError:
        return 0

def _parse_unbound_config(text: str) -> UnboundControls:
    lines = text.splitlines()
    return UnboundControls(
        ratelimit=_parse_int(_parse_unbound_value(lines, "ratelimit")),
        ip_ratelimit=_parse_int(_parse_unbound_value(lines, "ip-ratelimit")),
        unwanted_reply_threshold=_parse_int(
            _parse_unbound_value(lines, "unwanted-reply-threshold")
        ),
        serve_expired=_parse_bool(_parse_unbound_value(lines, "serve-expired")),
        serve_expired_ttl=_parse_int(
            _parse_unbound_value(lines, "serve-expired-ttl")
        ),
        prefetch=_parse_bool(_parse_unbound_value(lines, "prefetch")),
        msg_cache_size=_parse_unbound_value(lines, "msg-cache-size") or "",
        rrset_cache_size=_parse_unbound_value(lines, "rrset-cache-size") or "",
        aggressive_nsec=_parse_bool(_parse_unbound_value(lines, "aggressive-nsec")),
    )

def _upsert_unbound_line(lines: list[str], key: str, value: str) -> list[str]:
    pattern = re.compile(rf"^(\s*){re.escape(key)}\s*:\s*.*$", re.IGNORECASE)
    for idx, line in enumerate(lines):
        match = pattern.match(line)
        if match:
            indent = match.group(1) or "  "
            lines[idx] = f"{indent}{key}: {value}"
            return lines
    # Insert after server: if present, else append
    for idx, line in enumerate(lines):
        if line.strip().lower() == "server:":
            lines.insert(idx + 1, f"  {key}: {value}")
            return lines
    lines.append(f"  {key}: {value}")
    return lines

def _apply_unbound_config(text: str, cfg: UnboundControls) -> str:
    lines = text.splitlines()
    lines = _upsert_unbound_line(lines, "ratelimit", str(cfg.ratelimit))
    lines = _upsert_unbound_line(lines, "ip-ratelimit", str(cfg.ip_ratelimit))
    lines = _upsert_unbound_line(
        lines, "unwanted-reply-threshold", str(cfg.unwanted_reply_threshold)
    )
    lines = _upsert_unbound_line(
        lines, "serve-expired", "yes" if cfg.serve_expired else "no"
    )
    lines = _upsert_unbound_line(
        lines, "serve-expired-ttl", str(cfg.serve_expired_ttl)
    )
    lines = _upsert_unbound_line(
        lines, "prefetch", "yes" if cfg.prefetch else "no"
    )
    if cfg.msg_cache_size:
        lines = _upsert_unbound_line(lines, "msg-cache-size", cfg.msg_cache_size)
    if cfg.rrset_cache_size:
        lines = _upsert_unbound_line(lines, "rrset-cache-size", cfg.rrset_cache_size)
    lines = _upsert_unbound_line(
        lines, "aggressive-nsec", "yes" if cfg.aggressive_nsec else "no"
    )
    return "\n".join(lines) + "\n"

def _parse_bind_config(text: str) -> BindControls:
    recursion_match = re.search(r"^\s*recursion\s+(yes|no)\s*;", text, re.M)
    recursion = recursion_match.group(1).lower() == "yes" if recursion_match else False
    rrl_block = re.search(r"rate-limit\s*\{([\s\S]*?)\};", text, re.M)
    rrl_enabled = rrl_block is not None
    rps = 0
    window = 0
    slip = 0
    if rrl_block:
        block = rrl_block.group(1)
        m = re.search(r"responses-per-second\s+(\d+)\s*;", block)
        if m:
            rps = int(m.group(1))
        m = re.search(r"window\s+(\d+)\s*;", block)
        if m:
            window = int(m.group(1))
        m = re.search(r"slip\s+(\d+)\s*;", block)
        if m:
            slip = int(m.group(1))
    return BindControls(
        rrl_enabled=rrl_enabled,
        rrl_responses_per_second=rps or 20,
        rrl_window=window or 5,
        rrl_slip=slip or 2,
        recursion=recursion,
    )

def _apply_bind_config(text: str, cfg: BindControls) -> str:
    # Update recursion
    if re.search(r"^\s*recursion\s+(yes|no)\s*;", text, re.M):
        text = re.sub(
            r"^\s*recursion\s+(yes|no)\s*;",
            f"  recursion {'yes' if cfg.recursion else 'no'};",
            text,
            flags=re.M,
        )
    else:
        text = re.sub(
            r"(options\s*\{)",
            rf"\1\n  recursion {'yes' if cfg.recursion else 'no'};",
            text,
            count=1,
        )

    allow_recursion = "any" if cfg.recursion else "none"
    if re.search(r"^\s*allow-recursion\s+\{.*\};", text, re.M):
        text = re.sub(
            r"^\s*allow-recursion\s+\{.*\};",
            f"  allow-recursion {{ {allow_recursion}; }};",
            text,
            flags=re.M,
        )
    else:
        text = re.sub(
            r"(options\s*\{)",
            rf"\1\n  allow-recursion {{ {allow_recursion}; }};",
            text,
            count=1,
        )

    if re.search(r"^\s*allow-query-cache\s+\{.*\};", text, re.M):
        text = re.sub(
            r"^\s*allow-query-cache\s+\{.*\};",
            f"  allow-query-cache {{ {allow_recursion}; }};",
            text,
            flags=re.M,
        )
    else:
        text = re.sub(
            r"(options\s*\{)",
            rf"\1\n  allow-query-cache {{ {allow_recursion}; }};",
            text,
            count=1,
        )

    # Remove existing rate-limit block
    text = re.sub(r"\n\s*rate-limit\s*\{[\s\S]*?\};", "", text, count=1)

    if cfg.rrl_enabled:
        block = (
            "\n  rate-limit {\n"
            f"    responses-per-second {cfg.rrl_responses_per_second};\n"
            f"    window {cfg.rrl_window};\n"
            f"    slip {cfg.rrl_slip};\n"
            "  };\n"
        )
        if "minimal-responses yes;" in text:
            text = text.replace("minimal-responses yes;", "minimal-responses yes;" + block)
        else:
            text = re.sub(r"(options\s*\{)", rf"\1{block}", text, count=1)

    if not text.endswith("\n"):
        text += "\n"
    return text

def _dot_query(name: str, qtype: str) -> tuple[int, Optional[str], str, int]:
    qid, query = _build_query(name, qtype)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    start = time.perf_counter()
    with socket.create_connection((DOT_RESOLVER_IP, DOT_RESOLVER_PORT), timeout=4) as sock:
        with context.wrap_socket(sock, server_hostname="resolver.test") as tls:
            tls.sendall(struct.pack("!H", len(query)) + query)
            head = tls.recv(2)
            if len(head) != 2:
                raise HTTPException(status_code=502, detail="Short DoT response")
            resp_len = struct.unpack("!H", head)[0]
            response = bytearray()
            while len(response) < resp_len:
                chunk = tls.recv(resp_len - len(response))
                if not chunk:
                    break
                response.extend(chunk)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    rcode = _parse_rcode(bytes(response))
    detail = f"qid={qid}"
    return elapsed_ms, rcode, detail, len(response)

def _doh_query(name: str, qtype: str) -> tuple[int, Optional[str], str, int]:
    _, query = _build_query(name, qtype)
    context = ssl._create_unverified_context()
    start = time.perf_counter()
    conn = http.client.HTTPSConnection(
        DOH_PROXY_HOST, DOH_PROXY_PORT, context=context, timeout=4
    )
    conn.request(
        "POST",
        DOH_PROXY_PATH,
        body=query,
        headers={
            "content-type": "application/dns-message",
            "accept": "application/dns-message",
        },
    )
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    rcode = _parse_rcode(data)
    detail = f"http={resp.status}"
    return elapsed_ms, rcode, detail, len(data)

def list_config_files() -> list[ConfigFile]:
    files: list[ConfigFile] = []
    for root in CONFIG_DIRS.values():
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file():
                rel = path.relative_to(CONFIG_ROOT).as_posix()
                files.append(ConfigFile(path=rel, size=path.stat().st_size))
    files.sort(key=lambda f: f.path)
    return files

def resolve_config_path(rel_path: str) -> Path:
    if not rel_path or rel_path.startswith("/") or ".." in Path(rel_path).parts:
        raise HTTPException(status_code=400, detail="Invalid path")

    full = (CONFIG_ROOT / rel_path).resolve()
    for root in CONFIG_DIRS.values():
        try:
            full.relative_to(root)
            return full
        except ValueError:
            continue
    raise HTTPException(status_code=403, detail="Path not allowed")

def docker_exec_user(
    container: str,
    sh_cmd: str,
    user: Optional[str] = None,
    timeout_s: int = 8,
) -> CmdResponse:
    cmd = ["docker", "exec"]
    if user:
        cmd.extend(["-u", str(user)])
    cmd.extend([container, "sh", "-lc", sh_cmd])
    return run_cmd(cmd, timeout_s)

def docker_exec(container: str, sh_cmd: str, timeout_s: int = 8) -> CmdResponse:
    return docker_exec_user(container, sh_cmd, None, timeout_s)

def docker_exec_root(container: str, sh_cmd: str, timeout_s: int = 8) -> CmdResponse:
    return docker_exec_user(container, sh_cmd, "0", timeout_s)

def docker_cmd(args: list[str], timeout_s: int = 8) -> CmdResponse:
    return run_cmd(["docker", *args], timeout_s)

def _cmd_failure(command: str, message: str, exit_code: int = 127) -> CmdResponse:
    return CmdResponse(
        ok=False,
        command=command,
        exit_code=exit_code,
        stdout="",
        stderr=message,
    )

def _record_runbook_step(
    steps: list[RunbookStep],
    label: str,
    res: CmdResponse,
    ok_override: Optional[bool] = None,
) -> bool:
    ok = res.ok if ok_override is None else ok_override
    steps.append(
        RunbookStep(
            step=label,
            ok=ok,
            command=res.command,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
        )
    )
    return ok

def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

def _matches_all(text: str, patterns: list[str]) -> bool:
    return all(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

def _evaluate_output(
    res: CmdResponse,
    expect_any: Optional[list[str]] = None,
    expect_all: Optional[list[str]] = None,
    forbid_any: Optional[list[str]] = None,
    allow_nonzero: bool = False,
) -> bool:
    text = "\n".join([res.stdout or "", res.stderr or ""])
    ok = True
    if not allow_nonzero:
        ok = ok and res.ok
    if expect_any:
        ok = ok and _matches_any(text, expect_any)
    if expect_all:
        ok = ok and _matches_all(text, expect_all)
    if forbid_any:
        ok = ok and not _matches_any(text, forbid_any)
    return ok

def ensure_running(container: str) -> CmdResponse:
    inspect = docker_cmd(
        ["inspect", "-f", "{{.State.Running}}", container], timeout_s=6
    )
    if inspect.exit_code != 0:
        return inspect
    if inspect.stdout.strip().lower() == "true":
        return inspect
    return docker_cmd(["start", container], timeout_s=10)

def capture_pid_file(target: str) -> str:
    return f"/tmp/capture_{target}.pid"

def capture_file_file(target: str) -> str:
    return f"/tmp/capture_{target}.file"

def capture_log_file(target: str) -> str:
    return f"/tmp/capture_{target}.log"

def capture_running(target: Literal["resolver", "authoritative"]) -> bool:
    container = CAPTURE_TARGETS[target]
    pid_path = capture_pid_file(target)
    check_cmd = (
        f"if [ -f {pid_path} ]; then "
        f"pid=$(cat {pid_path}); "
        "if kill -0 $pid >/dev/null 2>&1; then echo RUNNING; else echo STALE; fi; "
        "fi"
    )
    result = docker_exec_root(container, check_cmd)
    if result.exit_code != 0:
        raise HTTPException(
            status_code=500,
            detail=result.stderr or f"Failed to check capture on {target}",
        )
    if "STALE" in result.stdout:
        docker_exec_root(container, f"rm -f {pid_path}")
        return False
    return "RUNNING" in result.stdout

def capture_target_from_file(name: str) -> Literal["resolver", "authoritative"]:
    if name.startswith("resolver-"):
        return "resolver"
    if name.startswith("authoritative-"):
        return "authoritative"
    raise HTTPException(status_code=400, detail="Unknown capture file target")

def parse_count(value: str) -> int:
    try:
        return int(value.strip())
    except ValueError:
        return -1

def _tail_bind_log(tail: int) -> str:
    if AUTH_AGENT_URL:
        data = _agent_request(AUTH_AGENT_URL, "/logs", {"scope": "bind", "tail": tail})
        return data.get("stdout", "")
    base = Path("/logs/bind")
    log = _latest_log_file(base)
    if not log:
        return ""
    return _tail_file(log, tail)

def _extract_rrl_block(text: str) -> str:
    match = re.search(r"\n\s*rate-limit\s*\{[\s\S]*?\};", text, re.M)
    return match.group(0).strip() if match else ""

def _resolver_container(kind: Literal["valid", "plain"]) -> str:
    return RESOLVER_CONTAINER if kind == "valid" else RESOLVER_PLAIN_CONTAINER

def _unbound_config_path(kind: Literal["valid", "plain"]) -> Path:
    return UNBOUND_CONFIGS[0] if kind == "valid" else UNBOUND_CONFIGS[1]

def _resolver_cpu_pct(container: str) -> Optional[float]:
    res = docker_cmd(
        ["stats", "--no-stream", "--format", "{{.CPUPerc}}", container],
        timeout_s=6,
    )
    if res.exit_code != 0:
        return None
    raw = res.stdout.strip().replace("%", "")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None

def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(math.ceil(pct * len(ordered))) - 1
    idx = max(0, min(idx, len(ordered) - 1))
    return float(ordered[idx])

def _parse_mem_bytes(value: str) -> Optional[int]:
    raw = value.strip()
    if not raw:
        return None
    match = re.match(r"([0-9.]+)\s*([A-Za-z]+)", raw)
    if not match:
        return None
    num = float(match.group(1))
    unit = match.group(2).lower()
    units = {
        "b": 1,
        "kb": 1000,
        "kib": 1024,
        "mb": 1000**2,
        "mib": 1024**2,
        "gb": 1000**3,
        "gib": 1024**3,
        "tb": 1000**4,
        "tib": 1024**4,
    }
    factor = units.get(unit)
    if not factor:
        return None
    return int(num * factor)

def _resolver_mem_stats(container: str) -> tuple[Optional[int], Optional[int]]:
    res = docker_cmd(
        ["stats", "--no-stream", "--format", "{{.MemUsage}}", container],
        timeout_s=6,
    )
    if res.exit_code != 0:
        return None, None
    raw = res.stdout.strip()
    if "/" not in raw:
        return None, None
    used_raw, limit_raw = [part.strip() for part in raw.split("/", 1)]
    return _parse_mem_bytes(used_raw), _parse_mem_bytes(limit_raw)

def ensure_capture_dir():
    if not CAPTURE_DIR.exists():
        raise HTTPException(status_code=500, detail="Capture directory not mounted")

def ensure_demo_dir():
    ensure_capture_dir()
    if not DEMO_DIR.exists():
        DEMO_DIR.mkdir(parents=True, exist_ok=True)

def _mail_log_file() -> str:
    res = docker_exec_root(
        MAILSERVER_CONTAINER,
        "ls -1t /var/log/mail/* 2>/dev/null | head -n 1",
        timeout_s=6,
    )
    if res.exit_code != 0 or not res.stdout.strip():
        raise HTTPException(status_code=404, detail="Mail log not found")
    return res.stdout.strip()

def _doveadm_has_error(stderr_text: str) -> bool:
    return bool(re.search(r"(?im)^(?:doveadm\\([^)]*\\):\\s*)?(Error|Fatal|Panic):", stderr_text or ""))

def _build_swaks_command(req: EmailSendRequest) -> tuple[str, str]:
    subject = (req.subject or "").strip()
    if len(subject) > MAX_EMAIL_SUBJECT_CHARS:
        subject = subject[:MAX_EMAIL_SUBJECT_CHARS]
    body = req.body or ""
    if len(body) > MAX_EMAIL_BODY_CHARS:
        raise HTTPException(status_code=400, detail="Email body too large")

    parts = [
        "swaks",
        "--to",
        req.to_addr,
        "--from",
        req.from_addr,
        "--server",
        req.server,
        "--port",
        str(req.port),
        "--header",
        f"Subject: {subject}",
        "--body",
        body,
    ]

    if req.tls_mode == "starttls":
        parts.append("--tls")
    elif req.tls_mode == "tls":
        parts.append("--tls-on-connect")

    if req.auth_user or req.auth_password:
        if not req.auth_user or not req.auth_password:
            raise HTTPException(status_code=400, detail="Auth user/password required")
        parts.extend(
            [
                "--auth",
                req.auth_type,
                "--auth-user",
                req.auth_user,
                "--auth-password",
                req.auth_password,
            ]
        )

    cmd = " ".join(shlex.quote(p) for p in parts)
    return cmd, redact_auth_password(cmd)

def _maildir_headers(user: str, limit: int) -> CmdResponse:
    if "@" not in user:
        raise HTTPException(status_code=400, detail="Invalid mailbox user")
    local, domain = user.split("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        raise HTTPException(status_code=400, detail="Invalid mailbox user")
    if not NAME_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid mailbox domain")
    # local-part validation is relaxed, but restrict to safe set for paths
    if not MAILBOX_RE.match(local):
        raise HTTPException(status_code=400, detail="Invalid mailbox user")

    base = f"/var/mail/{domain}/{local}"
    cmd = (
        "sh -lc '"
        "dir={base}; "
        "files=$(ls -t \"$dir\"/new/* \"$dir\"/cur/* 2>/dev/null | head -n {limit}); "
        "if [ -z \"$files\" ]; then echo \"No messages found.\"; exit 0; fi; "
        "for f in $files; do "
        "echo \"FILE: $f\"; "
        "sed -n \"1,80p\" \"$f\" | sed -n \"/^$/q; p\" | "
        "grep -Ei \"^(From|To|Subject|Date|Message-Id):\"; "
        "echo \"\"; "
        "done'"
    ).format(base=base, limit=limit)
    return docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)

def _maildir_list(user: str, limit: int) -> CmdResponse:
    if "@" not in user:
        raise HTTPException(status_code=400, detail="Invalid mailbox user")
    local, domain = user.split("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        raise HTTPException(status_code=400, detail="Invalid mailbox user")
    if not NAME_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid mailbox domain")
    if not MAILBOX_RE.match(local):
        raise HTTPException(status_code=400, detail="Invalid mailbox user")

    base = f"/var/mail/{domain}/{local}"
    cmd = (
        "sh -lc '"
        "dir={base}; "
        "files=$(ls -t \"$dir\"/new/* \"$dir\"/cur/* 2>/dev/null | head -n {limit}); "
        "if [ -z \"$files\" ]; then echo \"No messages found.\"; exit 0; fi; "
        "for f in $files; do "
        "rel=${{f#\"$dir\"/}}; "
        "echo \"FILE: $rel\"; "
        "sed -n \"1,120p\" \"$f\" | sed -n \"/^$/q; p\" | "
        "grep -Ei \"^(From|To|Subject|Date|Message-Id):\"; "
        "echo \"\"; "
        "done'"
    ).format(base=base, limit=limit)
    return docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)

def _parse_doveadm_message_list(output: str, mailbox: str) -> list[EmailMessageSummary]:
    messages: list[dict] = []
    current: dict = {}
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            if current.get("id"):
                messages.append(current)
            current = {}
            continue
        if line.lower().startswith("seq:"):
            if current.get("id"):
                messages.append(current)
            current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "uid":
            current["id"] = value
        elif key == "hdr.subject":
            current["subject"] = value
        elif key == "hdr.from":
            current["from_addr"] = value
        elif key == "hdr.to":
            current["to_addr"] = value
        elif key == "hdr.date":
            current["date"] = value
    if current.get("id"):
        messages.append(current)

    return [
        EmailMessageSummary(
            id=str(msg.get("id", "")).strip(),
            source="uid",
            mailbox=mailbox,
            subject=str(msg.get("subject", "")).strip(),
            from_addr=str(msg.get("from_addr", "")).strip(),
            to_addr=str(msg.get("to_addr", "")).strip(),
            date=str(msg.get("date", "")).strip(),
        )
        for msg in messages
        if str(msg.get("id", "")).strip()
    ]

def _parse_maildir_message_list(output: str, mailbox: str) -> list[EmailMessageSummary]:
    messages: list[EmailMessageSummary] = []
    current: Optional[dict] = None
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("FILE: "):
            if current:
                messages.append(
                    EmailMessageSummary(
                        id=current.get("id", ""),
                        source="file",
                        mailbox=mailbox,
                        subject=current.get("subject", ""),
                        from_addr=current.get("from_addr", ""),
                        to_addr=current.get("to_addr", ""),
                        date=current.get("date", ""),
                    )
                )
            current = {
                "id": line.replace("FILE:", "", 1).strip(),
                "subject": "",
                "from_addr": "",
                "to_addr": "",
                "date": "",
            }
            continue
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "subject":
            current["subject"] = value
        elif key == "from":
            current["from_addr"] = value
        elif key == "to":
            current["to_addr"] = value
        elif key == "date":
            current["date"] = value
    if current:
        messages.append(
            EmailMessageSummary(
                id=current.get("id", ""),
                source="file",
                mailbox=mailbox,
                subject=current.get("subject", ""),
                from_addr=current.get("from_addr", ""),
                to_addr=current.get("to_addr", ""),
                date=current.get("date", ""),
            )
        )
    return messages

def _clean_doveadm_text(output: str) -> str:
    lines = (output or "").splitlines()
    content: list[str] = []
    capturing = False
    for line in lines:
        if line.startswith("text:") or line.startswith("body:"):
            capturing = True
            remainder = line.split(":", 1)[1].lstrip()
            if remainder:
                content.append(remainder)
            continue
        if line.startswith("seq:") or line.startswith("uid:"):
            continue
        if capturing:
            content.append(line)
    if not content:
        content = [line for line in lines if not line.startswith("seq:") and not line.startswith("uid:")]
    return "\n".join(content).strip()

def _validate_maildir_rel(value: str) -> str:
    rel = (value or "").strip()
    if not rel:
        raise HTTPException(status_code=400, detail="Missing mailbox message id")
    if ".." in rel or rel.startswith("/") or "\\" in rel:
        raise HTTPException(status_code=400, detail="Invalid mailbox message id")
    if not re.match(r"^(?:new|cur)/[A-Za-z0-9._@+=:,%+-]+$", rel):
        raise HTTPException(status_code=400, detail="Invalid mailbox message id")
    return rel

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/controls/status", response_model=ControlsStatusResponse)
def controls_status(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    unbound_text = _read_text(UNBOUND_CONFIGS[0])
    bind_text = _read_text(BIND_CONFIGS[0])
    return ControlsStatusResponse(
        ok=True,
        unbound=_parse_unbound_config(unbound_text),
        bind=_parse_bind_config(bind_text),
    )

@app.post("/controls/apply", response_model=ControlsStatusResponse)
def controls_apply(
    req: ControlsUpdateRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    unbound_cfg = req.unbound
    bind_cfg = req.bind

    if unbound_cfg:
        for path in UNBOUND_CONFIGS:
            text = _read_text(path)
            _write_text(path, _apply_unbound_config(text, unbound_cfg))
        docker_cmd(
            ["restart", RESOLVER_CONTAINER, RESOLVER_PLAIN_CONTAINER], timeout_s=20
        )

    if bind_cfg:
        for path in BIND_CONFIGS:
            text = _read_text(path)
            _write_text(path, _apply_bind_config(text, bind_cfg))
        docker_cmd(
            ["restart", SIGNING_PARENT_CONTAINER, SIGNING_CHILD_CONTAINER], timeout_s=20
        )

    unbound_text = _read_text(UNBOUND_CONFIGS[0])
    bind_text = _read_text(BIND_CONFIGS[0])
    if request:
        audit_log(
            request,
            "controls_apply",
            {
                "unbound": bool(unbound_cfg),
                "bind": bool(bind_cfg),
            },
        )
    return ControlsStatusResponse(
        ok=True,
        unbound=_parse_unbound_config(unbound_text),
        bind=_parse_bind_config(bind_text),
    )

@app.get("/availability/metrics", response_model=AvailabilityMetricsResponse)
def availability_metrics(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    require_docker()
    res = docker_exec(
        RESOLVER_CONTAINER,
        "/opt/unbound/sbin/unbound-control -c /opt/unbound/etc/unbound/unbound.conf stats_noreset",
        timeout_s=8,
    )
    if res.exit_code != 0:
        raise HTTPException(status_code=502, detail=res.stderr or "Failed to read stats")

    stats = _parse_unbound_stats(res.stdout)
    total_queries = int(
        _pick_stat(stats, ["total.num.queries", "num.queries", "num.query"])
    )
    cache_hits = int(_pick_stat(stats, ["total.num.cachehits", "num.cachehits"]))
    cache_miss = int(_pick_stat(stats, ["total.num.cachemiss", "num.cachemiss"]))
    nxdomain = int(
        _pick_stat(stats, ["total.num.query.rcode.NXDOMAIN", "num.query.rcode.NXDOMAIN"])
    )
    servfail = int(
        _pick_stat(stats, ["total.num.query.rcode.SERVFAIL", "num.query.rcode.SERVFAIL"])
    )
    ip_ratelimited = int(
        _pick_stat(
            stats,
            ["total.num.queries_ip_ratelimited", "num.queries_ip_ratelimited"],
        )
    )
    ratelimited = int(
        _pick_stat(stats, ["total.num.queries_ratelimited", "num.queries_ratelimited"])
    )
    avg_recursion = _pick_stat(
        stats,
        ["total.recursion.time.avg", "recursion.time.avg"],
    )

    denom = max(total_queries, 1)
    ratios = {
        "nxdomain": nxdomain / denom,
        "servfail": servfail / denom,
        "cache_hit": cache_hits / max(cache_hits + cache_miss, 1),
        "ratelimited": ratelimited / denom,
        "ip_ratelimited": ip_ratelimited / denom,
    }
    totals = {
        "queries": total_queries,
        "cache_hits": cache_hits,
        "cache_miss": cache_miss,
        "nxdomain": nxdomain,
        "servfail": servfail,
        "ratelimited": ratelimited,
        "ip_ratelimited": ip_ratelimited,
    }
    return AvailabilityMetricsResponse(
        ok=True,
        totals=totals,
        ratios=ratios,
        avg_recursion_ms=round(avg_recursion * 1000, 2),
        raw=res.stdout,
    )

@app.get("/availability/resolver-stats", response_model=ResolverStatsResponse)
def availability_resolver_stats(
    resolver: Literal["valid", "plain"] = "valid",
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    require_docker()
    container = _resolver_container(resolver)
    cpu_pct = _resolver_cpu_pct(container)
    mem_bytes, mem_limit_bytes = _resolver_mem_stats(container)
    mem_pct = None
    if mem_bytes is not None and mem_limit_bytes:
        mem_pct = round(mem_bytes / mem_limit_bytes * 100.0, 2)
    return ResolverStatsResponse(
        ok=True,
        resolver=resolver,
        container=container,
        cpu_pct=cpu_pct,
        mem_bytes=mem_bytes,
        mem_limit_bytes=mem_limit_bytes,
        mem_pct=mem_pct,
    )

@app.post("/availability/probe", response_model=AvailabilityProbeResponse)
def availability_probe(
    req: AvailabilityProbeRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    if req.count < 1 or req.count > MAX_PROBE_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count")

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]
    timings: list[float] = []
    rcode_counts: dict[str, int] = {}

    for _ in range(req.count):
        elapsed_ms, rcode, _, _ = _udp_query(resolver_ip, name, req.qtype)
        timings.append(elapsed_ms)
        if rcode:
            rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1

    if not timings:
        raise HTTPException(status_code=500, detail="Probe failed")

    return AvailabilityProbeResponse(
        ok=True,
        target=f"{req.profile}/{req.resolver}@{resolver_ip}",
        name=name,
        qtype=req.qtype,
        count=req.count,
        min_ms=round(min(timings), 3),
        max_ms=round(max(timings), 3),
        avg_ms=round(sum(timings) / len(timings), 3),
        p50_ms=round(_percentile(timings, 0.50), 3),
        p95_ms=round(_percentile(timings, 0.95), 3),
        p99_ms=round(_percentile(timings, 0.99), 3),
        rcode_counts=rcode_counts,
    )

@app.post("/availability/load", response_model=CmdResponse)
def availability_load(
    req: LoadTestRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    require_docker()
    if req.count < 1 or req.count > MAX_LOAD_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count")
    if req.qps < 1 or req.qps > MAX_LOAD_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps")

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]
    client_container = CLIENT_CONTAINER_BY_PROFILE[req.profile]
    sleep_s = 1.0 / req.qps

    if sleep_s <= 0:
        loop_cmd = (
            f"for i in $(seq 1 {req.count}); do "
            f"dig @{resolver_ip} {name} {req.qtype} +time=1 +tries=1 >/dev/null; "
            "done"
        )
    else:
        loop_cmd = (
            f"for i in $(seq 1 {req.count}); do "
            f"dig @{resolver_ip} {name} {req.qtype} +time=1 +tries=1 >/dev/null; "
            f"sleep {sleep_s:.3f}; "
            "done"
        )

    timeout_s = min(60, int((req.count / req.qps) + 10))
    return docker_exec(client_container, loop_cmd, timeout_s=timeout_s)

@app.post("/perf/dnsperf", response_model=DnsperfResponse)
def perf_dnsperf(
    req: DnsperfRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    if req.duration_s < 1 or req.duration_s > MAX_DNSPERF_DURATION:
        raise HTTPException(status_code=400, detail="Invalid duration_s")
    if req.qps < 1 or req.qps > MAX_DNSPERF_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps")
    if req.max_queries < 1 or req.max_queries > MAX_DNSPERF_QUERIES:
        raise HTTPException(status_code=400, detail="Invalid max_queries")
    if req.threads < 1 or req.threads > MAX_DNSPERF_THREADS:
        raise HTTPException(status_code=400, detail="Invalid threads")
    if req.clients < 1 or req.clients > MAX_DNSPERF_CLIENTS:
        raise HTTPException(status_code=400, detail="Invalid clients")

    ensure = ensure_running(PERF_TOOLS_CONTAINER)
    if ensure.exit_code != 0:
        raise HTTPException(status_code=500, detail="perf_tools container not running")

    target_ip = perf_target_ip(req.target)
    queries = sanitize_perf_queries(req.queries)
    query_file = (
        write_perf_queries(PERF_TOOLS_CONTAINER, queries)
        if queries
        else DEFAULT_PERF_QUERY_FILE
    )
    cmd = (
        f"dnsperf -s {target_ip} -d {query_file} -l {req.duration_s} "
        f"-Q {req.qps} -q {req.max_queries} -T {req.threads} -c {req.clients}"
    )
    timeout_s = min(600, max(20, req.duration_s + 20))
    res = docker_exec(PERF_TOOLS_CONTAINER, cmd, timeout_s=timeout_s)
    summary = parse_dnsperf_summary(res.stdout or "")
    if request:
        audit_log(
            request,
            "perf_dnsperf",
            {
                "target": req.target,
                "duration_s": req.duration_s,
                "qps": req.qps,
                "max_queries": req.max_queries,
                "ok": res.ok,
            },
        )
    return DnsperfResponse(
        ok=res.ok,
        target=target_ip,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        summary=summary,
    )

@app.post("/perf/resperf", response_model=ResperfResponse)
def perf_resperf(
    req: ResperfRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    if req.max_qps < 1 or req.max_qps > MAX_RESPERF_MAX_QPS:
        raise HTTPException(status_code=400, detail="Invalid max_qps")
    if req.ramp_qps < 1 or req.ramp_qps > MAX_RESPERF_RAMP_QPS:
        raise HTTPException(status_code=400, detail="Invalid ramp_qps")
    if req.clients < 1 or req.clients > MAX_RESPERF_CLIENTS:
        raise HTTPException(status_code=400, detail="Invalid clients")
    if req.queries_per_step < 1 or req.queries_per_step > MAX_RESPERF_QUERIES:
        raise HTTPException(status_code=400, detail="Invalid queries_per_step")

    ensure = ensure_running(PERF_TOOLS_CONTAINER)
    if ensure.exit_code != 0:
        raise HTTPException(status_code=500, detail="perf_tools container not running")

    target_ip = perf_target_ip(req.target)
    queries = sanitize_perf_queries(req.queries)
    query_file = (
        write_perf_queries(PERF_TOOLS_CONTAINER, queries)
        if queries
        else DEFAULT_PERF_QUERY_FILE
    )
    plot_name = sanitize_plot_name(req.plot_file)
    if not plot_name:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        plot_name = f"resperf_plot_{ts}.txt"
    plot_path = f"/work/captures/{plot_name}"
    cmd = (
        f"resperf -s {target_ip} -d {query_file} -m {req.max_qps} "
        f"-r {req.ramp_qps} -c {req.clients} -q {req.queries_per_step} "
        f"-P {plot_path}"
    )
    res = docker_exec(PERF_TOOLS_CONTAINER, cmd, timeout_s=240)
    if request:
        audit_log(
            request,
            "perf_resperf",
            {
                "target": req.target,
                "max_qps": req.max_qps,
                "ramp_qps": req.ramp_qps,
                "ok": res.ok,
            },
        )
    return ResperfResponse(
        ok=res.ok,
        target=target_ip,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        plot_file=plot_path,
    )

@app.post("/availability/flood", response_model=FloodTestResponse)
def availability_flood(
    req: FloodTestRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    if req.qps_start < 1 or req.qps_start > MAX_FLOOD_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps_start")
    if req.qps_end < 1 or req.qps_end > MAX_FLOOD_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps_end")
    if req.qps_step < 1 or req.qps_step > MAX_FLOOD_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps_step")
    if req.qps_start > req.qps_end:
        raise HTTPException(status_code=400, detail="qps_start must be <= qps_end")
    if req.step_seconds < 5 or req.step_seconds > MAX_FLOOD_STEP_SECONDS:
        raise HTTPException(status_code=400, detail="Invalid step_seconds")
    if req.max_outstanding < 1 or req.max_outstanding > MAX_FLOOD_OUTSTANDING:
        raise HTTPException(status_code=400, detail="Invalid max_outstanding")
    if req.timeout_ms < 200 or req.timeout_ms > 5000:
        raise HTTPException(status_code=400, detail="Invalid timeout_ms")

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]
    client_container = CLIENT_CONTAINER_BY_PROFILE[req.profile]
    steps = list(range(req.qps_start, req.qps_end + 1, req.qps_step))
    if not steps:
        raise HTTPException(status_code=400, detail="No steps to execute")
    if len(steps) > MAX_FLOOD_STEPS:
        raise HTTPException(status_code=400, detail="Too many steps")
    total_seconds = len(steps) * req.step_seconds
    if total_seconds > MAX_FLOOD_TOTAL_SECONDS:
        raise HTTPException(status_code=400, detail="Total test duration too long")

    cpu_streak = 0
    cpu_required = max(1, int((30 + req.step_seconds - 1) // req.step_seconds))
    results: list[FloodStepResult] = []
    stop_reason: Optional[str] = None

    for idx, qps in enumerate(steps, start=1):
        timeout_s = max(0.2, req.timeout_ms / 1000.0)
        script = f"""python - <<'PY'
import json, math, socket, struct, time
from concurrent.futures import ThreadPoolExecutor, wait

SERVER = "{resolver_ip}"
NAME = "{name}"
QTYPE = "{req.qtype}"
QPS = {qps}
DURATION = {req.step_seconds}
MAX_OUT = {req.max_outstanding}
TIMEOUT = {timeout_s}

QTYPE_MAP = {{
    "A": 1, "AAAA": 28, "CAA": 257, "CNAME": 5, "DS": 43, "DNSKEY": 48,
    "MX": 15, "NS": 2, "NSEC": 47, "NSEC3": 50, "NSEC3PARAM": 51,
    "RRSIG": 46, "SOA": 6, "SRV": 33, "TXT": 16, "ANY": 255,
}}

def encode_name(name):
    labels = name.strip().rstrip(".").split(".") if name.strip() else []
    if not labels:
        return b"\\x00"
    out = bytearray()
    for label in labels:
        part = label.encode("ascii", errors="ignore")
        if len(part) > 63:
            part = part[:63]
        out.append(len(part))
        out.extend(part)
    out.append(0)
    return bytes(out)

def build_query(name, qtype):
    qid = int(time.time() * 1000) & 0xFFFF
    flags = 0x0100
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = encode_name(name)
    qtype_id = QTYPE_MAP.get(qtype, 1)
    question = qname + struct.pack("!HH", qtype_id, 1)
    return header + question

def parse_rcode(response):
    if len(response) < 4:
        return None
    return response[3] & 0x0F

def query_once(query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    start = time.perf_counter()
    try:
        sock.sendto(query, (SERVER, 53))
        resp, _ = sock.recvfrom(4096)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return True, elapsed_ms, parse_rcode(resp)
    except socket.timeout:
        return False, None, None
    except Exception:
        return False, None, None
    finally:
        sock.close()

def percentile(values, pct):
    if not values:
        return 0
    values = sorted(values)
    idx = int(math.ceil(pct * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]

query = build_query(NAME, QTYPE)
interval = 1.0 / max(1, QPS)
end_time = time.perf_counter() + DURATION
sent = 0
responses = 0
timeouts = 0
latencies = []
rcode_counts = {{}}

with ThreadPoolExecutor(max_workers=max(1, MAX_OUT)) as ex:
    inflight = set()
    next_send = time.perf_counter()
    while time.perf_counter() < end_time:
        now = time.perf_counter()
        while now >= next_send and len(inflight) < MAX_OUT:
            inflight.add(ex.submit(query_once, query))
            sent += 1
            next_send += interval
        done, inflight = wait(inflight, timeout=0)
        for fut in done:
            ok, elapsed_ms, rcode = fut.result()
            if ok:
                responses += 1
                if elapsed_ms is not None:
                    latencies.append(elapsed_ms)
                if rcode is not None:
                    rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
            else:
                timeouts += 1
        time.sleep(0.001)

    drain_until = time.perf_counter() + min(2.0, TIMEOUT * 2)
    while inflight and time.perf_counter() < drain_until:
        done, inflight = wait(inflight, timeout=0.05)
        for fut in done:
            ok, elapsed_ms, rcode = fut.result()
            if ok:
                responses += 1
                if elapsed_ms is not None:
                    latencies.append(elapsed_ms)
                if rcode is not None:
                    rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
            else:
                timeouts += 1

rcode_map = {{
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}}
rcode_named = {{}}
for key, val in rcode_counts.items():
    rcode_named[rcode_map.get(key, f"RCODE={{key}}")] = val

avg_ms = int(sum(latencies) / len(latencies)) if latencies else 0
p95_ms = int(percentile(latencies, 0.95)) if latencies else 0
max_ms = int(max(latencies)) if latencies else 0
loss_pct = (timeouts / sent * 100.0) if sent else 0.0
result = {{
    "sent": sent,
    "responses": responses,
    "timeouts": timeouts,
    "loss_pct": round(loss_pct, 2),
    "rcode_counts": rcode_named,
    "avg_ms": avg_ms,
    "p95_ms": p95_ms,
    "max_ms": max_ms,
}}
print(json.dumps(result))
PY"""

        exec_timeout = min(180, req.step_seconds + 20)
        exec_result = docker_exec(client_container, script, timeout_s=exec_timeout)
        if not exec_result.ok:
            raise HTTPException(
                status_code=502,
                detail=exec_result.stderr or "Flood step failed",
            )
        raw = (exec_result.stdout or "").strip()
        line = raw.splitlines()[-1] if raw else ""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=502, detail=f"Invalid flood output: {raw[:200]}"
            )

        sent = int(data.get("sent", 0))
        responses = int(data.get("responses", 0))
        timeouts = int(data.get("timeouts", 0))
        loss_pct = float(data.get("loss_pct", 0.0))
        rcode_counts = data.get("rcode_counts", {}) or {}
        avg_ms = int(data.get("avg_ms", 0))
        p95_ms = int(data.get("p95_ms", 0))
        max_ms = int(data.get("max_ms", 0))

        servfail = int(rcode_counts.get("SERVFAIL", 0))
        servfail_pct = (servfail / sent * 100.0) if sent else 0.0
        actual_qps = round((sent / req.step_seconds) if req.step_seconds else 0.0, 2)

        cpu_pct = _resolver_cpu_pct(_resolver_container(req.resolver))
        if req.stop_cpu_pct > 0 and cpu_pct is not None and cpu_pct >= req.stop_cpu_pct:
            cpu_streak += 1
        else:
            cpu_streak = 0

        step_stop_reason = None
        if req.stop_loss_pct > 0 and loss_pct > req.stop_loss_pct:
            step_stop_reason = f"loss {loss_pct:.2f}% > {req.stop_loss_pct:.2f}%"
        elif req.stop_p95_ms > 0 and p95_ms > req.stop_p95_ms:
            step_stop_reason = f"p95 {p95_ms} ms > {req.stop_p95_ms} ms"
        elif req.stop_servfail_pct > 0 and servfail_pct > req.stop_servfail_pct:
            step_stop_reason = (
                f"SERVFAIL {servfail_pct:.2f}% > {req.stop_servfail_pct:.2f}%"
            )
        elif req.stop_cpu_pct > 0 and cpu_pct is not None and cpu_streak >= cpu_required:
            step_stop_reason = f"CPU {cpu_pct:.1f}% >= {req.stop_cpu_pct:.1f}%"

        results.append(
            FloodStepResult(
                step=idx,
                qps=qps,
                actual_qps=actual_qps,
                duration_s=req.step_seconds,
                sent=sent,
                responses=responses,
                timeouts=timeouts,
                loss_pct=loss_pct,
                rcode_counts=rcode_counts,
                avg_ms=avg_ms,
                p95_ms=p95_ms,
                max_ms=max_ms,
                servfail_pct=round(servfail_pct, 2),
                cpu_pct=cpu_pct,
                stop_reason=step_stop_reason,
            )
        )

        if step_stop_reason:
            stop_reason = step_stop_reason
            break

    if request:
        audit_log(
            request,
            "availability_flood",
            {
                "profile": req.profile,
                "resolver": req.resolver,
                "name": name,
                "qtype": req.qtype,
                "steps": len(results),
                "stopped_early": stop_reason is not None,
                "stop_reason": stop_reason,
            },
        )

    return FloodTestResponse(
        ok=True,
        target=f"{req.profile}/{req.resolver}@{resolver_ip}",
        name=name,
        qtype=req.qtype,
        steps=results,
        stopped_early=stop_reason is not None,
        stop_reason=stop_reason,
    )

@app.post("/availability/rrl-test", response_model=RrlTestResponse)
def availability_rrl_test(
    req: RrlTestRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    if req.count < 1 or req.count > MAX_RRL_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count")

    name = validate_name(req.name)
    bind_text = _read_text(BIND_CONFIGS[0])
    rrl_block = _extract_rrl_block(bind_text)
    rrl_enabled = bool(rrl_block)

    if not rrl_enabled:
        if request:
            audit_log(
                request,
                "availability_rrl_test",
                {
                    "name": name,
                    "qtype": req.qtype,
                    "count": req.count,
                    "rrl_enabled": False,
                    "matches": 0,
                },
            )
        return RrlTestResponse(
            ok=True,
            rrl_enabled=False,
            config_excerpt="",
            log_excerpt="",
            matches=[],
        )

    script = f"""python - <<'PY'
import socket, struct, time

SERVER = "{AUTH_CHILD_IP}"
NAME = "{name}"
QTYPE = "{req.qtype}"
COUNT = {req.count}

QTYPE_MAP = {{
    "A": 1, "AAAA": 28, "CAA": 257, "CNAME": 5, "DS": 43, "DNSKEY": 48,
    "MX": 15, "NS": 2, "NSEC": 47, "NSEC3": 50, "NSEC3PARAM": 51,
    "RRSIG": 46, "SOA": 6, "SRV": 33, "TXT": 16, "ANY": 255,
}}

def encode_name(name):
    labels = name.strip().rstrip(".").split(".") if name.strip() else []
    if not labels:
        return b"\\x00"
    out = bytearray()
    for label in labels:
        part = label.encode("ascii", errors="ignore")
        if len(part) > 63:
            part = part[:63]
        out.append(len(part))
        out.extend(part)
    out.append(0)
    return bytes(out)

def build_query(name, qtype):
    qid = int(time.time() * 1000) & 0xFFFF
    flags = 0x0100
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = encode_name(name)
    qtype_id = QTYPE_MAP.get(qtype, 1)
    question = qname + struct.pack("!HH", qtype_id, 1)
    return header + question

query = build_query(NAME, QTYPE)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(COUNT):
    sock.sendto(query, (SERVER, 53))
sock.close()
time.sleep(1.0)
print("sent", COUNT)
PY"""
    timeout_s = min(60, max(10, int(req.count / 200) + 10))
    exec_result = docker_exec(TOOLBOX_CONTAINER, script, timeout_s=timeout_s)
    if exec_result.exit_code != 0:
        raise HTTPException(
            status_code=502,
            detail=exec_result.stderr or "RRL test command failed",
        )

    log_tail = max(20, min(req.log_tail, 2000))
    log_text = _tail_bind_log(log_tail)
    pattern = re.compile(r"(rate[- ]limit|rrl|slip|limit)", re.IGNORECASE)
    matches = [line for line in log_text.splitlines() if pattern.search(line)]
    match_excerpt = "\n".join(matches[-20:]) if matches else ""

    if request:
        audit_log(
            request,
            "availability_rrl_test",
            {
                "name": name,
                "qtype": req.qtype,
                "count": req.count,
                "rrl_enabled": rrl_enabled,
                "matches": len(matches),
            },
        )

    return RrlTestResponse(
        ok=True,
        rrl_enabled=rrl_enabled,
        config_excerpt=rrl_block,
        log_excerpt=match_excerpt,
        matches=matches[-20:],
    )

@app.post("/amplification/test", response_model=AmplificationTestResponse)
def amplification_test(
    req: AmplificationTestRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    if req.count_per_qtype < 1 or req.count_per_qtype > MAX_AMP_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count_per_qtype")
    if not req.qtypes:
        raise HTTPException(status_code=400, detail="No qtypes provided")

    for size in req.edns_sizes:
        if size < 512 or size > 4096:
            raise HTTPException(status_code=400, detail="Invalid edns_size")

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]

    results: list[AmplificationResult] = []
    for size in req.edns_sizes:
        for qtype in req.qtypes:
            total_latency: list[float] = []
            udp_sizes: list[int] = []
            tcp_sizes: list[int] = []
            tc_count = 0
            tcp_count = 0
            rcode_counts: dict[str, int] = {}

            for _ in range(req.count_per_qtype):
                try:
                    udp_ms, rcode, udp_size, tc = _udp_query(
                        resolver_ip,
                        name,
                        qtype,
                        edns_size=size,
                        dnssec=req.dnssec,
                    )
                    udp_sizes.append(udp_size)
                    if tc:
                        tc_count += 1
                    tcp_used = False
                    tcp_ms = 0.0
                    tcp_size = 0
                    if tc and req.tcp_fallback:
                        tcp_used = True
                        tcp_count += 1
                        try:
                            tcp_ms, tcp_rcode, tcp_size, _ = _tcp_query(
                                resolver_ip,
                                name,
                                qtype,
                                edns_size=size,
                                dnssec=req.dnssec,
                            )
                            if tcp_rcode:
                                rcode = tcp_rcode
                            tcp_sizes.append(tcp_size)
                        except Exception:
                            rcode = "TCP_FAIL"
                    total_latency.append(udp_ms + (tcp_ms if tcp_used else 0))
                    if rcode:
                        rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
                except socket.timeout:
                    rcode_counts["TIMEOUT"] = rcode_counts.get("TIMEOUT", 0) + 1
                except Exception:
                    rcode_counts["ERROR"] = rcode_counts.get("ERROR", 0) + 1

            count = max(req.count_per_qtype, 1)
            avg_udp = sum(udp_sizes) / count if udp_sizes else 0.0
            avg_tcp = sum(tcp_sizes) / max(len(tcp_sizes), 1) if tcp_sizes else 0.0
            avg_latency = sum(total_latency) / max(len(total_latency), 1)
            results.append(
                AmplificationResult(
                    edns_size=size,
                    qtype=qtype,
                    count=req.count_per_qtype,
                    rcode_counts=rcode_counts,
                    tc_rate=tc_count / count,
                    tcp_rate=tcp_count / count,
                    avg_latency_ms=round(avg_latency, 3),
                    p95_latency_ms=round(_p95(total_latency), 3),
                    avg_udp_size=round(avg_udp, 2),
                    max_udp_size=max(udp_sizes) if udp_sizes else 0,
                    avg_tcp_size=round(avg_tcp, 2),
                    max_tcp_size=max(tcp_sizes) if tcp_sizes else 0,
                )
            )

    return AmplificationTestResponse(
        ok=True,
        target=f"{req.profile}/{req.resolver}@{resolver_ip}",
        name=name,
        results=results,
    )

@app.post("/amplification/mix", response_model=MixLoadResponse)
def amplification_mix(
    req: MixLoadRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    if req.count < 1 or req.count > MAX_MIX_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count")
    if req.edns_size < 512 or req.edns_size > 4096:
        raise HTTPException(status_code=400, detail="Invalid edns_size")

    zone = validate_name(req.zone)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]

    total_latency: list[float] = []
    udp_sizes: list[int] = []
    tcp_sizes: list[int] = []
    tc_count = 0
    tcp_count = 0
    rcode_counts: dict[str, int] = {}
    mix_counts = {"A": 0, "AAAA": 0, "NXDOMAIN": 0, "DNSKEY": 0}

    for i in range(req.count):
        roll = secrets.randbelow(100)
        qtype = "A"
        name = f"www.{zone}"
        if roll < 40:
            qtype = "A"
            mix_counts["A"] += 1
        elif roll < 80:
            qtype = "AAAA"
            mix_counts["AAAA"] += 1
        elif roll < 90:
            qtype = "A"
            name = f"nope-{i}-{secrets.randbelow(9999)}.{zone}"
            mix_counts["NXDOMAIN"] += 1
        else:
            qtype = "DNSKEY"
            name = zone
            mix_counts["DNSKEY"] += 1

        try:
            udp_ms, rcode, udp_size, tc = _udp_query(
                resolver_ip,
                name,
                qtype,
                edns_size=req.edns_size,
                dnssec=req.dnssec,
            )
            udp_sizes.append(udp_size)
            if tc:
                tc_count += 1
            tcp_used = False
            tcp_ms = 0.0
            tcp_size = 0
            if tc and req.tcp_fallback:
                tcp_used = True
                tcp_count += 1
                try:
                    tcp_ms, tcp_rcode, tcp_size, _ = _tcp_query(
                        resolver_ip,
                        name,
                        qtype,
                        edns_size=req.edns_size,
                        dnssec=req.dnssec,
                    )
                    if tcp_rcode:
                        rcode = tcp_rcode
                    tcp_sizes.append(tcp_size)
                except Exception:
                    rcode = "TCP_FAIL"
            total_latency.append(udp_ms + (tcp_ms if tcp_used else 0))
            if rcode:
                rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
        except socket.timeout:
            rcode_counts["TIMEOUT"] = rcode_counts.get("TIMEOUT", 0) + 1
        except Exception:
            rcode_counts["ERROR"] = rcode_counts.get("ERROR", 0) + 1

    count = max(req.count, 1)
    avg_udp = sum(udp_sizes) / count if udp_sizes else 0.0
    avg_tcp = sum(tcp_sizes) / max(len(tcp_sizes), 1) if tcp_sizes else 0.0
    avg_latency = sum(total_latency) / max(len(total_latency), 1)
    return MixLoadResponse(
        ok=True,
        target=f"{req.profile}/{req.resolver}@{resolver_ip}",
        count=req.count,
        edns_size=req.edns_size,
        rcode_counts=rcode_counts,
        query_mix=mix_counts,
        tc_rate=tc_count / count,
        tcp_rate=tcp_count / count,
        avg_latency_ms=round(avg_latency, 3),
        p95_latency_ms=round(_p95(total_latency), 3),
        avg_udp_size=round(avg_udp, 2),
        max_udp_size=max(udp_sizes) if udp_sizes else 0,
        avg_tcp_size=round(avg_tcp, 2),
        max_tcp_size=max(tcp_sizes) if tcp_sizes else 0,
    )

@app.post("/dig", response_model=CmdResponse)
def dig(req: DigRequest, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]

    # safe allow-list: only runs dig with controlled arguments
    args = ["dig", f"@{resolver_ip}", name, req.qtype, "+time=1", "+tries=1"]
    if req.dnssec:
        args.append("+dnssec")
    if req.trace:
        args.append("+trace")
    if req.short:
        args.append("+short")

    return run_cmd(args)

@app.get("/logs/{service}", response_model=CmdResponse)
def logs(
    service: Literal["bind", "unbound"],
    tail: int = 200,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)

    if service == "bind" and AUTH_AGENT_URL:
        data = _agent_request(
            AUTH_AGENT_URL, "/logs", {"scope": "bind", "tail": tail}
        )
        return CmdResponse(**data)
    if service == "unbound" and RESOLVER_AGENT_URL:
        data = _agent_request(
            RESOLVER_AGENT_URL, "/logs", {"scope": "unbound", "tail": tail}
        )
        return CmdResponse(**data)

    base = Path("/logs/bind") if service == "bind" else Path("/logs/unbound")
    candidates = sorted(
        [p for p in base.rglob("*") if p.is_file()],
        key=lambda p: p.stat().st_size,
        reverse=True,
    )
    if not candidates:
        raise HTTPException(status_code=404, detail=f"No log files found under {base}")

    logfile = str(candidates[0])
    tail = max(1, min(tail, 5000))
    return run_cmd(["sh", "-lc", f"tail -n {tail} {logfile}"])

@app.get("/config/list", response_model=ConfigListResponse)
def config_list(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    if AUTH_AGENT_URL or RESOLVER_AGENT_URL:
        files: list[ConfigFile] = []
        if AUTH_AGENT_URL:
            auth = _agent_request(AUTH_AGENT_URL, "/config/list")
            files.extend(ConfigFile(**f) for f in auth.get("files", []))
        if RESOLVER_AGENT_URL:
            res = _agent_request(RESOLVER_AGENT_URL, "/config/list")
            files.extend(ConfigFile(**f) for f in res.get("files", []))
        return ConfigListResponse(ok=True, files=files)
    return ConfigListResponse(ok=True, files=list_config_files())

@app.get("/config/file", response_model=ConfigFileResponse)
def config_file(path: str, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    agent_url = _agent_for_config(path)
    if agent_url:
        data = _agent_request(agent_url, "/config/file", {"path": path})
        return ConfigFileResponse(**data)
    full = resolve_config_path(path)
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    data = full.read_bytes()
    truncated = False
    if len(data) > MAX_CONFIG_BYTES:
        data = data[:MAX_CONFIG_BYTES]
        truncated = True

    content = data.decode("utf-8", errors="replace")
    return ConfigFileResponse(
        ok=True,
        path=path,
        size=full.stat().st_size,
        truncated=truncated,
        content=content,
    )

@app.get("/diagnostics/startup", response_model=StartupDiagnosticsResponse)
def diagnostics_startup(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    issues: list[str] = []
    details: dict[str, str] = {}

    bind_parent_text = ""
    if AUTH_AGENT_URL:
        try:
            data = _agent_request(
                AUTH_AGENT_URL, "/logs", {"scope": "bind_parent", "tail": 200}
            )
            bind_parent_text = data.get("stdout", "")
        except HTTPException as exc:
            details["bind_parent_error"] = f"agent error: {exc.detail}"
    else:
        log = _latest_log_file(Path("/logs/bind_parent"))
        if log:
            bind_parent_text = _tail_file(log, 200)
            details["bind_parent_log"] = str(log)

    conflict_marker = "writeable file '/etc/bind/zones/db.test': already in use"
    if conflict_marker in bind_parent_text:
        issues.append(
            "authoritative_parent failed: db.test is writable in two views. "
            "Use in-view in external view to reference the internal zone."
        )
        details["bind_parent_excerpt"] = bind_parent_text[-1200:]
    elif "loading configuration: failure" in bind_parent_text:
        issues.append("authoritative_parent failed to load config (see bind_parent log)")
        details["bind_parent_excerpt"] = bind_parent_text[-1200:]

    return StartupDiagnosticsResponse(ok=len(issues) == 0, issues=issues, details=details)

@app.post("/maintenance/authoritative/clear-signed", response_model=MaintenanceResponse)
def maintenance_clear_authoritative_signed(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    parent_cmd = "rm -f /etc/bind/zones/db.test.signed /etc/bind/zones/db.test.signed.jnl"
    child_cmd = (
        "rm -f /etc/bind/zones/db.example.test.signed "
        "/etc/bind/zones/db.example.test.signed.jnl "
        "/etc/bind/zones/db.example.test.internal.signed "
        "/etc/bind/zones/db.example.test.internal.signed.jnl"
    )
    removed_parent = docker_exec(SIGNING_PARENT_CONTAINER, parent_cmd)
    removed_child = docker_exec(SIGNING_CHILD_CONTAINER, child_cmd)
    restarted = docker_cmd(
        ["restart", SIGNING_PARENT_CONTAINER, SIGNING_CHILD_CONTAINER], timeout_s=20
    )
    ok = removed_parent.ok and removed_child.ok and restarted.ok
    stdout = "\n".join(
        [
            f"[remove parent]\n{removed_parent.stdout}".strip(),
            f"[remove child]\n{removed_child.stdout}".strip(),
            f"[restart]\n{restarted.stdout}".strip(),
        ]
    ).strip()
    stderr = "\n".join(
        [
            f"[remove parent]\n{removed_parent.stderr}".strip(),
            f"[remove child]\n{removed_child.stderr}".strip(),
            f"[restart]\n{restarted.stderr}".strip(),
        ]
    ).strip()
    if request:
        audit_log(
            request,
            "maintenance_clear_authoritative_signed",
            {"ok": ok},
        )
    return MaintenanceResponse(
        ok=ok,
        command=(
            f"docker exec {SIGNING_PARENT_CONTAINER} {parent_cmd} && "
            f"docker exec {SIGNING_CHILD_CONTAINER} {child_cmd} && "
            f"docker restart {SIGNING_PARENT_CONTAINER} {SIGNING_CHILD_CONTAINER}"
        ),
        exit_code=0 if ok else 1,
        stdout=stdout,
        stderr=stderr,
    )

@app.get("/agent/status", response_model=AgentAggregateResponse)
def agent_status(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    agents: dict[str, dict] = {}
    if AUTH_AGENT_URL:
        agents["authoritative"] = _agent_request(AUTH_AGENT_URL, "/status")
    if RESOLVER_AGENT_URL:
        agents["resolver"] = _agent_request(RESOLVER_AGENT_URL, "/status")
    return AgentAggregateResponse(ok=True, agents=agents)

@app.get("/agent/stats", response_model=AgentAggregateResponse)
def agent_stats(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    agents: dict[str, dict] = {}
    if AUTH_AGENT_URL:
        agents["authoritative"] = _agent_request(AUTH_AGENT_URL, "/stats")
    if RESOLVER_AGENT_URL:
        agents["resolver"] = _agent_request(RESOLVER_AGENT_URL, "/stats")
    return AgentAggregateResponse(ok=True, agents=agents)

@app.get("/nodes", response_model=NodesResponse)
def nodes(x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    nodes_list, errors = _collect_nodes()
    return NodesResponse(ok=len(errors) == 0, nodes=nodes_list, errors=errors)

@app.post("/capture/start", response_model=CaptureStartResponse)
def capture_start(
    req: CaptureStartRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    if req.filter not in CAPTURE_FILTERS:
        raise HTTPException(status_code=400, detail="Invalid filter")

    if capture_running(req.target):
        raise HTTPException(status_code=409, detail=f"{req.target} capture already running")

    container = CAPTURE_TARGETS[req.target]
    check_tcpdump = docker_exec_root(container, "command -v tcpdump >/dev/null 2>&1")
    if check_tcpdump.exit_code != 0:
        raise HTTPException(
            status_code=500,
            detail=f"tcpdump not found in {container}. Rebuild capture-enabled images.",
        )
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{req.target}-{ts}.pcap"
    filter_expr = CAPTURE_FILTERS[req.filter]
    # "any" is safest across Docker network_mode setups where eth0 may not exist.
    iface = "any"
    base_cmd = f"tcpdump -i {iface} -s 0 -U -w /captures/{filename}"
    if filter_expr:
        base_cmd = f"{base_cmd} {filter_expr}"

    pid_path = capture_pid_file(req.target)
    file_path = capture_file_file(req.target)
    log_path = capture_log_file(req.target)
    sh_cmd = (
        f"nohup {base_cmd} >{log_path} 2>&1 & "
        f"echo $! > {pid_path}; "
        f"echo {filename} > {file_path}"
    )
    result = docker_exec_root(container, sh_cmd)
    if result.exit_code != 0:
        raise HTTPException(status_code=500, detail=result.stderr or "Failed to start capture")

    if request:
        audit_log(request, "capture_start", {"target": req.target, "filter": req.filter})

    return CaptureStartResponse(
        ok=True,
        target=req.target,
        file=filename,
        filter=req.filter,
        command=base_cmd,
    )

@app.post("/capture/stop", response_model=CaptureStopResponse)
def capture_stop(
    req: CaptureStopRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    container = CAPTURE_TARGETS[req.target]
    pid_path = capture_pid_file(req.target)
    file_path = capture_file_file(req.target)
    sh_cmd = (
        f"if [ ! -f {pid_path} ]; then exit 2; fi; "
        f"pid=$(cat {pid_path}); "
        f"file=$(cat {file_path} 2>/dev/null || true); "
        f"kill -2 $pid >/dev/null 2>&1 || true; "
        "sleep 2; "
        f"rm -f {pid_path}; "
        "echo $file"
    )
    result = docker_exec_root(container, sh_cmd)
    if result.exit_code == 2:
        raise HTTPException(status_code=404, detail="No running capture")
    if result.exit_code != 0:
        raise HTTPException(status_code=500, detail=result.stderr or "Failed to stop capture")

    filename = result.stdout.strip() or None
    if request:
        audit_log(request, "capture_stop", {"target": req.target, "file": filename})
    return CaptureStopResponse(ok=True, target=req.target, file=filename)

@app.get("/capture/list", response_model=CaptureListResponse)
def capture_list(
    target: Optional[Literal["resolver", "authoritative"]] = None,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    files: list[CaptureFileInfo] = []
    for path in CAPTURE_DIR.glob("*.pcap"):
        name = path.name
        if name.startswith("resolver-"):
            file_target = "resolver"
        elif name.startswith("authoritative-"):
            file_target = "authoritative"
        else:
            continue
        if target and target != file_target:
            continue
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        files.append(
            CaptureFileInfo(
                file=name,
                size=path.stat().st_size,
                mtime=mtime,
                target=file_target,
            )
        )

    files.sort(key=lambda f: f.mtime, reverse=True)
    running = {
        "resolver": capture_running("resolver"),
        "authoritative": capture_running("authoritative"),
    }
    return CaptureListResponse(ok=True, files=files, running=running)

@app.get("/capture/health", response_model=CaptureHealthResponse)
def capture_health(
    target: Literal["resolver", "authoritative"],
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    container = CAPTURE_TARGETS[target]
    pid_path = capture_pid_file(target)
    log_path = capture_log_file(target)
    sh_cmd = (
        f"if [ -f {pid_path} ]; then "
        f"pid=$(cat {pid_path}); "
        f"if [ -n \"$pid\" ] && [ -d /proc/$pid ]; then "
        f"echo RUNNING:$pid; "
        f"else echo NOTRUNNING:$pid; fi; "
        f"else echo NOPID; fi; "
        f"echo LOG; tail -n 5 {log_path} 2>/dev/null"
    )
    result = docker_exec_root(container, sh_cmd)
    stdout = result.stdout.strip()
    running = False
    pid = None
    detail = stdout
    if stdout.startswith("RUNNING:"):
        running = True
        try:
            pid = int(stdout.split(":", 1)[1].splitlines()[0])
        except Exception:
            pid = None
    elif stdout.startswith("NOTRUNNING:"):
        try:
            pid = int(stdout.split(":", 1)[1].splitlines()[0])
        except Exception:
            pid = None
    return CaptureHealthResponse(
        ok=result.ok,
        target=target,
        running=running,
        pid=pid,
        detail=detail,
    )

@app.get("/capture/download")
def capture_download(
    file: str,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    ensure_capture_dir()

    if not file or "/" in file or ".." in file:
        raise HTTPException(status_code=400, detail="Invalid file name")
    full = (CAPTURE_DIR / file).resolve()
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="Capture not found")
    if CAPTURE_DIR not in full.parents:
        raise HTTPException(status_code=403, detail="Path not allowed")

    return FileResponse(
        full,
        filename=file,
        media_type="application/vnd.tcpdump.pcap",
    )

@app.post("/resolver/restart", response_model=ResolverRestartResponse)
def resolver_restart(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    res = docker_cmd(["restart", RESOLVER_CONTAINER], timeout_s=20)
    if request:
        audit_log(request, "resolver_restart", {"ok": res.ok})
    return ResolverRestartResponse(
        ok=res.ok,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/resolver/flush", response_model=ResolverFlushResponse)
def resolver_flush(
    req: ResolverFlushRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    zone = validate_name(req.zone)
    res = docker_exec(
        RESOLVER_CONTAINER,
        f"/opt/unbound/sbin/unbound-control -c /opt/unbound/etc/unbound/unbound.conf "
        f"flush_zone {zone}",
        timeout_s=8,
    )
    if request:
        audit_log(request, "resolver_flush", {"zone": zone, "ok": res.ok})
    return ResolverFlushResponse(
        ok=res.ok,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/privacy/dot-check", response_model=PrivacyCheckResponse)
def privacy_dot_check(
    req: PrivacyCheckRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    name = validate_name(req.name)
    try:
        elapsed_ms, rcode, detail, size = _dot_query(name, req.qtype)
        return PrivacyCheckResponse(
            ok=True,
            kind="dot",
            endpoint=f"{DOT_RESOLVER_IP}:{DOT_RESOLVER_PORT}",
            method="TLS",
            name=name,
            qtype=req.qtype,
            rcode=rcode,
            response_bytes=size,
            elapsed_ms=elapsed_ms,
            detail=detail,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

@app.post("/privacy/doh-check", response_model=PrivacyCheckResponse)
def privacy_doh_check(
    req: PrivacyCheckRequest, x_api_key: Optional[str] = Header(default=None)
):
    require_key(x_api_key)
    name = validate_name(req.name)
    try:
        elapsed_ms, rcode, detail, size = _doh_query(name, req.qtype)
        return PrivacyCheckResponse(
            ok=True,
            kind="doh",
            endpoint=f"https://{DOH_PROXY_HOST}:{DOH_PROXY_PORT}{DOH_PROXY_PATH}",
            method="HTTPS",
            name=name,
            qtype=req.qtype,
            rcode=rcode,
            response_bytes=size,
            elapsed_ms=elapsed_ms,
            detail=detail,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

@app.post("/email/send", response_model=CmdResponse)
def email_send(
    req: EmailSendRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    req.to_addr = validate_email(req.to_addr)
    req.from_addr = validate_email(req.from_addr)
    req.server = validate_host(req.server)
    req.port = validate_port(req.port)

    ensure_running(SWAKS_CONTAINER)
    ensure_running(MAILSERVER_CONTAINER)

    swaks_cmd, swaks_cmd_redacted = _build_swaks_command(req)
    res = docker_exec(SWAKS_CONTAINER, swaks_cmd, timeout_s=20)
    if request:
        audit_log(
            request,
            "email_send",
            {
                "ok": res.ok,
                "to": req.to_addr,
                "from": req.from_addr,
                "server": req.server,
                "port": req.port,
                "tls": req.tls_mode,
            },
        )
    return CmdResponse(
        ok=res.ok,
        command=f"docker exec {SWAKS_CONTAINER} sh -lc {swaks_cmd_redacted}",
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/user/add", response_model=CmdResponse)
def email_user_add(
    req: EmailUserAddRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    email = validate_email(req.email)
    password = (req.password or "").strip()
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")

    ensure_running(MAILSERVER_CONTAINER)

    cmd = f"setup email add {shlex.quote(email)} {shlex.quote(password)}"
    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=20)
    redacted_cmd = f"docker exec {MAILSERVER_CONTAINER} sh -lc {shlex.quote(f'setup email add {email} ****')}"
    if request:
        audit_log(request, "email_user_add", {"ok": res.ok, "email": email})
    return CmdResponse(
        ok=res.ok,
        command=redacted_cmd,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/user/update", response_model=CmdResponse)
def email_user_update(
    req: EmailUserUpdateRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    email = validate_email(req.email)
    password = (req.password or "").strip()
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")

    ensure_running(MAILSERVER_CONTAINER)

    cmd = f"setup email update {shlex.quote(email)} {shlex.quote(password)}"
    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=20)
    redacted_cmd = f"docker exec {MAILSERVER_CONTAINER} sh -lc {shlex.quote(f'setup email update {email} ****')}"
    if request:
        audit_log(request, "email_user_update", {"ok": res.ok, "email": email})
    return CmdResponse(
        ok=res.ok,
        command=redacted_cmd,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/user/delete", response_model=CmdResponse)
def email_user_delete(
    req: EmailUserDeleteRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    email = validate_email(req.email)

    ensure_running(MAILSERVER_CONTAINER)

    cmd = f"setup email del {shlex.quote(email)}"
    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=20)
    redacted_cmd = f"docker exec {MAILSERVER_CONTAINER} sh -lc {shlex.quote(f'setup email del {email}')}"
    if request:
        audit_log(request, "email_user_delete", {"ok": res.ok, "email": email})
    return CmdResponse(
        ok=res.ok,
        command=redacted_cmd,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.get("/email/logs", response_model=EmailLogResponse)
def email_logs(
    tail: int = 200,
    grep: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    tail = max(1, min(tail, MAX_MAIL_LOG_LINES))
    if grep:
        grep = grep.strip()
        if len(grep) > MAX_MAIL_LOG_GREP_CHARS:
            raise HTTPException(status_code=400, detail="Grep filter too long")

    ensure_running(MAILSERVER_CONTAINER)
    log_file = _mail_log_file()
    base_cmd = f"tail -n {tail} {shlex.quote(log_file)}"
    cmd = base_cmd
    if grep:
        cmd = f"{base_cmd} | grep -iF -- {shlex.quote(grep)}"

    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)
    if request:
        audit_log(request, "email_logs", {"ok": res.ok, "grep": grep or ""})
    return EmailLogResponse(
        ok=res.ok,
        file=log_file,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/imap-check", response_model=CmdResponse)
def email_imap_check(
    req: EmailImapCheckRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    user = validate_email(req.user)
    mailbox = validate_mailbox(req.mailbox)
    limit = max(1, min(req.limit, MAX_IMAP_LINES))

    ensure_running(MAILSERVER_CONTAINER)
    fields = "hdr.subject hdr.from hdr.to hdr.date"
    cmd = (
        "tmp=$(mktemp); "
        "doveadm fetch -u {user} '{fields}' mailbox {mailbox} all > \"$tmp\"; "
        "status=$?; "
        "tail -n {limit} \"$tmp\"; "
        "rm -f \"$tmp\"; "
        "exit $status"
    ).format(
        user=shlex.quote(user),
        fields=fields,
        mailbox=shlex.quote(mailbox),
        limit=limit,
    )
    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)
    # Fallback for missing dovecot index files or empty mailbox metadata.
    # doveadm can emit errors on stderr while still returning exit code 0.
    has_error = _doveadm_has_error(res.stderr or "")
    if not res.ok or has_error:
        res = _maildir_headers(user, limit)
    if request:
        audit_log(
            request,
            "email_imap_check",
            {"ok": res.ok, "user": user, "mailbox": mailbox, "limit": limit},
        )
    return CmdResponse(
        ok=res.ok,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/inbox/list", response_model=EmailMessageListResponse)
def email_inbox_list(
    req: EmailMessageListRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    user = validate_email(req.user)
    mailbox = validate_mailbox(req.mailbox)
    limit = max(1, min(req.limit, MAX_IMAP_LINES))

    ensure_running(MAILSERVER_CONTAINER)
    fields = "uid hdr.subject hdr.from hdr.to hdr.date"
    cmd = "doveadm fetch -u {user} '{fields}' mailbox {mailbox} all".format(
        user=shlex.quote(user),
        fields=fields,
        mailbox=shlex.quote(mailbox),
    )
    res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)
    has_error = _doveadm_has_error(res.stderr or "")
    if not res.ok or has_error:
        res = _maildir_list(user, limit)
        messages = _parse_maildir_message_list(res.stdout, mailbox)
    else:
        messages = _parse_doveadm_message_list(res.stdout, mailbox)

    if len(messages) > limit:
        messages = messages[-limit:]

    if request:
        audit_log(
            request,
            "email_inbox_list",
            {"ok": res.ok, "user": user, "mailbox": mailbox, "limit": limit},
        )
    return EmailMessageListResponse(
        ok=res.ok,
        mailbox=mailbox,
        messages=messages,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
    )

@app.post("/email/inbox/view", response_model=EmailMessageViewResponse)
def email_inbox_view(
    req: EmailMessageViewRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    user = validate_email(req.user)
    mailbox = validate_mailbox(req.mailbox)
    message_id = (req.message_id or "").strip()
    source = req.source or "uid"
    max_lines = max(20, min(req.max_lines, MAX_IMAP_LINES))

    ensure_running(MAILSERVER_CONTAINER)
    if source == "file":
        rel = _validate_maildir_rel(message_id)
        local, domain = user.split("@", 1)
        base = f"/var/mail/{domain}/{local}"
        cmd = "sed -n '1,{limit}p' {path}".format(
            limit=max_lines,
            path=shlex.quote(f"{base}/{rel}"),
        )
        res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)
        content = (res.stdout or "").rstrip()
    else:
        if not re.match(r"^\\d+$", message_id):
            raise HTTPException(status_code=400, detail="Invalid message id")
        cmd = "doveadm fetch -u {user} 'text' mailbox {mailbox} uid {uid}".format(
            user=shlex.quote(user),
            mailbox=shlex.quote(mailbox),
            uid=shlex.quote(message_id),
        )
        res = docker_exec_root(MAILSERVER_CONTAINER, cmd, timeout_s=12)
        if _doveadm_has_error(res.stderr or ""):
            res = CmdResponse(
                ok=False,
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )
        content = _clean_doveadm_text(res.stdout)

    if request:
        audit_log(
            request,
            "email_inbox_view",
            {"ok": res.ok, "user": user, "mailbox": mailbox, "source": source},
        )
    return EmailMessageViewResponse(
        ok=res.ok,
        mailbox=mailbox,
        message_id=message_id,
        source=source,
        command=res.command,
        exit_code=res.exit_code,
        stdout=res.stdout,
        stderr=res.stderr,
        content=content,
    )

@app.get("/capture/summary", response_model=CaptureSummaryResponse)
def capture_summary(
    file: str,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    if not file or "/" in file or ".." in file:
        raise HTTPException(status_code=400, detail="Invalid file name")

    full = (CAPTURE_DIR / file).resolve()
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="Capture not found")
    if CAPTURE_DIR not in full.parents:
        raise HTTPException(status_code=403, detail="Path not allowed")

    target = capture_target_from_file(file)
    container = CAPTURE_TARGETS[target]

    total_cmd = f"tcpdump -nn -r /captures/{file} port 53 2>/dev/null | wc -l"
    total = docker_exec_root(container, total_cmd, timeout_s=15)

    if target == "authoritative":
        upstream_cmd = (
            "tcpdump -nn -r /captures/{file} "
            "src {resolver} and dst {auth} and port 53 2>/dev/null | wc -l"
        ).format(file=file, resolver=RESOLVER_CORE_IP, auth=AUTH_CHILD_IP)
    else:
        upstream_cmd = "tcpdump -nn -r /captures/{file} port 53 2>/dev/null | wc -l".format(
            file=file
        )
    upstream = docker_exec_root(container, upstream_cmd, timeout_s=15)

    return CaptureSummaryResponse(
        ok=total.ok and upstream.ok,
        file=file,
        target=target,
        total_packets=parse_count(total.stdout),
        upstream_queries=parse_count(upstream.stdout),
        command_total=total.command,
        command_upstream=upstream.command,
        stdout_total=total.stdout,
        stdout_upstream=upstream.stdout,
        stderr_total=total.stderr,
        stderr_upstream=upstream.stderr,
    )

@app.post("/demo/aggressive-nsec", response_model=DemoAggressiveNsecResponse)
def demo_aggressive_nsec(
    req: DemoAggressiveNsecRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    ensure_demo_dir()

    if req.count < 10 or req.count > MAX_DEMO_NX_COUNT:
        raise HTTPException(status_code=400, detail="Invalid count")
    if req.qps < 1 or req.qps > MAX_DEMO_QPS:
        raise HTTPException(status_code=400, detail="Invalid qps")

    zone = validate_name(req.zone)
    resolver_ip = RESOLVER_BY_PROFILE[req.resolver][req.profile]
    client_container = CLIENT_CONTAINER_BY_PROFILE[req.profile]
    resolver_container = _resolver_container(req.resolver)
    config_path = _unbound_config_path(req.resolver)
    original_text = _read_text(config_path)
    original_cfg = _parse_unbound_config(original_text)
    notes: list[str] = []

    def restart_resolver() -> None:
        res = docker_cmd(["restart", resolver_container], timeout_s=20)
        if res.exit_code != 0:
            raise HTTPException(
                status_code=502, detail=res.stderr or "Failed to restart resolver"
            )
        time.sleep(4)

    def flush_zone() -> None:
        docker_exec(
            resolver_container,
            f"/opt/unbound/sbin/unbound-control -c /opt/unbound/etc/unbound/unbound.conf flush_zone {zone}",
            timeout_s=8,
        )

    def apply_aggressive(enabled: bool) -> bool:
        text = _read_text(config_path)
        cfg = _parse_unbound_config(text)
        if cfg.aggressive_nsec == enabled:
            return False
        cfg.aggressive_nsec = enabled
        _write_text(config_path, _apply_unbound_config(text, cfg))
        restart_resolver()
        return True

    def build_names(count: int) -> list[str]:
        token = secrets.token_hex(3)
        return [f"nx-{token}-{idx}.{zone}" for idx in range(count)]

    def run_phase(enabled: bool) -> DemoAggressiveNsecPhase:
        changed = apply_aggressive(enabled)
        if req.cold_restart:
            if not changed:
                restart_resolver()
        else:
            try:
                flush_zone()
            except HTTPException:
                pass

        stats_before = _extract_unbound_counters(
            _read_unbound_stats(resolver_container)
        )
        names = build_names(req.count)
        first_name = names[0]
        last_name = names[-1]
        middle_names = names[1:-1]

        capture_file: Optional[str] = None
        if req.capture:
            start = capture_start(
                CaptureStartRequest(target=req.capture_target, filter="dns"),
                x_api_key=x_api_key,
                request=request,
            )
            capture_file = start.file

        try:
            dig_first = docker_exec(
                client_container,
                f"dig @{resolver_ip} {first_name} A +time=1 +tries=1 +dnssec",
                timeout_s=8,
            )

            sleep_s = 1.0 / req.qps if req.qps > 0 else 0.0
            sleep_cmd = f"sleep {sleep_s:.3f};" if sleep_s > 0 else ""
            if middle_names:
                names_str = " ".join(middle_names)
                loop_cmd = (
                    f"for name in {names_str}; do "
                    f"dig @{resolver_ip} $name A +time=1 +tries=1 +dnssec >/dev/null; "
                    f"{sleep_cmd} done"
                )
            else:
                loop_cmd = "true"

            timeout_s = max(10, int(len(middle_names) * max(sleep_s, 0.02) + 10))
            loop = docker_exec(client_container, loop_cmd, timeout_s=min(120, timeout_s))

            dig_last = docker_exec(
                client_container,
                f"dig @{resolver_ip} {last_name} A +time=1 +tries=1 +dnssec",
                timeout_s=8,
            )
        finally:
            if req.capture:
                try:
                    stopped = capture_stop(
                        CaptureStopRequest(target=req.capture_target),
                        x_api_key=x_api_key,
                        request=request,
                    )
                    capture_file = stopped.file or capture_file
                except HTTPException as exc:
                    notes.append(f"capture stop failed: {exc.detail}")

        stats_after = _extract_unbound_counters(
            _read_unbound_stats(resolver_container)
        )
        delta = _diff_counters(stats_before, stats_after)

        return DemoAggressiveNsecPhase(
            aggressive_nsec=enabled,
            dig_first=dig_first,
            dig_last=dig_last,
            loop=loop,
            stats_before=stats_before,
            stats_after=stats_after,
            delta=delta,
            capture_file=capture_file,
        )

    phases: list[DemoAggressiveNsecPhase] = []
    ok = True
    try:
        phases.append(run_phase(False))
        phases.append(run_phase(True))
        ok = all(
            phase.loop.ok and phase.dig_first.ok and phase.dig_last.ok
            for phase in phases
        )
    finally:
        if req.restore:
            current_text = _read_text(config_path)
            current_cfg = _parse_unbound_config(current_text)
            if current_cfg.aggressive_nsec != original_cfg.aggressive_nsec:
                _write_text(config_path, original_text)
                try:
                    restart_resolver()
                except HTTPException:
                    notes.append("failed to restore resolver after demo")
                else:
                    notes.append(
                        f"restored aggressive-nsec={original_cfg.aggressive_nsec}"
                    )

    response = DemoAggressiveNsecResponse(
        ok=ok,
        zone=zone,
        count=req.count,
        qps=req.qps,
        profile=req.profile,
        resolver=req.resolver,
        phases=phases,
        notes=notes,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    artifact_name = f"demo-aggressive-nsec-{stamp}.json"
    artifact_path = DEMO_DIR / artifact_name
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": req.model_dump(),
        "result": response.model_dump(),
    }
    artifact_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    response.artifact_json = artifact_name

    if req.zip:
        zip_name = f"demo-aggressive-nsec-{stamp}.zip"
        zip_path = DEMO_DIR / zip_name
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(artifact_path, arcname=artifact_name)
            for phase in phases:
                if not phase.capture_file:
                    continue
                pcap_path = (CAPTURE_DIR / phase.capture_file).resolve()
                if CAPTURE_DIR in pcap_path.parents and pcap_path.exists():
                    zf.write(pcap_path, arcname=phase.capture_file)
        response.artifact_zip = zip_name

    if request:
        audit_log(
            request,
            "demo_aggressive_nsec",
            {"ok": ok, "count": req.count, "resolver": req.resolver},
        )

    return response

@app.get("/demo/download")
def demo_download(
    file: str,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
    ensure_demo_dir()
    name = (file or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Missing file")
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid file name")
    full = (DEMO_DIR / name).resolve()
    if DEMO_DIR not in full.parents:
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not full.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    media_type = "application/zip" if name.endswith(".zip") else "application/json"
    return FileResponse(path=full, media_type=media_type, filename=name)

@app.post("/signing/switch", response_model=SigningSwitchResponse)
def signing_switch(
    req: SigningSwitchRequest,
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[SigningStep] = []

    def record(step: str, res: CmdResponse) -> bool:
        steps.append(
            SigningStep(
                step=step,
                ok=res.ok,
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )
        )
        return res.ok

    ok = True

    ok = ok and record(
        "ensure switcher running",
        ensure_running(SIGNING_SWITCHER_CONTAINER),
    )

    if ok:
        ok = ok and record(
            f"apply mode {req.mode}",
            docker_exec(
                SIGNING_SWITCHER_CONTAINER,
                f"sh /switcher/switch_signing.sh {req.mode}",
                timeout_s=120,
            ),
        )

    if ok:
        ok = ok and record(
            "restart authoritative",
            docker_cmd(
                ["restart", SIGNING_PARENT_CONTAINER, SIGNING_CHILD_CONTAINER],
                timeout_s=20,
            ),
        )

    if ok and req.mode == "nsec3":
        ds_changed = False
        ds_res = docker_cmd(["start", "-a", DS_RECOMPUTE_CONTAINER], timeout_s=180)
        ok = ok and record("run ds_recompute", ds_res)
        if ds_res.ok and "Updated DS" in (ds_res.stdout or ""):
            ds_changed = True

        if ok and ds_changed:
            ok = ok and record(
                "re-sign zones after DS update",
                docker_exec(
                    SIGNING_SWITCHER_CONTAINER,
                    "sh /switcher/switch_signing.sh nsec3",
                    timeout_s=120,
                ),
            )
            if ok:
                ok = ok and record(
                    "restart authoritative (post DS update)",
                    docker_cmd(
                        ["restart", SIGNING_PARENT_CONTAINER, SIGNING_CHILD_CONTAINER],
                        timeout_s=20,
                    ),
                )

        if ok:
            ok = ok and record(
                "run anchor_export",
                docker_cmd(["start", "-a", ANCHOR_EXPORT_CONTAINER], timeout_s=180),
            )

        if ok:
            ok = ok and record(
                "restart resolver",
                docker_cmd(["restart", RESOLVER_CONTAINER], timeout_s=20),
            )

    if request:
        audit_log(request, "signing_switch", {"mode": req.mode, "ok": ok})
    return SigningSwitchResponse(ok=ok, mode=req.mode, steps=steps)

@app.post("/runbook/topology", response_model=RunbookResponse)
def runbook_topology(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[RunbookStep] = []
    list_res = docker_cmd(["network", "ls"])
    _record_runbook_step(steps, "list docker networks", list_res)

    names_res = docker_cmd(["network", "ls", "--format", "{{.Name}}"])
    network_names = (
        [line.strip() for line in names_res.stdout.splitlines() if line.strip()]
        if names_res.ok
        else []
    )
    network_suffixes = ["client_net", "untrusted_net", "dns_core", "mgmt_net", "public_net"]

    for suffix in network_suffixes:
        name = next(
            (
                candidate
                for candidate in network_names
                if candidate == suffix or candidate.endswith(f"_{suffix}")
            ),
            None,
        )
        inspect_name = name or suffix
        res = docker_cmd(["network", "inspect", inspect_name])
        if not res.ok and not name:
            res = _cmd_failure(
                f"docker network inspect {inspect_name}",
                f"Network not found for suffix: {suffix}",
            )
        _record_runbook_step(steps, f"inspect network {inspect_name}", res)

    ip_format = (
        "{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}"
        "| {{$k}}={{$v.IPAddress}} {{end}}"
    )
    containers = [
        RESOLVER_CONTAINER,
        RESOLVER_PLAIN_CONTAINER,
        SIGNING_PARENT_CONTAINER,
        SIGNING_CHILD_CONTAINER,
        CLIENT_TRUSTED_CONTAINER,
        CLIENT_UNTRUSTED_CONTAINER,
        CLIENT_MGMT_CONTAINER,
        TOOLBOX_CONTAINER,
    ]
    for container in containers:
        res = docker_cmd(["inspect", "-f", ip_format, container])
        _record_runbook_step(steps, f"container IPs: {container}", res)

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_topology", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="topology", steps=steps)

@app.post("/runbook/smoke", response_model=RunbookResponse)
def runbook_smoke(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[RunbookStep] = []
    ok = True

    ok = ok and _record_runbook_step(
        steps,
        "ensure trusted client running",
        ensure_running(CLIENT_TRUSTED_CONTAINER),
    )
    ok = ok and _record_runbook_step(
        steps,
        "ensure untrusted client running",
        ensure_running(CLIENT_UNTRUSTED_CONTAINER),
    )
    ok = ok and _record_runbook_step(
        steps,
        "ensure toolbox running",
        ensure_running(TOOLBOX_CONTAINER),
    )

    if not ok:
        if request:
            audit_log(request, "runbook_smoke", {"ok": False})
        return RunbookResponse(ok=False, runbook="smoke", steps=steps)

    trusted_resolver = RESOLVER_BY_PROFILE["valid"]["trusted"]
    untrusted_resolver = RESOLVER_BY_PROFILE["valid"]["untrusted"]
    plain_resolver = RESOLVER_BY_PROFILE["plain"]["trusted"]

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test A",
    )
    passed = _evaluate_output(res, expect_any=[r"status:\s*NOERROR"])
    _record_runbook_step(steps, "trusted recursion works", res, passed)

    res = docker_exec(
        CLIENT_UNTRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{untrusted_resolver} example.test A",
    )
    passed = _evaluate_output(
        res,
        expect_any=[
            r"status:\s*REFUSED",
            r"connection timed out",
            r"no servers could be reached",
            r"recursion requested but not available",
        ],
        allow_nonzero=True,
    )
    _record_runbook_step(steps, "untrusted recursion is blocked", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_PARENT_IP} test SOA",
    )
    passed = _evaluate_output(
        res,
        expect_any=[r"connection timed out", r"no servers could be reached"],
        allow_nonzero=True,
    )
    _record_runbook_step(steps, "client cannot reach parent authoritative", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_CHILD_IP} example.test SOA",
    )
    passed = _evaluate_output(
        res,
        expect_any=[r"connection timed out", r"no servers could be reached"],
        allow_nonzero=True,
    )
    _record_runbook_step(steps, "client cannot reach child authoritative", res, passed)

    res = docker_exec(
        TOOLBOX_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_PARENT_IP} test SOA",
    )
    passed = _evaluate_output(res, expect_any=[r"status:\s*NOERROR"])
    _record_runbook_step(steps, "toolbox can reach parent authoritative", res, passed)

    res = docker_exec(
        TOOLBOX_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_CHILD_IP} example.test SOA",
    )
    passed = _evaluate_output(res, expect_any=[r"status:\s*NOERROR"])
    _record_runbook_step(steps, "toolbox can reach child authoritative", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test A +dnssec",
    )
    passed = _evaluate_output(res, expect_all=[r"flags:.*\bad\b"])
    _record_runbook_step(steps, "DNSSEC validation sets AD flag", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{plain_resolver} example.test A +dnssec",
    )
    passed = _evaluate_output(
        res,
        expect_all=[r"status:\s*NOERROR"],
        forbid_any=[r"flags:.*\bad\b"],
    )
    _record_runbook_step(steps, "plain resolver does not set AD flag", res, passed)

    res = docker_exec(
        TOOLBOX_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_CHILD_IP} nope1.example.test A +dnssec +multi",
    )
    passed = _evaluate_output(
        res,
        expect_all=[r"status:\s*NXDOMAIN"],
        expect_any=[r"\bNSEC3\b", r"\bNSEC\b"],
    )
    _record_runbook_step(steps, "NSEC/NSEC3 proof from child", res, passed)

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_smoke", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="smoke", steps=steps)

@app.post("/runbook/capture", response_model=RunbookResponse)
def runbook_capture(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()
    ensure_capture_dir()

    steps: list[RunbookStep] = []
    ok = True

    ok = ok and _record_runbook_step(
        steps,
        "ensure trusted client running",
        ensure_running(CLIENT_TRUSTED_CONTAINER),
    )
    ok = ok and _record_runbook_step(
        steps,
        "ensure toolbox running",
        ensure_running(TOOLBOX_CONTAINER),
    )

    if not ok:
        if request:
            audit_log(request, "runbook_capture", {"ok": False})
        return RunbookResponse(ok=False, runbook="capture", steps=steps)

    def record_capture_idle(target: Literal["resolver", "authoritative"]) -> bool:
        try:
            running = capture_running(target)
        except HTTPException as exc:
            res = _cmd_failure(f"capture check {target}", str(exc.detail))
            _record_runbook_step(steps, f"check {target} capture idle", res, False)
            return False
        if running:
            res = _cmd_failure(f"capture check {target}", "capture already running")
            _record_runbook_step(steps, f"check {target} capture idle", res, False)
            return False
        res = CmdResponse(
            ok=True,
            command=f"capture check {target}",
            exit_code=0,
            stdout="idle",
            stderr="",
        )
        _record_runbook_step(steps, f"check {target} capture idle", res, True)
        return True

    resolver_idle = record_capture_idle("resolver")
    authoritative_idle = record_capture_idle("authoritative")
    if not (resolver_idle and authoritative_idle):
        if request:
            audit_log(request, "runbook_capture", {"ok": False})
        return RunbookResponse(ok=False, runbook="capture", steps=steps)

    def start_capture(target: Literal["resolver", "authoritative"]) -> Optional[str]:
        container = CAPTURE_TARGETS[target]
        check_tcpdump = docker_exec_root(
            container, "command -v tcpdump >/dev/null 2>&1"
        )
        if not _record_runbook_step(
            steps, f"check tcpdump in {target}", check_tcpdump
        ):
            return None
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"{target}-{ts}.pcap"
        filter_expr = CAPTURE_FILTERS["dns"]
        iface = "any"
        base_cmd = f"tcpdump -i {iface} -s 0 -U -w /captures/{filename}"
        if filter_expr:
            base_cmd = f"{base_cmd} {filter_expr}"
        pid_path = capture_pid_file(target)
        file_path = capture_file_file(target)
        log_path = capture_log_file(target)
        sh_cmd = (
            f"nohup {base_cmd} >{log_path} 2>&1 & "
            f"echo $! > {pid_path}; "
            f"echo {filename} > {file_path}"
        )
        res = docker_exec_root(container, sh_cmd)
        if not _record_runbook_step(steps, f"start {target} capture", res):
            return None
        return filename

    def stop_capture(
        target: Literal["resolver", "authoritative"], label: str
    ) -> Optional[str]:
        container = CAPTURE_TARGETS[target]
        pid_path = capture_pid_file(target)
        file_path = capture_file_file(target)
        sh_cmd = (
            f"if [ ! -f {pid_path} ]; then exit 2; fi; "
            f"pid=$(cat {pid_path}); "
            f"file=$(cat {file_path} 2>/dev/null || true); "
            f"kill -2 $pid >/dev/null 2>&1 || true; "
            "sleep 2; "
            f"rm -f {pid_path}; "
            "echo $file"
        )
        res = docker_exec_root(container, sh_cmd, timeout_s=12)
        if res.exit_code == 2:
            res = _cmd_failure(f"stop {target} capture", "No running capture")
        _record_runbook_step(steps, label, res)
        filename = res.stdout.strip() if res.ok else ""
        return filename or None

    resolver_file = start_capture("resolver")
    authoritative_file = start_capture("authoritative")

    if not resolver_file or not authoritative_file:
        if resolver_file:
            stop_capture("resolver", "stop resolver capture (cleanup)")
        if authoritative_file:
            stop_capture("authoritative", "stop authoritative capture (cleanup)")
        ok = False
        if request:
            audit_log(request, "runbook_capture", {"ok": False})
        return RunbookResponse(ok=False, runbook="capture", steps=steps)

    trusted_resolver = RESOLVER_BY_PROFILE["valid"]["trusted"]
    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test A",
    )
    passed = _evaluate_output(res, expect_any=[r"status:\s*NOERROR"])
    _record_runbook_step(steps, "generate traffic (trusted query)", res, passed)

    resolver_file = stop_capture("resolver", "stop resolver capture")
    authoritative_file = stop_capture("authoritative", "stop authoritative capture")

    if resolver_file:
        preview = docker_exec_root(
            CAPTURE_TARGETS["resolver"],
            f"tcpdump -nn -r /captures/{resolver_file} port 53 -c 25 2>/dev/null",
            timeout_s=15,
        )
        _record_runbook_step(
            steps, f"preview resolver capture ({resolver_file})", preview
        )
    if authoritative_file:
        preview = docker_exec_root(
            CAPTURE_TARGETS["authoritative"],
            f"tcpdump -nn -r /captures/{authoritative_file} port 53 -c 25 2>/dev/null",
            timeout_s=15,
        )
        _record_runbook_step(
            steps, f"preview authoritative capture ({authoritative_file})", preview
        )

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_capture", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="capture", steps=steps)

@app.post("/runbook/verify", response_model=RunbookResponse)
def runbook_verify(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[RunbookStep] = []
    ok = True

    ok = ok and _record_runbook_step(
        steps,
        "ensure trusted client running",
        ensure_running(CLIENT_TRUSTED_CONTAINER),
    )
    ok = ok and _record_runbook_step(
        steps,
        "ensure toolbox running",
        ensure_running(TOOLBOX_CONTAINER),
    )

    if not ok:
        if request:
            audit_log(request, "runbook_verify", {"ok": False})
        return RunbookResponse(ok=False, runbook="verify", steps=steps)

    res = docker_exec(
        TOOLBOX_CONTAINER,
        f"dig +time=1 +tries=1 @{AUTH_PARENT_IP} example.test DS +dnssec +multi",
    )
    passed = _evaluate_output(
        res,
        expect_all=[r"status:\s*NOERROR"],
        expect_any=[r"\bDS\b"],
    )
    _record_runbook_step(steps, "parent DS record present", res, passed)

    trusted_resolver = RESOLVER_BY_PROFILE["valid"]["trusted"]
    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test A +dnssec",
    )
    passed = _evaluate_output(
        res,
        expect_all=[r"status:\s*NOERROR", r"flags:.*\bad\b"],
    )
    _record_runbook_step(steps, "resolver validates example.test", res, passed)

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_verify", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="verify", steps=steps)

@app.post("/runbook/mail", response_model=RunbookResponse)
def runbook_mail(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[RunbookStep] = []
    ok = True

    ok = ok and _record_runbook_step(
        steps,
        "ensure trusted client running",
        ensure_running(CLIENT_TRUSTED_CONTAINER),
    )

    if not ok:
        if request:
            audit_log(request, "runbook_mail", {"ok": False})
        return RunbookResponse(ok=False, runbook="mail", steps=steps)

    trusted_resolver = RESOLVER_BY_PROFILE["valid"]["trusted"]

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test MX",
    )
    passed = _evaluate_output(
        res,
        expect_all=[r"status:\s*NOERROR"],
        expect_any=[r"\bMX\b", r"mail\.example\.test"],
    )
    _record_runbook_step(steps, "MX record present", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} example.test TXT",
    )
    passed = _evaluate_output(res, expect_any=[r"v=spf1"])
    _record_runbook_step(steps, "SPF record present", res, passed)

    res = docker_exec(
        CLIENT_TRUSTED_CONTAINER,
        f"dig +time=1 +tries=1 @{trusted_resolver} mail._domainkey.example.test TXT",
    )
    passed = _evaluate_output(res, expect_any=[r"DKIM1", r"v=DKIM1"])
    _record_runbook_step(steps, "DKIM record present", res, passed)

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_mail", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="mail", steps=steps)

@app.post("/runbook/dnssec", response_model=RunbookResponse)
def runbook_dnssec(
    x_api_key: Optional[str] = Header(default=None),
    request: Request = None,
):
    require_key(x_api_key)
    require_docker()

    steps: list[RunbookStep] = []
    res = docker_cmd(["start", "-a", DS_RECOMPUTE_CONTAINER], timeout_s=180)
    _record_runbook_step(steps, "run ds_recompute", res)

    res = docker_cmd(["start", "-a", ANCHOR_EXPORT_CONTAINER], timeout_s=180)
    _record_runbook_step(steps, "run anchor_export", res)

    res = docker_cmd(["restart", RESOLVER_CONTAINER], timeout_s=20)
    _record_runbook_step(steps, "restart resolver", res)

    ok = all(step.ok for step in steps)
    if request:
        audit_log(request, "runbook_dnssec", {"ok": ok})
    return RunbookResponse(ok=ok, runbook="dnssec", steps=steps)
