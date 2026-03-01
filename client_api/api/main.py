import os
import re
import subprocess
import time
import threading
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="dns-client-agent", version="1.0.0")

CLIENT_API_KEY = os.getenv("CLIENT_API_KEY", "")
RATE_LIMIT_PER_MIN = int(os.getenv("CLIENT_RATE_LIMIT_PER_MIN", "120"))
RATE_LIMIT_WINDOW_S = int(os.getenv("CLIENT_RATE_LIMIT_WINDOW_S", "60"))

_rate_lock = threading.Lock()
_rate_hits: dict[str, list[float]] = {}

ALLOWED_QTYPES = {
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT",
    "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "ANY"
}

# allow typical FQDNs like www.example.test. (also allows trailing dot)
NAME_RE = re.compile(r"^(?=.{1,253}\.?$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{1,63}\.?$")

# allow IPv4/IPv6/hostnames (basic sanity, not full RFC)
SERVER_RE = re.compile(r"^[A-Za-z0-9\.\-:]+$")

def _client_ip(request: Request) -> str:
    return (
        request.headers.get("x-real-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

def _rate_limit_check(request: Request) -> Optional[JSONResponse]:
    if RATE_LIMIT_PER_MIN <= 0:
        return None
    path = request.url.path
    if path in ("/health", "/openapi.json") or path.startswith("/docs"):
        return None
    now = time.time()
    key = _client_ip(request)
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

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    blocked = _rate_limit_check(request)
    if blocked:
        return blocked
    return await call_next(request)

def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    return parts[1].strip()

def require_client_key(x_api_key: Optional[str], authorization: Optional[str]):
    if not CLIENT_API_KEY:
        return
    bearer = _extract_bearer(authorization)
    if x_api_key != CLIENT_API_KEY and bearer != CLIENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _parse_ad_flag(dig_output: str) -> bool:
    # dig header line looks like: ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, ..."
    for line in dig_output.splitlines():
        if ";; flags:" in line:
            # get portion between "flags:" and ";"
            try:
                flags_part = line.split(";; flags:", 1)[1]
                flags_part = flags_part.split(";", 1)[0]
                flags = {f.strip() for f in flags_part.strip().split()}
                return "ad" in flags
            except Exception:
                return False
    return False


def _run_cmd(cmd: List[str], timeout_s: int) -> str:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timed out")

    # dig returns non-zero sometimes even with partial output; keep output for debugging
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    return out.strip()


class DigRequest(BaseModel):
    server: Optional[str] = Field(
        default=None,
        description="DNS server to query (IP/hostname). If omitted, uses DEFAULT_DNS_SERVER env if set."
    )
    name: str = Field(..., description="FQDN to query, e.g. www.example.test")
    qtype: str = Field(default="A", description="Record type, e.g. A, AAAA, DNSKEY")
    dnssec: bool = Field(default=True, description="Add +dnssec")
    trace: bool = Field(default=False, description="Add +trace")
    short: bool = Field(default=False, description="Add +short")
    time: int = Field(default=1, ge=1, le=30, description="dig +time")
    tries: int = Field(default=1, ge=1, le=10, description="dig +tries")
    timeout_s: int = Field(default=5, ge=1, le=60, description="process timeout")


class DigResponse(BaseModel):
    ok: bool
    ad: bool
    cmd: List[str]
    output: str


@app.get("/health")
def health() -> Dict[str, Any]:
    profile = os.getenv("PROFILE", "unknown")
    default_server = os.getenv("DEFAULT_DNS_SERVER", "")
    return {
        "ok": True,
        "profile": profile,
        "default_dns_server": default_server,
    }


@app.post("/dig", response_model=DigResponse)
def run_dig(
    req: DigRequest,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> DigResponse:
    require_client_key(x_api_key, authorization)
    qtype = req.qtype.upper().strip()
    if qtype not in ALLOWED_QTYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported qtype: {qtype}")

    name = req.name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail=f"Invalid name: {name}")

    server = (req.server or os.getenv("DEFAULT_DNS_SERVER", "")).strip()
    if server:
        if not SERVER_RE.match(server):
            raise HTTPException(status_code=400, detail=f"Invalid server: {server}")

    cmd: List[str] = ["dig"]
    if server:
        cmd.append(f"@{server}")

    cmd += [name, qtype, f"+time={req.time}", f"+tries={req.tries}"]

    if req.dnssec:
        cmd.append("+dnssec")
    if req.trace:
        cmd.append("+trace")
    if req.short:
        cmd.append("+short")

    output = _run_cmd(cmd, timeout_s=req.timeout_s)
    ad = _parse_ad_flag(output)

    return DigResponse(ok=True, ad=ad, cmd=cmd, output=output)
