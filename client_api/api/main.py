import os
import re
import subprocess
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="dns-client-agent", version="1.0.0")

ALLOWED_QTYPES = {
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT",
    "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "ANY"
}

# allow typical FQDNs like www.example.test. (also allows trailing dot)
NAME_RE = re.compile(r"^(?=.{1,253}\.?$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{1,63}\.?$")

# allow IPv4/IPv6/hostnames (basic sanity, not full RFC)
SERVER_RE = re.compile(r"^[A-Za-z0-9\.\-:]+$")


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
def run_dig(req: DigRequest) -> DigResponse:
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