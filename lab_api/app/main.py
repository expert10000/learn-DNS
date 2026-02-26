import os
import re
import subprocess
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="dns-security-lab API", version="1.0")

API_KEY = os.getenv("LAB_API_KEY", "")

# Choose resolver IP by "segment" so Unbound ACLs behave like real clients
RESOLVER_BY_PROFILE = {
    "trusted": "172.32.0.20",    # client_net
    "untrusted": "172.33.0.20",  # untrusted_net
    "mgmt": "172.30.0.20",       # mgmt_net
}

NAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?$"
)

class DigRequest(BaseModel):
    profile: Literal["trusted", "untrusted", "mgmt"] = "trusted"
    name: str = Field(..., examples=["example.org"])
    qtype: Literal["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "DNSKEY", "DS"] = "A"
    dnssec: bool = False
    trace: bool = False
    short: bool = False

class CmdResponse(BaseModel):
    ok: bool
    command: str
    exit_code: int
    stdout: str
    stderr: str

def require_key(x_api_key: Optional[str]):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server missing LAB_API_KEY env")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

def validate_name(name: str) -> str:
    name = name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid DNS name format")
    return name

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

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/dig", response_model=CmdResponse)
def dig(req: DigRequest, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)

    name = validate_name(req.name)
    resolver_ip = RESOLVER_BY_PROFILE[req.profile]

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
