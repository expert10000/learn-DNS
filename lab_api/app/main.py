import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="dns-security-lab API", version="1.0")

API_KEY = os.getenv("LAB_API_KEY", "")

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
CAPTURE_TARGETS = {
    "resolver": os.getenv("CAPTURE_RESOLVER_CONTAINER", "dns_capture_resolver"),
    "authoritative": os.getenv(
        "CAPTURE_AUTHORITATIVE_CONTAINER", "dns_capture_authoritative"
    ),
}
CAPTURE_FILTERS = {
    "dns": "port 53",
    "dns+dot": "port 53 or port 853",
    "all": "",
}

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

def docker_exec(container: str, sh_cmd: str, timeout_s: int = 8) -> CmdResponse:
    return run_cmd(["docker", "exec", container, "sh", "-lc", sh_cmd], timeout_s)

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
    result = docker_exec(container, check_cmd)
    if result.exit_code != 0:
        raise HTTPException(
            status_code=500,
            detail=result.stderr or f"Failed to check capture on {target}",
        )
    if "STALE" in result.stdout:
        docker_exec(container, f"rm -f {pid_path}")
        return False
    return "RUNNING" in result.stdout

def ensure_capture_dir():
    if not CAPTURE_DIR.exists():
        raise HTTPException(status_code=500, detail="Capture directory not mounted")

@app.get("/health")
def health():
    return {"ok": True}

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
    return ConfigListResponse(ok=True, files=list_config_files())

@app.get("/config/file", response_model=ConfigFileResponse)
def config_file(path: str, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
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

@app.post("/capture/start", response_model=CaptureStartResponse)
def capture_start(req: CaptureStartRequest, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    ensure_capture_dir()

    if req.filter not in CAPTURE_FILTERS:
        raise HTTPException(status_code=400, detail="Invalid filter")

    if capture_running(req.target):
        raise HTTPException(status_code=409, detail=f"{req.target} capture already running")

    container = CAPTURE_TARGETS[req.target]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"{req.target}-{ts}.pcap"
    filter_expr = CAPTURE_FILTERS[req.filter]
    base_cmd = f"tcpdump -i any -s 0 -U -w /captures/{filename}"
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
    result = docker_exec(container, sh_cmd)
    if result.exit_code != 0:
        raise HTTPException(status_code=500, detail=result.stderr or "Failed to start capture")

    return CaptureStartResponse(
        ok=True,
        target=req.target,
        file=filename,
        filter=req.filter,
        command=base_cmd,
    )

@app.post("/capture/stop", response_model=CaptureStopResponse)
def capture_stop(req: CaptureStopRequest, x_api_key: Optional[str] = Header(default=None)):
    require_key(x_api_key)
    ensure_capture_dir()

    container = CAPTURE_TARGETS[req.target]
    pid_path = capture_pid_file(req.target)
    file_path = capture_file_file(req.target)
    sh_cmd = (
        f"if [ ! -f {pid_path} ]; then exit 2; fi; "
        f"pid=$(cat {pid_path}); "
        f"file=$(cat {file_path} 2>/dev/null || true); "
        f"kill -2 $pid >/dev/null 2>&1 || true; "
        "sleep 1; "
        f"rm -f {pid_path}; "
        "echo $file"
    )
    result = docker_exec(container, sh_cmd)
    if result.exit_code == 2:
        raise HTTPException(status_code=404, detail="No running capture")
    if result.exit_code != 0:
        raise HTTPException(status_code=500, detail=result.stderr or "Failed to stop capture")

    filename = result.stdout.strip() or None
    return CaptureStopResponse(ok=True, target=req.target, file=filename)

@app.get("/capture/list", response_model=CaptureListResponse)
def capture_list(
    target: Optional[Literal["resolver", "authoritative"]] = None,
    x_api_key: Optional[str] = Header(default=None),
):
    require_key(x_api_key)
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
