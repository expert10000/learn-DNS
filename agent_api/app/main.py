import os
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="dns-lab agent", version="1.0")

AGENT_ROLE = os.getenv("AGENT_ROLE", "unknown")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
AGENT_VERSION = os.getenv("AGENT_VERSION", app.version)
AGENT_NODE_IP = os.getenv("AGENT_NODE_IP", "")
MAX_CONFIG_BYTES = int(os.getenv("AGENT_MAX_CONFIG_BYTES", "200000"))
STATUS_TIMEOUT_S = float(os.getenv("AGENT_STATUS_TIMEOUT_S", "1.0"))

CONFIG_ROOTS_RAW = os.getenv("AGENT_CONFIG_ROOTS", "")
LOG_DIRS_RAW = os.getenv("AGENT_LOG_DIRS", "")
STATUS_TARGETS_RAW = os.getenv("AGENT_STATUS_TARGETS", "")

def _parse_named_paths(raw: str) -> dict[str, Path]:
    entries: dict[str, Path] = {}
    for chunk in [c.strip() for c in raw.split(",") if c.strip()]:
        if "=" not in chunk:
            continue
        name, path = chunk.split("=", 1)
        entries[name.strip()] = Path(path.strip())
    return entries

CONFIG_ROOTS = _parse_named_paths(CONFIG_ROOTS_RAW)
LOG_DIRS = _parse_named_paths(LOG_DIRS_RAW)

def _parse_targets(raw: str) -> list[dict[str, str]]:
    targets = []
    for chunk in [c.strip() for c in raw.split(",") if c.strip()]:
        if "=" in chunk:
            name, addr = chunk.split("=", 1)
        else:
            name, addr = "target", chunk
        if ":" not in addr:
            continue
        host, port = addr.rsplit(":", 1)
        targets.append(
            {
                "name": name.strip(),
                "host": host.strip(),
                "port": port.strip(),
            }
        )
    return targets

STATUS_TARGETS = _parse_targets(STATUS_TARGETS_RAW)

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

class StatusCheck(BaseModel):
    name: str
    host: str
    port: int
    ok: bool
    latency_ms: Optional[float] = None
    detail: Optional[str] = None

class StatusResponse(BaseModel):
    ok: bool
    role: str
    checks: list[StatusCheck]
    agent: Optional[dict] = None

class StatsResponse(BaseModel):
    ok: bool
    role: str
    config_files: int
    log_files: int
    log_bytes: int
    last_log_mtime: Optional[str]

def require_agent_key(x_agent_key: Optional[str]):
    if AGENT_API_KEY and x_agent_key != AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid agent API key")

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
            return b"\n".join(data.splitlines()[-lines:]).decode("utf-8", errors="replace")
    except Exception:
        return ""

def _list_config_files() -> list[ConfigFile]:
    files: list[ConfigFile] = []
    for prefix, root in CONFIG_ROOTS.items():
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            files.append(ConfigFile(path=f"{prefix}/{rel}", size=path.stat().st_size))
    return sorted(files, key=lambda f: f.path)

def _resolve_config_path(rel_path: str) -> Path:
    for prefix, root in CONFIG_ROOTS.items():
        if rel_path == prefix or rel_path.startswith(prefix + "/"):
            suffix = rel_path[len(prefix) :].lstrip("/")
            full = (root / suffix).resolve()
            if root.resolve() not in full.parents and full != root.resolve():
                raise HTTPException(status_code=400, detail="Invalid path")
            return full
    raise HTTPException(status_code=404, detail="Unknown config prefix")

@app.get("/health")
def health():
    return {"ok": True, "role": AGENT_ROLE}

@app.get("/status", response_model=StatusResponse)
def status(x_agent_key: Optional[str] = Header(default=None)):
    require_agent_key(x_agent_key)
    hostname = socket.gethostname()
    ip = AGENT_NODE_IP
    if not ip:
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = ""
    checks: list[StatusCheck] = []
    all_ok = True
    for target in STATUS_TARGETS:
        host = target["host"]
        port = int(target["port"])
        name = target["name"]
        ok = False
        detail = None
        latency_ms: Optional[float] = None
        try:
            start = datetime.now(timezone.utc)
            with socket.create_connection((host, port), timeout=STATUS_TIMEOUT_S):
                pass
            end = datetime.now(timezone.utc)
            latency_ms = (end - start).total_seconds() * 1000
            ok = True
        except Exception as exc:
            detail = str(exc)
        checks.append(
            StatusCheck(
                name=name,
                host=host,
                port=port,
                ok=ok,
                latency_ms=latency_ms,
                detail=detail,
            )
        )
        if not ok:
            all_ok = False
    return StatusResponse(
        ok=all_ok,
        role=AGENT_ROLE,
        checks=checks,
        agent={
            "role": AGENT_ROLE,
            "version": AGENT_VERSION,
            "hostname": hostname,
            "ip": ip,
        },
    )

@app.get("/stats", response_model=StatsResponse)
def stats(x_agent_key: Optional[str] = Header(default=None)):
    require_agent_key(x_agent_key)
    configs = _list_config_files()
    log_files = 0
    log_bytes = 0
    last_mtime: Optional[float] = None
    for root in LOG_DIRS.values():
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            log_files += 1
            stat = path.stat()
            log_bytes += stat.st_size
            mtime = stat.st_mtime
            if last_mtime is None or mtime > last_mtime:
                last_mtime = mtime
    last_log_mtime = (
        datetime.fromtimestamp(last_mtime, tz=timezone.utc).isoformat()
        if last_mtime is not None
        else None
    )
    return StatsResponse(
        ok=True,
        role=AGENT_ROLE,
        config_files=len(configs),
        log_files=log_files,
        log_bytes=log_bytes,
        last_log_mtime=last_log_mtime,
    )

@app.get("/config/list", response_model=ConfigListResponse)
def config_list(x_agent_key: Optional[str] = Header(default=None)):
    require_agent_key(x_agent_key)
    return ConfigListResponse(ok=True, files=_list_config_files())

@app.get("/config/file", response_model=ConfigFileResponse)
def config_file(path: str, x_agent_key: Optional[str] = Header(default=None)):
    require_agent_key(x_agent_key)
    full = _resolve_config_path(path)
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    data = full.read_bytes()
    truncated = False
    if len(data) > MAX_CONFIG_BYTES:
        data = data[:MAX_CONFIG_BYTES]
        truncated = True
    return ConfigFileResponse(
        ok=True,
        path=path,
        size=full.stat().st_size,
        truncated=truncated,
        content=data.decode("utf-8", errors="replace"),
    )

@app.get("/logs", response_model=CmdResponse)
def logs(
    scope: Optional[str] = None,
    tail: int = 200,
    x_agent_key: Optional[str] = Header(default=None),
):
    require_agent_key(x_agent_key)
    tail = max(1, min(tail, 5000))
    target_dir = None
    if scope and scope in LOG_DIRS:
        target_dir = LOG_DIRS[scope]
    elif LOG_DIRS:
        target_dir = list(LOG_DIRS.values())[0]
    if not target_dir or not target_dir.exists():
        raise HTTPException(status_code=404, detail="Log directory not configured")
    candidates = sorted(
        [p for p in target_dir.rglob("*") if p.is_file()],
        key=lambda p: p.stat().st_size,
        reverse=True,
    )
    if not candidates:
        raise HTTPException(status_code=404, detail="No log files found")
    logfile = candidates[0]
    stdout = _tail_file(logfile, tail)
    return CmdResponse(
        ok=True,
        command=f"tail -n {tail} {logfile}",
        exit_code=0,
        stdout=stdout,
        stderr="",
    )
