import base64
import os
import socket
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

app = FastAPI(title="doh-proxy", version="1.0.0")

UPSTREAM_DNS = os.getenv("UPSTREAM_DNS", "172.30.0.20")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "53"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "2.0"))
MAX_DNS_MESSAGE = int(os.getenv("MAX_DNS_MESSAGE", "4096"))


def _decode_b64url(value: str) -> bytes:
    value = value.strip()
    if not value:
        raise ValueError("missing dns param")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _udp_exchange(payload: bytes) -> bytes:
    if len(payload) > MAX_DNS_MESSAGE:
        raise HTTPException(status_code=413, detail="DNS message too large")

    last_error: Optional[Exception] = None
    addrinfo = socket.getaddrinfo(
        UPSTREAM_DNS, UPSTREAM_PORT, type=socket.SOCK_DGRAM
    )
    for family, socktype, proto, _, sockaddr in addrinfo:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(UPSTREAM_TIMEOUT)
                sock.sendto(payload, sockaddr)
                data, _ = sock.recvfrom(MAX_DNS_MESSAGE)
                return data
        except OSError as exc:
            last_error = exc
            continue

    raise HTTPException(status_code=502, detail=f"Upstream error: {last_error}")


def _response(payload: bytes) -> Response:
    return Response(
        content=payload,
        media_type="application/dns-message",
        headers={"cache-control": "no-store"},
    )


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "upstream_dns": UPSTREAM_DNS,
        "upstream_port": UPSTREAM_PORT,
    }


@app.get("/dns-query")
async def doh_get(request: Request) -> Response:
    dns_param = request.query_params.get("dns")
    if not dns_param:
        raise HTTPException(status_code=400, detail="Missing dns parameter")

    try:
        payload = _decode_b64url(dns_param)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid dns parameter")

    return _response(_udp_exchange(payload))


@app.post("/dns-query")
async def doh_post(request: Request) -> Response:
    content_type = request.headers.get("content-type", "")
    if "application/dns-message" not in content_type:
        raise HTTPException(status_code=415, detail="Unsupported content type")

    payload = await request.body()
    if not payload:
        raise HTTPException(status_code=400, detail="Empty body")

    return _response(_udp_exchange(payload))
