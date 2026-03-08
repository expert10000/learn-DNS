#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import asyncio
import random
import string
import time

import dns.asyncresolver
import dns.exception
import dns.resolver


def _normalize_zone(zone: str) -> str:
    zone = zone.strip()
    if zone.endswith("."):
        zone = zone[:-1]
    return zone


def _random_label(length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _build_qname(mode: str, zone: str, valid_labels: list[str], nxdomain_ratio: float) -> str:
    if mode == "nxdomain":
        return f"{_random_label(12)}.{zone}"
    if mode == "valid":
        return f"{random.choice(valid_labels)}.{zone}"
    # mix
    if random.random() < nxdomain_ratio:
        return f"{_random_label(12)}.{zone}"
    return f"{random.choice(valid_labels)}.{zone}"


async def _query_once(
    resolver: dns.asyncresolver.Resolver,
    qname: str,
    qtype: str,
    timeout_s: float,
    sem: asyncio.Semaphore,
    stats: dict[str, int],
    lock: asyncio.Lock,
) -> None:
    async with sem:
        try:
            await resolver.resolve(qname, qtype, lifetime=timeout_s, raise_on_no_answer=False)
            async with lock:
                stats["success"] += 1
        except dns.resolver.NXDOMAIN:
            async with lock:
                stats["nxdomain"] += 1
        except dns.exception.Timeout:
            async with lock:
                stats["timeout"] += 1
        except Exception:
            async with lock:
                stats["error"] += 1


async def _run_load(args: argparse.Namespace) -> None:
    zone = _normalize_zone(args.zone)
    if not zone:
        raise SystemExit("Zone must be non-empty.")

    valid_labels = [label.strip() for label in args.valid_labels.split(",") if label.strip()]
    if not valid_labels:
        valid_labels = ["www", "mail", "ns1", "ns2", "api"]

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [args.server]
    resolver.port = args.port
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    sem = asyncio.Semaphore(args.max_inflight)
    lock = asyncio.Lock()
    stats = {"sent": 0, "success": 0, "nxdomain": 0, "timeout": 0, "error": 0}

    interval = 1.0 / args.qps if args.qps > 0 else 0
    end_time = time.monotonic() + args.duration
    next_fire = time.monotonic()
    tasks: list[asyncio.Task[None]] = []

    while time.monotonic() < end_time:
        now = time.monotonic()
        if interval > 0 and now < next_fire:
            await asyncio.sleep(next_fire - now)
        qname = _build_qname(args.mode, zone, valid_labels, args.nxdomain_ratio)
        task = asyncio.create_task(
            _query_once(resolver, qname, args.qtype, args.timeout, sem, stats, lock)
        )
        tasks.append(task)
        stats["sent"] += 1
        if interval > 0:
            next_fire += interval

    if tasks:
        await asyncio.gather(*tasks)

    elapsed = max(0.001, time.monotonic() - (end_time - args.duration))
    achieved_qps = stats["sent"] / elapsed
    print(f"Elapsed: {elapsed:.2f}s")
    print(
        "Sent: {sent}, Success: {success}, NXDOMAIN: {nxdomain}, "
        "Timeout: {timeout}, Errors: {error}".format(**stats)
    )
    print(f"Achieved QPS: {achieved_qps:.1f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS traffic generator (QPS controlled).")
    parser.add_argument("--server", default="172.32.0.20", help="DNS server IP")
    parser.add_argument("--port", type=int, default=53, help="DNS server port")
    parser.add_argument("--zone", default="example.test", help="Zone to query")
    parser.add_argument("--qtype", default="A", help="Query type (A, AAAA, TXT, ...)")
    parser.add_argument("--duration", type=float, default=10.0, help="Run time in seconds")
    parser.add_argument("--qps", type=float, default=50.0, help="Target queries per second")
    parser.add_argument(
        "--mode",
        choices=["valid", "nxdomain", "mix"],
        default="nxdomain",
        help="Query mode",
    )
    parser.add_argument(
        "--nxdomain-ratio",
        type=float,
        default=0.7,
        help="NXDOMAIN ratio in mix mode (0-1)",
    )
    parser.add_argument(
        "--valid-labels",
        default="www,mail,ns1,ns2,api",
        help="Comma-separated labels for valid queries",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-query timeout (s)")
    parser.add_argument("--max-inflight", type=int, default=200, help="Max concurrent queries")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")

    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    asyncio.run(_run_load(args))


if __name__ == "__main__":
    main()
