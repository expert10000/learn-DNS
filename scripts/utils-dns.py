#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# --- deps ---
# pip install scapy dnspython
try:
    from scapy.utils import RawPcapReader  # type: ignore
except Exception as e:
    raise SystemExit(
        "Missing dependency: scapy\n"
        "Install with: pip install scapy\n"
        f"Original error: {e}"
    )

try:
    import dns.message
    import dns.dnssec
    import dns.rdatatype
except Exception as e:
    raise SystemExit(
        "Missing dependency: dnspython\n"
        "Install with: pip install dnspython\n"
        f"Original error: {e}"
    )

# -------------------------
# HARD-CODED DEFAULT PCAP
# -------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP = SCRIPT_DIR / "pcaps" / "authoritative-20260301-190718.pcap"

DNSKEY = dns.rdatatype.DNSKEY
DS = dns.rdatatype.DS
RRSIG = dns.rdatatype.RRSIG
NSEC = dns.rdatatype.NSEC
NSEC3 = dns.rdatatype.NSEC3


# -------------------------
# Data models
# -------------------------
@dataclass(frozen=True)
class DnskeyRow:
    zone: str
    key_tag: int
    role: str
    flags: int
    algorithm: int
    protocol: int
    key_len_bits: Optional[int]
    seen_src: str
    seen_dst: str


@dataclass(frozen=True)
class DsRow:
    owner: str
    key_tag: int
    algorithm: int
    digest_type: int
    digest_hex: str
    seen_src: str
    seen_dst: str


@dataclass(frozen=True)
class RrsigRow:
    owner: str
    type_covered: str
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    key_tag: int
    signer: str
    seen_src: str
    seen_dst: str


@dataclass(frozen=True)
class NsecRow:
    owner: str
    next_name: str
    rrtypes: str
    seen_src: str
    seen_dst: str


@dataclass(frozen=True)
class Nsec3Row:
    owner: str
    hash_alg: int
    flags: int
    iterations: int
    salt_hex: str
    next_hashed_owner: str
    rrtypes: str
    seen_src: str
    seen_dst: str


# -------------------------
# Helpers
# -------------------------
def _classify_key_role(flags: int) -> str:
    # Typical deployment convention:
    # 257 (SEP bit set) -> KSK
    # 256 -> ZSK
    if flags == 257:
        return "KSK"
    if flags == 256:
        return "ZSK"
    return "other"


def _key_len_bits_from_dnskey_rdata(dnskey_rdata) -> Optional[int]:
    # Best-effort: dnspython stores public key bytes as rdata.key for many algorithms
    try:
        key_bytes = dnskey_rdata.key
        return len(key_bytes) * 8
    except Exception:
        return None


def _owner_name(rrset) -> str:
    try:
        return str(rrset.name).rstrip(".")
    except Exception:
        return "?"


def _print_table(headers: List[str], rows: List[List[str]]) -> None:
    if not rows:
        print("(no rows)")
        return

    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(r: List[str]) -> str:
        return " | ".join(r[i].ljust(widths[i]) for i in range(len(headers)))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(fmt_row(r))


def _inet_ntop(version: int, addr_bytes: bytes) -> str:
    try:
        if version == 4:
            return socket.inet_ntop(socket.AF_INET, addr_bytes)
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    except Exception:
        return "?"


def _strip_l2(pkt_bytes: bytes, linktype: int) -> Optional[bytes]:
    """
    Remove L2 header based on common linktypes:
      - 1   : Ethernet (DLT_EN10MB) -> 14 bytes
      - 113 : Linux cooked capture (SLL) -> 16 bytes
      - 276 : Linux cooked capture v2 (SLL2) -> 20 bytes
    Fallback: heuristic search for IPv4/IPv6 header start.
    """
    if linktype == 1 and len(pkt_bytes) >= 14:
        return pkt_bytes[14:]
    if linktype == 113 and len(pkt_bytes) >= 16:
        return pkt_bytes[16:]
    if linktype == 276 and len(pkt_bytes) >= 20:
        return pkt_bytes[20:]

    # Heuristic fallback: find first offset that looks like IPv4 (0x4?) or IPv6 (0x6?)
    for off in (0, 14, 16, 18, 20, 22, 24, 26, 28):
        if len(pkt_bytes) > off:
            v = pkt_bytes[off] >> 4
            if v in (4, 6):
                return pkt_bytes[off:]
    return None


def _parse_ipv4(ip: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    """
    Return (src_ip, dst_ip, proto, l4_offset, l4_payload_bytes)
    """
    if len(ip) < 20:
        return None
    version = ip[0] >> 4
    if version != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None

    proto = ip[9]
    src = _inet_ntop(4, ip[12:16])
    dst = _inet_ntop(4, ip[16:20])

    # NOTE: We ignore IPv4 fragmentation (Wireshark reassembles; code here does not).
    # If you ever see "No DNS found" for big DNSSEC answers, it might be fragments.
    l4 = ip[ihl:]
    return src, dst, proto, ihl, l4


def _parse_ipv6(ip: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    """
    Return (src_ip, dst_ip, next_header, l4_offset, l4_payload_bytes)
    Minimal: handles basic IPv6 header (no extension headers).
    """
    if len(ip) < 40:
        return None
    version = ip[0] >> 4
    if version != 6:
        return None
    next_header = ip[6]
    src = _inet_ntop(6, ip[8:24])
    dst = _inet_ntop(6, ip[24:40])
    l4 = ip[40:]
    return src, dst, next_header, 40, l4


def _iter_dns_wire_from_pcap(pcap_path: Path, debug: bool = False) -> Iterable[Tuple[bytes, str, str]]:
    """
    Yield (dns_wire_bytes, ip_src, ip_dst) for UDP/53 or TCP/53.
    Works for SLL2 pcaps because it reads raw frames and strips L2 header.
    """
    reader = RawPcapReader(str(pcap_path))
    linktype = getattr(reader, "linktype", -1)

    total = 0
    ip_like = 0
    dns_candidates = 0

    try:
        for pkt_bytes, _meta in reader:
            total += 1
            ip_bytes = _strip_l2(pkt_bytes, linktype)
            if not ip_bytes:
                continue

            v = ip_bytes[0] >> 4
            if v not in (4, 6):
                continue
            ip_like += 1

            if v == 4:
                parsed = _parse_ipv4(ip_bytes)
            else:
                parsed = _parse_ipv6(ip_bytes)

            if not parsed:
                continue

            src, dst, proto, _l4off, l4 = parsed

            # UDP
            if proto == 17:
                if len(l4) < 8:
                    continue
                sport = int.from_bytes(l4[0:2], "big")
                dport = int.from_bytes(l4[2:4], "big")
                if sport != 53 and dport != 53:
                    continue
                dns_payload = l4[8:]
                if not dns_payload:
                    continue
                dns_candidates += 1
                yield dns_payload, src, dst
                continue

            # TCP
            if proto == 6:
                if len(l4) < 20:
                    continue
                sport = int.from_bytes(l4[0:2], "big")
                dport = int.from_bytes(l4[2:4], "big")
                if sport != 53 and dport != 53:
                    continue

                data_offset = (l4[12] >> 4) * 4
                if data_offset < 20 or len(l4) < data_offset:
                    continue
                tcp_payload = l4[data_offset:]
                if len(tcp_payload) < 2:
                    continue

                # DNS over TCP may contain multiple length-prefixed messages
                pos = 0
                while pos + 2 <= len(tcp_payload):
                    msg_len = int.from_bytes(tcp_payload[pos:pos + 2], "big")
                    pos += 2
                    if msg_len <= 0 or pos + msg_len > len(tcp_payload):
                        break
                    dns_candidates += 1
                    yield tcp_payload[pos:pos + msg_len], src, dst
                    pos += msg_len
                continue

    finally:
        try:
            reader.close()
        except Exception:
            pass

        if debug:
            print(f"[debug] linktype={linktype} total_frames={total} ip_like={ip_like} dns_candidates={dns_candidates}")


# -------------------------
# Extraction
# -------------------------
def extract_dnssec_from_pcap(pcap_path: Path, debug: bool = False) -> Dict[str, List]:
    dnskeys: List[DnskeyRow] = []
    dss: List[DsRow] = []
    rrsigs: List[RrsigRow] = []
    nsecs: List[NsecRow] = []
    nsec3s: List[Nsec3Row] = []

    for wire, src, dst in _iter_dns_wire_from_pcap(pcap_path, debug=debug):
        try:
            msg = dns.message.from_wire(wire, ignore_trailing=True)
        except Exception:
            continue

        rrsets = []
        rrsets.extend(list(msg.answer))
        rrsets.extend(list(msg.authority))
        rrsets.extend(list(msg.additional))

        for rrset in rrsets:
            owner = _owner_name(rrset)

            # DNSKEY
            if rrset.rdtype == DNSKEY:
                for rdata in rrset:
                    flags = int(getattr(rdata, "flags", -1))
                    protocol = int(getattr(rdata, "protocol", -1))
                    algorithm = int(getattr(rdata, "algorithm", -1))

                    try:
                        key_tag = int(dns.dnssec.key_id(rdata))
                    except Exception:
                        key_tag = -1

                    role = _classify_key_role(flags)
                    key_len_bits = _key_len_bits_from_dnskey_rdata(rdata)

                    dnskeys.append(
                        DnskeyRow(
                            zone=owner,
                            key_tag=key_tag,
                            role=role,
                            flags=flags,
                            algorithm=algorithm,
                            protocol=protocol,
                            key_len_bits=key_len_bits,
                            seen_src=src,
                            seen_dst=dst,
                        )
                    )
                continue

            # DS
            if rrset.rdtype == DS:
                for rdata in rrset:
                    key_tag = int(getattr(rdata, "key_tag", -1))
                    algorithm = int(getattr(rdata, "algorithm", -1))
                    digest_type = int(getattr(rdata, "digest_type", -1))
                    digest_hex = ""
                    try:
                        digest_hex = rdata.digest.hex()
                    except Exception:
                        digest_hex = str(getattr(rdata, "digest", ""))

                    dss.append(
                        DsRow(
                            owner=owner,
                            key_tag=key_tag,
                            algorithm=algorithm,
                            digest_type=digest_type,
                            digest_hex=digest_hex,
                            seen_src=src,
                            seen_dst=dst,
                        )
                    )
                continue

            # RRSIG
            if rrset.rdtype == RRSIG:
                for rdata in rrset:
                    try:
                        type_covered = dns.rdatatype.to_text(int(getattr(rdata, "type_covered", 0)))
                    except Exception:
                        type_covered = str(getattr(rdata, "type_covered", "?"))

                    rrsigs.append(
                        RrsigRow(
                            owner=owner,
                            type_covered=type_covered,
                            algorithm=int(getattr(rdata, "algorithm", -1)),
                            labels=int(getattr(rdata, "labels", -1)),
                            original_ttl=int(getattr(rdata, "original_ttl", -1)),
                            expiration=int(getattr(rdata, "expiration", -1)),
                            inception=int(getattr(rdata, "inception", -1)),
                            key_tag=int(getattr(rdata, "key_tag", -1)),
                            signer=str(getattr(rdata, "signer", "?")).rstrip("."),
                            seen_src=src,
                            seen_dst=dst,
                        )
                    )
                continue

            # NSEC
            if rrset.rdtype == NSEC:
                for rdata in rrset:
                    next_name = str(getattr(rdata, "next", "?")).rstrip(".")
                    rrtypes = ""
                    try:
                        rrtypes = ",".join(dns.rdatatype.to_text(t) for t in rdata.types)
                    except Exception:
                        rrtypes = str(getattr(rdata, "types", ""))

                    nsecs.append(
                        NsecRow(
                            owner=owner,
                            next_name=next_name,
                            rrtypes=rrtypes,
                            seen_src=src,
                            seen_dst=dst,
                        )
                    )
                continue

            # NSEC3
            if rrset.rdtype == NSEC3:
                for rdata in rrset:
                    salt_hex = ""
                    try:
                        salt_hex = rdata.salt.hex() if rdata.salt is not None else ""
                    except Exception:
                        salt_hex = str(getattr(rdata, "salt", ""))

                    rrtypes = ""
                    try:
                        rrtypes = ",".join(dns.rdatatype.to_text(t) for t in rdata.types)
                    except Exception:
                        rrtypes = str(getattr(rdata, "types", ""))

                    next_hashed = ""
                    try:
                        next_hashed = rdata.next.hex()
                    except Exception:
                        next_hashed = str(getattr(rdata, "next", ""))

                    nsec3s.append(
                        Nsec3Row(
                            owner=owner,
                            hash_alg=int(getattr(rdata, "algorithm", -1)),
                            flags=int(getattr(rdata, "flags", -1)),
                            iterations=int(getattr(rdata, "iterations", -1)),
                            salt_hex=salt_hex,
                            next_hashed_owner=next_hashed,
                            rrtypes=rrtypes,
                            seen_src=src,
                            seen_dst=dst,
                        )
                    )
                continue

    # Dedup (same RR can appear many times)
    def dedup(seq):
        seen = set()
        out = []
        for x in seq:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    return {
        "dnskeys": dedup(dnskeys),
        "ds": dedup(dss),
        "rrsig": dedup(rrsigs),
        "nsec": dedup(nsecs),
        "nsec3": dedup(nsec3s),
    }


# -------------------------
# Main
# -------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="PCAP -> DNSSEC artifacts (DNSKEY/DS/RRSIG/NSEC/NSEC3)")
    ap.add_argument(
        "--pcap",
        default=str(DEFAULT_PCAP),
        help=f"Path to PCAP (default hardcoded): {DEFAULT_PCAP}",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Print low-level counters (linktype, frames, candidates).",
    )
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"PCAP not found: {pcap_path}")

    print(f"Reading PCAP: {pcap_path}")
    data = extract_dnssec_from_pcap(pcap_path, debug=args.debug)

    dnskeys: List[DnskeyRow] = data["dnskeys"]
    dss: List[DsRow] = data["ds"]
    rrsigs: List[RrsigRow] = data["rrsig"]
    nsecs: List[NsecRow] = data["nsec"]
    nsec3s: List[Nsec3Row] = data["nsec3"]

    print("\n=== DNSKEY (KSK/ZSK) ===")
    if not dnskeys:
        print("No DNSKEY found.")
        print("Tip: generate traffic: dig +dnssec <zone> DNSKEY @<server>")
    else:
        rows = []
        for r in sorted(dnskeys, key=lambda x: (x.zone, x.role, x.key_tag)):
            rows.append(
                [
                    r.zone,
                    str(r.key_tag),
                    r.role,
                    str(r.flags),
                    str(r.algorithm),
                    str(r.protocol),
                    "" if r.key_len_bits is None else str(r.key_len_bits),
                    f"{r.seen_src}->{r.seen_dst}",
                ]
            )
        _print_table(
            headers=["zone", "key_tag", "role", "flags", "alg", "proto", "key_bits", "seen"],
            rows=rows,
        )

    print("\n=== DS ===")
    if not dss:
        print("No DS found.")
        print("Tip: DS is normally seen in PARENT zone responses (delegation).")
    else:
        rows = []
        for r in sorted(dss, key=lambda x: (x.owner, x.key_tag)):
            rows.append(
                [
                    r.owner,
                    str(r.key_tag),
                    str(r.algorithm),
                    str(r.digest_type),
                    r.digest_hex[:32] + ("..." if len(r.digest_hex) > 32 else ""),
                    f"{r.seen_src}->{r.seen_dst}",
                ]
            )
        _print_table(
            headers=["owner", "key_tag", "alg", "digest_t", "digest_hex", "seen"],
            rows=rows,
        )

    print("\n=== RRSIG ===")
    if not rrsigs:
        print("No RRSIG found.")
        print("Tip: ensure queries include DNSSEC OK (DO=1): dig +dnssec ...")
    else:
        rows = []
        for r in sorted(rrsigs, key=lambda x: (x.owner, x.type_covered, x.key_tag)):
            rows.append(
                [
                    r.owner,
                    r.type_covered,
                    str(r.algorithm),
                    str(r.key_tag),
                    r.signer,
                    str(r.inception),
                    str(r.expiration),
                    f"{r.seen_src}->{r.seen_dst}",
                ]
            )
        _print_table(
            headers=["owner", "covers", "alg", "key_tag", "signer", "inception", "expiration", "seen"],
            rows=rows,
        )

    print("\n=== NSEC ===")
    if not nsecs:
        print("No NSEC found.")
    else:
        rows = []
        for r in sorted(nsecs, key=lambda x: (x.owner, x.next_name)):
            rows.append([r.owner, r.next_name, r.rrtypes, f"{r.seen_src}->{r.seen_dst}"])
        _print_table(headers=["owner", "next", "types", "seen"], rows=rows)

    print("\n=== NSEC3 ===")
    if not nsec3s:
        print("No NSEC3 found.")
    else:
        rows = []
        for r in sorted(nsec3s, key=lambda x: (x.owner, x.iterations)):
            rows.append(
                [
                    r.owner,
                    str(r.hash_alg),
                    str(r.flags),
                    str(r.iterations),
                    r.salt_hex,
                    r.next_hashed_owner[:24] + ("..." if len(r.next_hashed_owner) > 24 else ""),
                    r.rrtypes,
                    f"{r.seen_src}->{r.seen_dst}",
                ]
            )
        _print_table(headers=["owner", "alg", "flags", "iter", "salt", "next_hash", "types", "seen"], rows=rows)


if __name__ == "__main__":
    main()