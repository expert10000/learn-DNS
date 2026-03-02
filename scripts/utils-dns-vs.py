#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# pip install scapy dnspython
from scapy.utils import RawPcapReader  # type: ignore

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.dnssec
import dns.rdatatype


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP = SCRIPT_DIR / "pcaps" / "authoritative-20260301-190718.pcap"

DNSKEY = dns.rdatatype.DNSKEY
DS = dns.rdatatype.DS
RRSIG = dns.rdatatype.RRSIG
NSEC = dns.rdatatype.NSEC
NSEC3 = dns.rdatatype.NSEC3


# -------------------------
# DNSSEC rows (same as before)
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
    if flags == 257:
        return "KSK"
    if flags == 256:
        return "ZSK"
    return "other"


def _key_len_bits_from_dnskey_rdata(dnskey_rdata) -> Optional[int]:
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


def _inet_ntop(version: int, addr_bytes: bytes) -> str:
    try:
        if version == 4:
            return socket.inet_ntop(socket.AF_INET, addr_bytes)
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    except Exception:
        return "?"


def _strip_l2(pkt_bytes: bytes, linktype: int) -> Optional[bytes]:
    # DLT_EN10MB=1, SLL=113, SLL2=276
    if linktype == 1 and len(pkt_bytes) >= 14:
        return pkt_bytes[14:]
    if linktype == 113 and len(pkt_bytes) >= 16:
        return pkt_bytes[16:]
    if linktype == 276 and len(pkt_bytes) >= 20:
        return pkt_bytes[20:]
    # heuristic fallback
    for off in (0, 14, 16, 18, 20, 22, 24, 26, 28):
        if len(pkt_bytes) > off:
            v = pkt_bytes[off] >> 4
            if v in (4, 6):
                return pkt_bytes[off:]
    return None


def _parse_ipv4(ip: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(ip) < 20:
        return None
    if (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    proto = ip[9]
    src = _inet_ntop(4, ip[12:16])
    dst = _inet_ntop(4, ip[16:20])
    return src, dst, proto, ip[ihl:]


def _parse_ipv6(ip: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(ip) < 40:
        return None
    if (ip[0] >> 4) != 6:
        return None
    nxt = ip[6]
    src = _inet_ntop(6, ip[8:24])
    dst = _inet_ntop(6, ip[24:40])
    return src, dst, nxt, ip[40:]


def _ts_to_iso(meta: Any) -> Optional[str]:
    # RawPcapReader metadata often provides sec/usec or seconds/microseconds
    sec = getattr(meta, "sec", None)
    usec = getattr(meta, "usec", None)
    if sec is None:
        sec = getattr(meta, "seconds", None)
    if usec is None:
        usec = getattr(meta, "microseconds", None)
    if sec is None:
        return None
    try:
        base = dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc)
        if usec:
            base = base + dt.timedelta(microseconds=int(usec))
        return base.isoformat()
    except Exception:
        return None


def _dns_rrset_to_dict(rrset) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "name": _owner_name(rrset),
        "ttl": int(getattr(rrset, "ttl", -1)),
        "class": str(getattr(rrset, "rdclass", "")),
        "type": dns.rdatatype.to_text(int(getattr(rrset, "rdtype", 0))),
        "rdatas": [],
    }

    for rdata in rrset:
        t = rrset.rdtype
        r: Dict[str, Any] = {"text": rdata.to_text()}

        if t == DNSKEY:
            r["flags"] = int(getattr(rdata, "flags", -1))
            r["protocol"] = int(getattr(rdata, "protocol", -1))
            r["algorithm"] = int(getattr(rdata, "algorithm", -1))
            try:
                r["key_tag"] = int(dns.dnssec.key_id(rdata))
            except Exception:
                r["key_tag"] = -1

        elif t == DS:
            r["key_tag"] = int(getattr(rdata, "key_tag", -1))
            r["algorithm"] = int(getattr(rdata, "algorithm", -1))
            r["digest_type"] = int(getattr(rdata, "digest_type", -1))
            try:
                r["digest_hex"] = rdata.digest.hex()
            except Exception:
                r["digest_hex"] = str(getattr(rdata, "digest", ""))

        elif t == RRSIG:
            r["type_covered"] = dns.rdatatype.to_text(int(getattr(rdata, "type_covered", 0)))
            r["algorithm"] = int(getattr(rdata, "algorithm", -1))
            r["labels"] = int(getattr(rdata, "labels", -1))
            r["original_ttl"] = int(getattr(rdata, "original_ttl", -1))
            r["expiration"] = int(getattr(rdata, "expiration", -1))
            r["inception"] = int(getattr(rdata, "inception", -1))
            r["key_tag"] = int(getattr(rdata, "key_tag", -1))
            r["signer"] = str(getattr(rdata, "signer", "?")).rstrip(".")

        elif t == NSEC:
            r["next_name"] = str(getattr(rdata, "next", "?")).rstrip(".")
            try:
                r["types"] = [dns.rdatatype.to_text(x) for x in rdata.types]
            except Exception:
                r["types"] = []

        elif t == NSEC3:
            r["hash_alg"] = int(getattr(rdata, "algorithm", -1))
            r["flags"] = int(getattr(rdata, "flags", -1))
            r["iterations"] = int(getattr(rdata, "iterations", -1))
            try:
                r["salt_hex"] = rdata.salt.hex() if rdata.salt is not None else ""
            except Exception:
                r["salt_hex"] = ""
            try:
                r["next_hex"] = rdata.next.hex()
            except Exception:
                r["next_hex"] = ""
            try:
                r["types"] = [dns.rdatatype.to_text(x) for x in rdata.types]
            except Exception:
                r["types"] = []

        out["rdatas"].append(r)

    return out


def _iter_dns_wire_from_pcap(pcap_path: Path) -> Iterable[Tuple[bytes, str, str, str, Optional[str]]]:
    """
    Yield (dns_wire_bytes, ip_src, ip_dst, transport, timestamp_iso)
    Robust for SLL2: reads raw frames and strips L2.
    """
    reader = RawPcapReader(str(pcap_path))
    linktype = getattr(reader, "linktype", -1)

    frame_no = 0
    try:
        for pkt_bytes, meta in reader:
            frame_no += 1
            ip_bytes = _strip_l2(pkt_bytes, linktype)
            if not ip_bytes:
                continue

            v = ip_bytes[0] >> 4
            if v == 4:
                parsed = _parse_ipv4(ip_bytes)
            elif v == 6:
                parsed = _parse_ipv6(ip_bytes)
            else:
                continue

            if not parsed:
                continue

            src, dst, proto, l4 = parsed
            ts = _ts_to_iso(meta)

            # UDP
            if proto == 17:
                if len(l4) < 8:
                    continue
                sport = int.from_bytes(l4[0:2], "big")
                dport = int.from_bytes(l4[2:4], "big")
                if sport != 53 and dport != 53:
                    continue
                dns_payload = l4[8:]
                if dns_payload:
                    yield dns_payload, src, dst, "UDP", ts
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
                pos = 0
                while pos + 2 <= len(tcp_payload):
                    msg_len = int.from_bytes(tcp_payload[pos:pos + 2], "big")
                    pos += 2
                    if msg_len <= 0 or pos + msg_len > len(tcp_payload):
                        break
                    yield tcp_payload[pos:pos + msg_len], src, dst, "TCP", ts
                    pos += msg_len
                continue

    finally:
        try:
            reader.close()
        except Exception:
            pass


def extract_dnssec(msg: dns.message.Message, src: str, dst: str) -> Dict[str, List]:
    dnskeys: List[DnskeyRow] = []
    dss: List[DsRow] = []
    rrsigs: List[RrsigRow] = []
    nsecs: List[NsecRow] = []
    nsec3s: List[Nsec3Row] = []

    rrsets = []
    rrsets.extend(list(msg.answer))
    rrsets.extend(list(msg.authority))
    rrsets.extend(list(msg.additional))

    for rrset in rrsets:
        owner = _owner_name(rrset)

        if rrset.rdtype == DNSKEY:
            for rdata in rrset:
                flags = int(getattr(rdata, "flags", -1))
                protocol = int(getattr(rdata, "protocol", -1))
                algorithm = int(getattr(rdata, "algorithm", -1))
                try:
                    key_tag = int(dns.dnssec.key_id(rdata))
                except Exception:
                    key_tag = -1
                dnskeys.append(
                    DnskeyRow(
                        zone=owner,
                        key_tag=key_tag,
                        role=_classify_key_role(flags),
                        flags=flags,
                        algorithm=algorithm,
                        protocol=protocol,
                        key_len_bits=_key_len_bits_from_dnskey_rdata(rdata),
                        seen_src=src,
                        seen_dst=dst,
                    )
                )
            continue

        if rrset.rdtype == DS:
            for rdata in rrset:
                digest_hex = ""
                try:
                    digest_hex = rdata.digest.hex()
                except Exception:
                    digest_hex = str(getattr(rdata, "digest", ""))
                dss.append(
                    DsRow(
                        owner=owner,
                        key_tag=int(getattr(rdata, "key_tag", -1)),
                        algorithm=int(getattr(rdata, "algorithm", -1)),
                        digest_type=int(getattr(rdata, "digest_type", -1)),
                        digest_hex=digest_hex,
                        seen_src=src,
                        seen_dst=dst,
                    )
                )
            continue

        if rrset.rdtype == RRSIG:
            for rdata in rrset:
                rrsigs.append(
                    RrsigRow(
                        owner=owner,
                        type_covered=dns.rdatatype.to_text(int(getattr(rdata, "type_covered", 0))),
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

        if rrset.rdtype == NSEC:
            for rdata in rrset:
                rrtypes = ""
                try:
                    rrtypes = ",".join(dns.rdatatype.to_text(t) for t in rdata.types)
                except Exception:
                    rrtypes = ""
                nsecs.append(
                    NsecRow(
                        owner=owner,
                        next_name=str(getattr(rdata, "next", "?")).rstrip("."),
                        rrtypes=rrtypes,
                        seen_src=src,
                        seen_dst=dst,
                    )
                )
            continue

        if rrset.rdtype == NSEC3:
            for rdata in rrset:
                salt_hex = ""
                try:
                    salt_hex = rdata.salt.hex() if rdata.salt is not None else ""
                except Exception:
                    salt_hex = ""
                rrtypes = ""
                try:
                    rrtypes = ",".join(dns.rdatatype.to_text(t) for t in rdata.types)
                except Exception:
                    rrtypes = ""
                next_hashed = ""
                try:
                    next_hashed = rdata.next.hex()
                except Exception:
                    next_hashed = ""
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


def build_report(pcap_path: Path) -> Dict[str, Any]:
    frames: List[Dict[str, Any]] = []
    all_dnskeys: List[DnskeyRow] = []
    all_ds: List[DsRow] = []
    all_rrsig: List[RrsigRow] = []
    all_nsec: List[NsecRow] = []
    all_nsec3: List[Nsec3Row] = []

    frame_idx = 0
    for wire, src, dst, transport, ts in _iter_dns_wire_from_pcap(pcap_path):
        frame_idx += 1
        try:
            msg = dns.message.from_wire(wire, ignore_trailing=True)
        except Exception:
            continue

        # Question summary (first question if present)
        qname = ""
        qtype = ""
        if msg.question:
            try:
                q = msg.question[0]
                qname = _owner_name(q)
                qtype = dns.rdatatype.to_text(int(getattr(q, "rdtype", 0)))
            except Exception:
                pass

        # EDNS summary
        edns_flags_text = ""
        if getattr(msg, "edns", -1) and msg.edns >= 0:
            try:
                edns_flags_text = dns.flags.edns_to_text(getattr(msg, "ednsflags", 0))
            except Exception:
                edns_flags_text = ""

        frame: Dict[str, Any] = {
            "frame_no": frame_idx,
            "timestamp_utc": ts,
            "src": src,
            "dst": dst,
            "transport": transport,
            "dns": {
                "id": msg.id,
                "opcode": dns.opcode.to_text(msg.opcode()),
                "rcode": dns.rcode.to_text(msg.rcode()),
                "flags_text": dns.flags.to_text(msg.flags),
                "qdcount": len(msg.question),
                "ancount_rrsets": len(msg.answer),
                "nscount_rrsets": len(msg.authority),
                "arcount_rrsets": len(msg.additional),
                "edns": {
                    "present": msg.edns >= 0,
                    "version": msg.edns if msg.edns >= 0 else None,
                    "udp_payload": getattr(msg, "payload", None),
                    "edns_flags_text": edns_flags_text,
                },
                "question": [_dns_rrset_to_dict(x) for x in msg.question],
                "answer": [_dns_rrset_to_dict(x) for x in msg.answer],
                "authority": [_dns_rrset_to_dict(x) for x in msg.authority],
                "additional": [_dns_rrset_to_dict(x) for x in msg.additional],
            },
            "summary": {
                "qname": qname,
                "qtype": qtype,
            },
            "raw": {
                "wire_len": len(wire),
                "wire_hex": wire.hex(),
            },
        }

        frames.append(frame)

        dnssec = extract_dnssec(msg, src, dst)
        all_dnskeys.extend(dnssec["dnskeys"])
        all_ds.extend(dnssec["ds"])
        all_rrsig.extend(dnssec["rrsig"])
        all_nsec.extend(dnssec["nsec"])
        all_nsec3.extend(dnssec["nsec3"])

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
        "pcap": str(pcap_path),
        "frames_total": len(frames),
        "frames": frames,
        "dnssec": {
            "dnskeys": [x.__dict__ for x in dedup(all_dnskeys)],
            "ds": [x.__dict__ for x in dedup(all_ds)],
            "rrsig": [x.__dict__ for x in dedup(all_rrsig)],
            "nsec": [x.__dict__ for x in dedup(all_nsec)],
            "nsec3": [x.__dict__ for x in dedup(all_nsec3)],
        },
    }


def _html_table(headers: List[str], rows: List[List[str]]) -> str:
    th = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        tds = "".join(f"<td>{html.escape(c)}</td>" for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


def render_html(report: Dict[str, Any]) -> str:
    dnssec = report["dnssec"]

    def dnskeys_table() -> str:
        rows = []
        for r in sorted(dnssec["dnskeys"], key=lambda x: (x["zone"], x["role"], x["key_tag"])):
            rows.append([
                r["zone"],
                str(r["key_tag"]),
                r["role"],
                str(r["flags"]),
                str(r["algorithm"]),
                str(r["protocol"]),
                "" if r["key_len_bits"] is None else str(r["key_len_bits"]),
                f'{r["seen_src"]}->{r["seen_dst"]}',
            ])
        return _html_table(
            ["zone", "key_tag", "role", "flags", "alg", "proto", "key_bits", "seen"],
            rows or [["(none)", "", "", "", "", "", "", ""]],
        )

    def ds_table() -> str:
        rows = []
        for r in sorted(dnssec["ds"], key=lambda x: (x["owner"], x["key_tag"])):
            dh = r["digest_hex"]
            rows.append([
                r["owner"],
                str(r["key_tag"]),
                str(r["algorithm"]),
                str(r["digest_type"]),
                (dh[:48] + ("..." if len(dh) > 48 else "")),
                f'{r["seen_src"]}->{r["seen_dst"]}',
            ])
        return _html_table(
            ["owner", "key_tag", "alg", "digest_t", "digest_hex", "seen"],
            rows or [["(none)", "", "", "", "", ""]],
        )

    def rrsig_table() -> str:
        rows = []
        for r in sorted(dnssec["rrsig"], key=lambda x: (x["owner"], x["type_covered"], x["key_tag"])):
            rows.append([
                r["owner"],
                r["type_covered"],
                str(r["algorithm"]),
                str(r["key_tag"]),
                r["signer"],
                str(r["inception"]),
                str(r["expiration"]),
                f'{r["seen_src"]}->{r["seen_dst"]}',
            ])
        return _html_table(
            ["owner", "covers", "alg", "key_tag", "signer", "inception", "expiration", "seen"],
            rows or [["(none)", "", "", "", "", "", "", ""]],
        )

    def frames_html() -> str:
        out = []
        for fr in report["frames"]:
            s = fr["summary"]
            dns = fr["dns"]
            title = (
                f'Frame {fr["frame_no"]} | {fr["transport"]} | {fr["src"]} → {fr["dst"]} | '
                f'{s.get("qname","")} {s.get("qtype","")} | '
                f'rcode={dns["rcode"]} | flags={dns["flags_text"]}'
            )

            # small per-frame blocks
            header_tbl = _html_table(
                ["Field", "Value"],
                [
                    ["Transaction ID", hex(dns["id"])],
                    ["Opcode", dns["opcode"]],
                    ["Rcode", dns["rcode"]],
                    ["Flags", dns["flags_text"]],
                    ["QD/AN/NS/AR (rrsets)", f'{dns["qdcount"]}/{dns["ancount_rrsets"]}/{dns["nscount_rrsets"]}/{dns["arcount_rrsets"]}'],
                    ["EDNS", "yes" if dns["edns"]["present"] else "no"],
                    ["EDNS flags", dns["edns"]["edns_flags_text"] or "-"],
                    ["UDP payload (EDNS)", str(dns["edns"]["udp_payload"] or "-")],
                    ["Timestamp (UTC)", fr["timestamp_utc"] or "-"],
                ]
            )

            def section(name: str, rrsets: List[Dict[str, Any]]) -> str:
                if not rrsets:
                    return f"<div class='section'><h4>{name}</h4><div class='muted'>(empty)</div></div>"
                parts = [f"<div class='section'><h4>{name}</h4>"]
                for rr in rrsets:
                    rr_title = f'{rr["name"]}  TTL={rr["ttl"]}  {rr["type"]}  ({len(rr["rdatas"])} rdata)'
                    parts.append("<details class='rrset'>")
                    parts.append(f"<summary>{html.escape(rr_title)}</summary>")
                    rrows = []
                    for rdata in rr["rdatas"]:
                        # show some parsed fields if present + the canonical text
                        extras = []
                        for k in ("flags", "protocol", "algorithm", "key_tag", "digest_type", "digest_hex",
                                  "type_covered", "labels", "original_ttl", "inception", "expiration", "signer",
                                  "next_name", "hash_alg", "iterations", "salt_hex", "next_hex"):
                            if k in rdata:
                                extras.append(f"{k}={rdata[k]}")
                        rrows.append([
                            ", ".join(extras) if extras else "-",
                            rdata.get("text", ""),
                        ])
                    parts.append(_html_table(["parsed", "rdata (text)"], rrows))
                    parts.append("</details>")
                parts.append("</div>")
                return "".join(parts)

            raw_hex = fr["raw"]["wire_hex"]
            raw_hex_pre = html.escape(raw_hex)

            body = (
                header_tbl
                + section("Question", dns["question"])
                + section("Answer", dns["answer"])
                + section("Authority", dns["authority"])
                + section("Additional", dns["additional"])
                + f"<div class='section'><h4>Raw DNS wire (hex)</h4><pre>{raw_hex_pre}</pre></div>"
            )

            out.append(f"<details class='frame'><summary>{html.escape(title)}</summary>{body}</details>")
        return "\n".join(out)

    css = """
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;line-height:1.35;background:#0b1220;color:#e6eefc}
    h1,h2,h3{margin:0 0 12px 0}
    .muted{opacity:.75}
    .card{background:#111b31;border:1px solid #223055;border-radius:12px;padding:14px;margin:12px 0}
    details{background:#0f1830;border:1px solid #223055;border-radius:12px;padding:10px;margin:10px 0}
    summary{cursor:pointer;font-weight:600}
    table{border-collapse:collapse;width:100%;margin:10px 0;font-size:14px}
    th,td{border:1px solid #223055;padding:7px;vertical-align:top}
    th{background:#172445}
    pre{white-space:pre-wrap;word-break:break-all;background:#0b1220;border:1px solid #223055;border-radius:10px;padding:10px}
    .section{margin:12px 0}
    .rrset{margin:8px 0}
    .toolbar{display:flex;gap:10px;align-items:center}
    input{padding:8px 10px;border-radius:10px;border:1px solid #223055;background:#0b1220;color:#e6eefc;width:420px}
    """
    js = """
    function applyFilter(){
      const q = document.getElementById('filter').value.toLowerCase();
      const frames = document.querySelectorAll('details.frame');
      frames.forEach(d=>{
        const txt = d.querySelector('summary').innerText.toLowerCase();
        d.style.display = (txt.includes(q)) ? '' : 'none';
      });
    }
    """

    html_doc = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>DNS/DNSSEC PCAP Report</title>
      <style>{css}</style>
    </head>
    <body>
      <h1>DNS/DNSSEC PCAP Report</h1>
      <div class="muted">PCAP: {html.escape(report["pcap"])} | Frames parsed: {report["frames_total"]}</div>

      <div class="card toolbar">
        <div><strong>Filter frames:</strong></div>
        <input id="filter" oninput="applyFilter()" placeholder="type e.g. example.test, DNSKEY, RRSIG, NXDOMAIN..." />
      </div>

      <div class="card">
        <h2>DNSSEC artifacts (deduplicated)</h2>
        <h3>DNSKEY (KSK/ZSK)</h3>
        {dnskeys_table()}
        <h3>DS</h3>
        {ds_table()}
        <h3>RRSIG</h3>
        {rrsig_table()}
      </div>

      <div class="card">
        <h2>Frames</h2>
        <div class="muted">Click a frame to expand. Inside, click RRsets to expand.</div>
        {frames_html()}
      </div>

      <script>{js}</script>
    </body>
    </html>
    """
    return html_doc


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a visual HTML report (Wireshark-like) from DNS/DNSSEC PCAP.")
    ap.add_argument("--pcap", default=str(DEFAULT_PCAP), help=f"Path to PCAP (default: {DEFAULT_PCAP})")
    ap.add_argument("--out", default="dnssec_report.html", help="Output HTML path")
    ap.add_argument("--json", default="dnssec_report.json", help="Output JSON path (raw parsed data)")
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"PCAP not found: {pcap_path}")

    report = build_report(pcap_path)

    Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(args.out).write_text(render_html(report), encoding="utf-8")

    print(f"Wrote: {args.out}")
    print(f"Wrote: {args.json}")
    print("Open the HTML in a browser for a collapsible packet view.")


if __name__ == "__main__":
    main()