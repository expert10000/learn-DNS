#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
import sys
import time
from datetime import datetime
from pathlib import Path


def _parse_state(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
    except Exception:
        return {}
    return data


def _parse_state_ts(value: str) -> int:
    token = value.strip().split()[0]
    return int(token) if token.isdigit() else -1


def find_ksk(keys_dir: Path, zone_name: str) -> tuple[Path, str] | None:
    key_prefix = f"K{zone_name}.+013+"
    states = sorted(keys_dir.glob(f"{key_prefix}*.state"))
    best_state: Path | None = None
    best_active = -1

    for state_path in states:
        data = _parse_state(state_path)
        if data.get("KSK") != "yes":
            continue
        if data.get("GoalState") != "omnipresent":
            continue
        active_raw = data.get("Active", "")
        active = _parse_state_ts(active_raw)
        if active < 0:
            continue
        if active > best_active:
            best_active = active
            best_state = state_path

    if not best_state and states:
        best_state = states[0]

    if best_state:
        key_path = best_state.with_suffix(".key")
        if key_path.exists():
            text = key_path.read_text(encoding="utf-8", errors="ignore")
            if " DNSKEY 257 " in text:
                return key_path, text

    candidates: list[tuple[Path, str]] = []
    for path in sorted(keys_dir.glob(f"{key_prefix}*.key")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if " DNSKEY 257 " in text:
            candidates.append((path, text))
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0].stat().st_mtime, reverse=True)
    return candidates[0]


def compute_ds(dnskey_text: str, owner: str) -> tuple[int, int, str]:
    m = re.search(r"DNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z0-9+/=\s]+)", dnskey_text)
    if not m:
        raise ValueError("DNSKEY record not found in key file")
    flags = int(m.group(1))
    proto = int(m.group(2))
    alg = int(m.group(3))
    key_b64 = re.sub(r"\s+", "", m.group(4))
    key = base64.b64decode(key_b64)

    rdata = flags.to_bytes(2, "big") + bytes([proto, alg]) + key
    acc = 0
    for i, b in enumerate(rdata):
        acc += b << 8 if i % 2 == 0 else b
    acc += (acc >> 16) & 0xFFFF
    keytag = acc & 0xFFFF

    labels = owner.rstrip(".").split(".")
    wire = b""
    for lab in labels:
        wire += bytes([len(lab)]) + lab.lower().encode("ascii")
    wire += b"\x00"
    digest = hashlib.sha256(wire + rdata).hexdigest().upper()

    return keytag, alg, digest


def bump_serial(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        old = match.group(1)
        today = datetime.now().strftime("%Y%m%d")
        if old.startswith(today):
            new_serial = str(int(old) + 1)
        else:
            new_serial = f"{today}01"
        return match.group(0).replace(old, new_serial, 1)

    return re.sub(r"(\d+)\s*;\s*serial", repl, text, count=1)


def find_existing_ds(zone_text: str) -> tuple[int, int, int, str] | None:
    m = re.search(
        r"^\s*example\s+IN\s+DS\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f]+)\s*$",
        zone_text,
        re.MULTILINE,
    )
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4).upper()


def update_ds(zone_text: str, keytag: int, alg: int, digest: str) -> str:
    lines = zone_text.splitlines()
    ds_line = f"example  IN DS  {keytag} {alg} 2 {digest}"
    ds_re = re.compile(r"^\s*example\s+IN\s+DS\s+")
    for i, line in enumerate(lines):
        if ds_re.match(line):
            lines[i] = ds_line
            return "\n".join(lines) + "\n"

    ns_re = re.compile(r"^\s*example\s+IN\s+NS\s+")
    for i, line in enumerate(lines):
        if ns_re.match(line):
            lines.insert(i + 1, ds_line)
            return "\n".join(lines) + "\n"

    lines.append(ds_line)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute DS for example.test and patch bind9_parent/zones/db.test")
    parser.add_argument("--zone", default="example.test", help="Child zone name (default: example.test)")
    parser.add_argument("--keys-dir", default="bind9/keys", help="Path to child keys dir")
    parser.add_argument("--parent-zone", default="bind9_parent/zones/db.test", help="Path to parent zone file")
    parser.add_argument("--wait", type=int, default=0, help="Wait seconds for child KSK to appear")
    parser.add_argument(
        "--exit-code-on-change",
        action="store_true",
        help="Exit with code 10 when DS changes, 0 when unchanged",
    )
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    parent_zone = Path(args.parent_zone)
    zone_name = args.zone.rstrip(".")

    deadline = time.time() + args.wait if args.wait > 0 else None
    ksk = find_ksk(keys_dir, zone_name)
    while ksk is None and deadline and time.time() < deadline:
        time.sleep(1)
        ksk = find_ksk(keys_dir, zone_name)

    if ksk is None:
        print(f"ERROR: KSK not found in {keys_dir}", file=sys.stderr)
        return 1

    key_path, key_text = ksk
    keytag, alg, digest = compute_ds(key_text, f"{zone_name}.")

    zone_text = parent_zone.read_text(encoding="utf-8")
    zone_text = zone_text.replace("\\n", "\n")

    existing = find_existing_ds(zone_text)
    desired = (keytag, alg, 2, digest)

    if existing == desired:
        print("DS already up to date; no change.")
        return 0

    zone_text = bump_serial(zone_text)
    zone_text = update_ds(zone_text, keytag, alg, digest)
    parent_zone.write_text(zone_text, encoding="utf-8")

    print(f"Updated DS in {parent_zone} using {key_path.name}")
    print(f"DS: {keytag} {alg} 2 {digest}")
    return 10 if args.exit_code_on_change else 0


if __name__ == "__main__":
    raise SystemExit(main())
