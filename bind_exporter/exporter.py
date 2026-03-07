import http.server
import os
import subprocess
import time
from pathlib import Path

PORT = int(os.getenv("PORT", "9119"))
STATS_FILE = os.getenv("BIND_STATS_FILE", "/var/log/bind/named.stats")
RNDC_BIN = os.getenv("BIND_RNDC_BIN", "rndc")
RNDC_CONFIG = os.getenv("BIND_RNDC_CONF", "/etc/bind/rndc.conf")
RNDC_SERVER = os.getenv("BIND_RNDC_SERVER")
RNDC_PORT = os.getenv("BIND_RNDC_PORT")
SERVER_NAME = os.getenv("BIND_SERVER_NAME", "authoritative")


def _is_number(token: str) -> bool:
    try:
        float(token)
        return True
    except ValueError:
        return False


def _run_rndc_stats():
    cmd = [RNDC_BIN, "-c", RNDC_CONFIG]
    if RNDC_SERVER:
        cmd.extend(["-s", RNDC_SERVER])
    if RNDC_PORT:
        cmd.extend(["-p", RNDC_PORT])
    cmd.append("stats")
    start = time.time()
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
        duration = time.time() - start
        return True, output, duration, ""
    except Exception as exc:
        duration = time.time() - start
        return False, "", duration, str(exc)


def _parse_stats(text: str):
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("++") and line.endswith("++"):
            section = line.strip("+").strip()
            continue
        if line.startswith("++"):
            continue
        if line.startswith("---") or line.startswith("[" ):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = None
        value = None
        if _is_number(parts[0]):
            value = parts[0]
            name = " ".join(parts[1:])
        elif _is_number(parts[-1]):
            value = parts[-1]
            name = " ".join(parts[:-1])
        if name is None or value is None:
            continue
        try:
            num = float(value)
        except ValueError:
            continue
        yield section or "Unknown", name, num


def _render_metrics():
    ok, _, duration, error = _run_rndc_stats()
    lines = []
    lines.append("# HELP bind_exporter_up Whether the last BIND stats scrape succeeded (1) or failed (0).")
    lines.append("# TYPE bind_exporter_up gauge")
    lines.append(f"bind_exporter_up {1 if ok else 0}")
    lines.append("# HELP bind_exporter_scrape_duration_seconds BIND stats scrape duration in seconds.")
    lines.append("# TYPE bind_exporter_scrape_duration_seconds gauge")
    lines.append(f"bind_exporter_scrape_duration_seconds {duration:.6f}")

    if not ok:
        lines.append("# HELP bind_exporter_error 1 if the last scrape failed.")
        lines.append("# TYPE bind_exporter_error gauge")
        lines.append("bind_exporter_error 1")
        lines.append(f"# RNDC error: {error}")
        return "\n".join(lines) + "\n"

    stats_path = Path(STATS_FILE)
    if not stats_path.exists():
        lines.append("# HELP bind_exporter_stats_missing 1 if named.stats was not found.")
        lines.append("# TYPE bind_exporter_stats_missing gauge")
        lines.append("bind_exporter_stats_missing 1")
        return "\n".join(lines) + "\n"

    text = stats_path.read_text(errors="ignore")

    lines.append("# HELP bind_stat BIND statistics extracted from named.stats.")
    lines.append("# TYPE bind_stat gauge")

    for section, name, value in _parse_stats(text):
        section_label = section.replace("\"", "\\\"")
        name_label = name.replace("\"", "\\\"")
        lines.append(
            "bind_stat{server=\"%s\",section=\"%s\",name=\"%s\"} %s"
            % (SERVER_NAME, section_label, name_label, value)
        )

        upper_section = section.upper()
        upper_name = name.upper()
        if "INCOMING REQUEST" in upper_section and upper_name == "QUERY":
            lines.append(
                "bind_queries_total{server=\"%s\"} %s" % (SERVER_NAME, value)
            )
        if "RCODE" in upper_section:
            lines.append(
                "bind_rcode_total{server=\"%s\",rcode=\"%s\"} %s"
                % (SERVER_NAME, upper_name, value)
            )

    return "\n".join(lines) + "\n"


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/metrics", "/"):
            self.send_response(404)
            self.end_headers()
            return

        body = _render_metrics().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def main():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), MetricsHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()