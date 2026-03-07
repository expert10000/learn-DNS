import http.server
import os
import subprocess
import time

PORT = int(os.getenv("PORT", "9167"))
CONTROL_CONFIG = os.getenv("UNBOUND_CONTROL_CONFIG", "/opt/unbound/etc/unbound/unbound.conf")
RESOLVER_NAME = os.getenv("UNBOUND_RESOLVER_NAME", "resolver")
CONTROL_BIN = os.getenv("UNBOUND_CONTROL_BIN", "unbound-control")


def _collect_stats():
    cmd = [CONTROL_BIN, "-c", CONTROL_CONFIG, "stats_noreset"]
    start = time.time()
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
        duration = time.time() - start
        return True, output, duration, ""
    except Exception as exc:
        duration = time.time() - start
        return False, "", duration, str(exc)


def _render_metrics():
    ok, output, duration, error = _collect_stats()
    lines = []
    lines.append("# HELP unbound_exporter_up Whether the last Unbound stats scrape succeeded (1) or failed (0).")
    lines.append("# TYPE unbound_exporter_up gauge")
    lines.append(f"unbound_exporter_up {1 if ok else 0}")
    lines.append("# HELP unbound_exporter_scrape_duration_seconds Unbound stats scrape duration in seconds.")
    lines.append("# TYPE unbound_exporter_scrape_duration_seconds gauge")
    lines.append(f"unbound_exporter_scrape_duration_seconds {duration:.6f}")

    if not ok:
        lines.append("# HELP unbound_exporter_error 1 if the last scrape failed.")
        lines.append("# TYPE unbound_exporter_error gauge")
        lines.append("unbound_exporter_error 1")
        lines.append(f"# Unbound control error: {error}")
        return "\n".join(lines) + "\n"

    lines.append("# HELP unbound_stat Unbound statistics from unbound-control stats_noreset.")
    lines.append("# TYPE unbound_stat gauge")

    for raw in output.splitlines():
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        try:
            num = float(value)
        except ValueError:
            continue
        lines.append(
            "unbound_stat{resolver=\"%s\",stat=\"%s\"} %s"
            % (RESOLVER_NAME, key.replace("\"", "\\\""), value)
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