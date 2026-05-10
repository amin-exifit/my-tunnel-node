#!/usr/bin/env python3
"""
rust-exit-node.py — Python re‑implementation of MHR-CFW Exit Worker
(Cloudflare Workers companion to Code.cfw.gs).

This script acts as a relay between Apps Script and the destination
server, handling both single and batch HTTP requests. It faithfully
replicates the logic of the Cloudflare Worker, including:

- Auth via PSK (from EXIT_NODE_PSK environment or --psk argument)
- Single request: POST { k, u, m, h, b, ct, r }
- Batch request:  POST { k, q: [ {u, m, h, b, ct, r}, ... ] }
- Loop protection via x-relay-hop header and self‑host check
- Hop‑by‑hop header stripping
- Base64 request/response body conversion
- Redirect handling (r=false → no follow)
- Body‑prohibited method safety (GET/HEAD drop body)
- Parallel batch processing (ThreadPoolExecutor)

Result shape matches the Worker exactly:
  Success: { s: status, h: {...}, b: base64_body }
  Error:   { e: "..." }
"""

import argparse
import base64
import concurrent.futures
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("exit-worker")

# ---------------------------------------------------------------------------
# Constants (kept in sync with the Cloudflare Worker)
# ---------------------------------------------------------------------------
DEFAULT_PSK = "CHANGE_ME_TO_A_STRONG_SECRET"

HEADER_RELAY_HOP = "x-relay-hop"

# Hop‑by‑hop headers stripped from the upstream request.
STRIP_REQUEST_HEADERS = frozenset(
    h.lower()
    for h in (
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        "priority",
        "te",
    )
)

MAX_BATCH_SIZE = 40          # must match WORKER_BATCH_CHUNK in Code.cfw.gs
OUTBOUND_TIMEOUT = 30        # seconds per fetch
MAX_RESPONSE_BODY = 64 * 1024 * 1024   # 64 MiB

# ---------------------------------------------------------------------------
# Global PSK
# ---------------------------------------------------------------------------
PSK = ""

# ---------------------------------------------------------------------------
# Outbound HTTP client
# ---------------------------------------------------------------------------
def _build_no_redirect_opener():
    """Return an opener that does NOT follow redirects."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    # The default HTTPRedirectHandler follows redirects; we omit it.
    return opener

_no_redirect_opener = _build_no_redirect_opener()
_default_opener = urllib.request.build_opener()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clean_headers(raw):
    """Return a dict without hop‑by‑hop headers."""
    if not isinstance(raw, dict):
        return {}
    clean = {}
    for k, v in raw.items():
        if isinstance(k, str) and k.lower() not in STRIP_REQUEST_HEADERS:
            clean[k] = str(v) if v is not None else ""
    return clean


def _fetch_with_redirect_policy(method: str, url: str, headers: dict,
                                body: bytes | None, follow_redirects: bool):
    """Perform the outbound request, returning (status, resp_headers, bytes)."""
    req = urllib.request.Request(url, method=method, headers=headers, data=body)
    opener = _default_opener if follow_redirects else _no_redirect_opener

    try:
        with opener.open(req, timeout=OUTBOUND_TIMEOUT) as resp:
            data = resp.read(MAX_RESPONSE_BODY)
            # Collect response headers, preserving duplicates as lists
            resp_headers = {}
            key_map = {}
            for k, v in resp.headers.items():
                kl = k.lower()
                if kl not in key_map:
                    key_map[kl] = k
                    resp_headers[k] = v
                else:
                    existing = resp_headers[key_map[kl]]
                    if isinstance(existing, list):
                        existing.append(v)
                    else:
                        resp_headers[key_map[kl]] = [existing, v]
            return resp.status, resp_headers, data
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_RESPONSE_BODY) if exc.fp else b""
        headers = {}
        if exc.headers:
            for k, v in exc.headers.items():
                headers[k] = v
        return exc.code, headers, data


def _process_one(item: dict, self_host: str) -> dict:
    """Process a single item, mirroring the Worker's processOne()."""
    # Validate item shape
    if not isinstance(item, dict):
        return {"e": "bad item"}
    u = item.get("u")
    if not u or not isinstance(u, str) or not re.match(r"^https?://", u, re.IGNORECASE):
        return {"e": "bad url"}

    # Parse target URL
    try:
        target_url = urllib.request.urlparse(u)
        target_host = target_url.hostname or ""
    except Exception:
        return {"e": "bad url"}

    # Self‑fetch prevention (loop guard)
    if target_host.lower() == self_host.lower():
        return {"e": "self-fetch blocked"}

    # Build request headers: start with sanitised incoming headers
    headers = {}
    if "h" in item and isinstance(item["h"], dict):
        for k, v in item["h"].items():
            if k.lower() in STRIP_REQUEST_HEADERS:
                continue
            headers[k] = str(v)
    # Mark with relay‑hop header to prevent downstream loops
    headers[HEADER_RELAY_HOP] = "1"

    method = str(item.get("m", "GET")).upper()

    # Redirect policy
    follow_redirects = item.get("r") is not False   # default True

    # Body handling (body‑prohibited methods silently drop body)
    body_bytes = None
    if method not in ("GET", "HEAD"):
        b64 = item.get("b")
        if isinstance(b64, str) and b64:
            try:
                body_bytes = base64.b64decode(b64)
            except Exception:
                return {"e": "bad body base64"}
            # Content‑type injection
            if "ct" in item and item["ct"] and "content-type" not in {
                    k.lower() for k in headers
            }:
                headers["content-type"] = str(item["ct"])

    # Perform the outbound request
    try:
        status, resp_headers, data = _fetch_with_redirect_policy(
            method, u, headers, body_bytes, follow_redirects
        )
    except Exception as err:
        return {"e": "fetch failed: " + str(err)}

    # Convert response body to base64 (chunked to avoid call‑stack issues with
    # large payloads – Python handles it fine, but we mirror the Worker's logic).
    b64_body = base64.b64encode(data).decode("ascii")

    return {
        "s": status,
        "h": resp_headers,
        "b": b64_body,
    }


def _process_batch(items: list, self_host: str) -> list:
    """Process a list of items in parallel."""
    if len(items) > MAX_BATCH_SIZE:
        # The Worker returns a top‑level error for oversized batches.
        # We'll simulate that by raising an exception that the handler
        # turns into a 400 response.
        raise ValueError(
            f"batch too large ({len(items)} > {MAX_BATCH_SIZE})"
        )

    if not items:
        return []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(_process_one, item, self_host) for item in items]
        results = []
        for f in futures:
            try:
                results.append(f.result())
            except Exception as exc:
                results.append({"e": "fetch failed: " + str(exc)})
        return results


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------
class ExitWorkerHandler(http.server.BaseHTTPRequestHandler):
    """Handles POST relay requests; GET returns health status."""

    def log_message(self, fmt, *args):
        pass  # use our own logger

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(
            200,
            {
                "ok": True,
                "status": "healthy",
                "message": "mhrv-rs Cloudflare Worker relay (Python)",
                "usage": "POST JSON with single or batch relay payload.",
            },
        )

    def do_POST(self):
        # Enforce POST only
        if self.command != "POST":
            self._send_json(405, {"e": "method not allowed"})
            return

        # Loop detection via relay‑hop header (sent by this same server)
        if self.headers.get(HEADER_RELAY_HOP) == "1":
            self._send_json(508, {"e": "loop detected"})
            return

        # Read the request body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send_json(400, {"e": "empty body"})
            return
        raw = self.rfile.read(content_length)
        try:
            body = json.loads(raw)
        except Exception:
            self._send_json(400, {"e": "bad json"})
            return

        # Auth check
        if not isinstance(body, dict) or body.get("k") != PSK:
            log.warning("Unauthorized request from %s", self.client_address[0])
            self._send_json(401, {"e": "unauthorized"})
            return

        # Determine our own hostname from the Host header
        host_header = self.headers.get("Host", "")
        self_host = host_header.split(":")[0]   # strip port

        # Batch mode
        if "q" in body and isinstance(body.get("q"), list):
            batch = body["q"]
            if len(batch) > MAX_BATCH_SIZE:
                self._send_json(
                    400,
                    {"e": f"batch too large ({len(batch)} > {MAX_BATCH_SIZE})"},
                )
                return
            results = _process_batch(batch, self_host)
            self._send_json(200, {"q": results})
            return

        # Single mode
        result = _process_one(body, self_host)
        if "e" in result:
            self._send_json(400, result)
        else:
            self._send_json(200, result)


# ---------------------------------------------------------------------------
# Threaded HTTP server
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="mhrv-rs exit Worker relay (Python)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen interface (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8181, help="Listen port (default 8181)")
    parser.add_argument(
        "--psk",
        default="",
        help="Pre‑shared key (or set EXIT_NODE_PSK env var)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    global PSK
    PSK = (args.psk or os.environ.get("EXIT_NODE_PSK", "")).strip()
    if not PSK:
        log.error("No PSK configured. Use --psk or EXIT_NODE_PSK env var.")
        sys.exit(1)
    if PSK == DEFAULT_PSK:
        log.error(
            "Placeholder PSK detected. Set a strong secret before running "
            "the exit worker."
        )
        sys.exit(1)

    server = ThreadedHTTPServer((args.host, args.port), ExitWorkerHandler)
    log.info("Exit Worker listening on %s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
