#!/usr/bin/env python3
"""Local-only web proxy for the Dockhand Git Stack Manager SPA."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


STATIC_ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
BEARER_RE = re.compile(r"^Bearer\s+(dh_[A-Za-z0-9_-]{20,})$")
NUMERIC_ID = r"[1-9][0-9]*"

READ_ENDPOINTS = (
    re.compile(r"^/api/health$"),
    re.compile(r"^/api/environments$"),
    re.compile(r"^/api/git/repositories$"),
    re.compile(r"^/api/git/stacks$"),
    re.compile(r"^/api/stacks$"),
)
CREATE_ENDPOINTS = (
    re.compile(r"^/api/git/repositories$"),
    re.compile(r"^/api/git/stacks$"),
    re.compile(rf"^/api/git/repositories/{NUMERIC_ID}/(?:test|sync)$"),
    re.compile(rf"^/api/git/stacks/{NUMERIC_ID}/(?:deploy|sync)$"),
)
DELETE_ENDPOINTS = (
    re.compile(rf"^/api/git/repositories/{NUMERIC_ID}$"),
    re.compile(rf"^/api/git/stacks/{NUMERIC_ID}$"),
)
SENSITIVE_KEY_PARTS = (
    "accesskey",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "envcontent",
    "envfile",
    "private",
    "password",
    "privatekey",
    "rawcontent",
    "refreshtoken",
    "secret",
    "ssh",
    "token",
    "tlskey",
)
SENSITIVE_EXACT_KEYS = {
    "config",
    "content",
    "env",
    "environment",
    "value",
    "values",
    "variables",
}


class NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward an Authorization header across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


UPSTREAM_OPENER = build_opener(NoRedirectHandler())


def validate_upstream_url(raw_url: str) -> str:
    """Validate a trusted CLI-provided Dockhand origin."""

    parsed = urlsplit(raw_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Dockhand URL must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("Dockhand URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Dockhand URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Dockhand URL must not contain query parameters or a fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("Dockhand URL must be an origin without a path prefix")
    if parsed.scheme == "http":
        hostname = parsed.hostname.lower()
        try:
            loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if not loopback:
            raise ValueError("Plain HTTP is allowed only for a loopback Dockhand URL; use HTTPS")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def is_allowed_endpoint(method: str, api_path: str) -> bool:
    patterns = {
        "GET": READ_ENDPOINTS,
        "POST": CREATE_ENDPOINTS,
        "DELETE": DELETE_ENDPOINTS,
    }.get(method, ())
    return any(pattern.fullmatch(api_path) for pattern in patterns)


def build_upstream_path(method: str, raw_target: str) -> str:
    """Validate a local proxy target and return its Dockhand API path."""

    parsed = urlsplit(raw_target)
    prefix = "/dockhand"
    if not parsed.path.startswith(prefix + "/"):
        raise ValueError("Unknown proxy path")
    api_path = parsed.path[len(prefix) :]
    if not is_allowed_endpoint(method, api_path):
        raise PermissionError("Dockhand endpoint or HTTP method is not allowed")

    query = parse_qs(parsed.query, keep_blank_values=True)
    if query:
        query_allowed = (
            (method == "GET" and api_path in {"/api/git/stacks", "/api/stacks"})
            or (
                method in {"POST", "DELETE"}
                and re.fullmatch(
                    rf"/api/git/stacks/{NUMERIC_ID}(?:/(?:deploy|sync))?",
                    api_path,
                )
            )
        )
        if not query_allowed:
            raise ValueError("Query parameters are not allowed for this endpoint")
        if set(query) != {"env"} or len(query["env"]) != 1:
            raise ValueError("Only one env query parameter is allowed")
        env_id = query["env"][0]
        if not env_id.isdigit() or int(env_id) < 1:
            raise ValueError("env must be a positive integer")
        return f"{api_path}?{urlencode({'env': env_id})}"
    return api_path


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def redact_sensitive(value: Any) -> Any:
    """Recursively remove secrets that Dockhand may return in JSON payloads."""

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _normalized_key(key)
            if normalized in SENSITIVE_EXACT_KEYS or any(
                part in normalized for part in SENSITIVE_KEY_PARTS
            ):
                cleaned[str(key)] = "[REDACTED]"
            else:
                cleaned[str(key)] = redact_sensitive(item)
        return cleaned
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def sanitize_upstream_body(body: bytes, content_type: str, bearer_token: str) -> bytes:
    """Redact response secrets before returning anything to the SPA."""

    if not body:
        return b""
    text = body.decode("utf-8", errors="replace").replace(bearer_token, "[REDACTED]")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            return json.dumps(redact_sensitive(parsed), ensure_ascii=False).encode("utf-8")
    # Opaque text may contain .env values, deployment logs, or credentials with
    # unknown labels. Do not attempt incomplete regex redaction.
    return json.dumps(
        {
            "message": "Dockhand returned a non-JSON response; body withheld for safety",
            "contentType": content_type.split(";", 1)[0],
            "responseBytes": len(body),
        },
        ensure_ascii=False,
    ).encode("utf-8")


class DockhandManagerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, upstream_url: str, timeout: int):
        super().__init__(server_address, handler_class)
        self.upstream_url = upstream_url
        self.upstream_timeout = timeout
        self.csrf_token = secrets.token_urlsafe(32)


class DockhandManagerHandler(BaseHTTPRequestHandler):
    server_version = "DockhandManager/1.0"

    def log_message(self, _format: str, *args: Any) -> None:
        # Disable BaseHTTPRequestHandler access logging so bearer tokens and
        # upstream response fragments cannot leak into terminal history.
        return

    @property
    def manager_server(self) -> DockhandManagerServer:
        return self.server  # type: ignore[return-value]

    def _host_is_local(self) -> bool:
        raw_host = self.headers.get("Host", "")
        try:
            parsed = urlsplit(f"//{raw_host}")
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError:
            return False
        if parsed.username or parsed.password or hostname not in LOCAL_HOSTS:
            return False
        return port == self.server.server_port

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )

    def _write_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers(content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _write_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._write_bytes(status, body, "application/json; charset=utf-8")

    def _reject_nonlocal_host(self) -> bool:
        if self._host_is_local():
            return False
        self._write_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Host header"})
        return True

    def _origin_is_valid(self) -> bool:
        origin = self.headers.get("Origin", "")
        host = self.headers.get("Host", "")
        return origin == f"http://{host}"

    def _csrf_is_valid(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("X-CSRF-Token", ""), self.manager_server.csrf_token
        )

    def _read_request_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise OverflowError("Request body is too large")
        return self.rfile.read(length)

    def _serve_static(self, filename: str, content_type: str) -> None:
        path = STATIC_ROOT / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "Static file not found"})
            return
        self._write_bytes(HTTPStatus.OK, body, content_type)

    def do_GET(self) -> None:  # noqa: N802
        if self._reject_nonlocal_host():
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._serve_static("app.js", "text/javascript; charset=utf-8")
            return
        if parsed.path == "/app.css":
            self._serve_static("app.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/favicon.ico":
            self._write_bytes(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            return
        if parsed.path == "/config":
            self._write_json(
                HTTPStatus.OK,
                {
                    "dockhandUrl": self.manager_server.upstream_url,
                    "csrfToken": self.manager_server.csrf_token,
                    "tokenStorage": "memory-only",
                },
            )
            return
        if parsed.path.startswith("/dockhand/"):
            self._proxy("GET")
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        self._handle_mutation("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_mutation("DELETE")

    def do_PUT(self) -> None:  # noqa: N802
        self._reject_method()

    def do_PATCH(self) -> None:  # noqa: N802
        self._reject_method()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._reject_method()

    def do_HEAD(self) -> None:  # noqa: N802
        self._reject_method()

    def _reject_method(self) -> None:
        if self._reject_nonlocal_host():
            return
        self._write_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method not allowed"})

    def _handle_mutation(self, method: str) -> None:
        if self._reject_nonlocal_host():
            return
        if not self._origin_is_valid() or not self._csrf_is_valid():
            self._write_json(HTTPStatus.FORBIDDEN, {"error": "Origin or CSRF check failed"})
            return
        self._proxy(method)

    def _proxy(self, method: str) -> None:
        try:
            upstream_path = build_upstream_path(method, self.path)
        except PermissionError as exc:
            self._write_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": str(exc)})
            return
        except ValueError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        authorization = self.headers.get("Authorization", "")
        token_match = BEARER_RE.fullmatch(authorization)
        if not token_match:
            self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "Valid Dockhand bearer token required"})
            return
        bearer_token = token_match.group(1)

        body = b""
        if method == "POST":
            try:
                body = self._read_request_body()
            except OverflowError as exc:
                self._write_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(exc)})
                return
            except ValueError as exc:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            if body:
                try:
                    json.loads(body)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._write_json(HTTPStatus.BAD_REQUEST, {"error": "Request body must be valid JSON"})
                    return

        upstream_request = Request(
            self.manager_server.upstream_url + upstream_path,
            data=body if method == "POST" else None,
            method=method,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "WhatServ-Dockhand-Manager/1.0",
            },
        )
        try:
            response = UPSTREAM_OPENER.open(
                upstream_request, timeout=self.manager_server.upstream_timeout
            )
            status = response.status
            content_type = response.headers.get("Content-Type", "application/json")
            upstream_body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            status = exc.code
            content_type = exc.headers.get("Content-Type", "application/json")
            upstream_body = exc.read(MAX_RESPONSE_BYTES + 1)
        except (URLError, TimeoutError, OSError) as exc:
            self._write_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": "Dockhand is unavailable", "detail": type(exc).__name__},
            )
            return

        if len(upstream_body) > MAX_RESPONSE_BYTES:
            self._write_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": "Dockhand response exceeded the safe size limit"},
            )
            return
        sanitized = sanitize_upstream_body(upstream_body, content_type, bearer_token)
        self._write_bytes(status, sanitized, "application/json; charset=utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the localhost-only Dockhand Git Stack Manager"
    )
    parser.add_argument(
        "--dockhand-url",
        default="http://127.0.0.1:9853",
        help="Dockhand origin, default: http://127.0.0.1:9853",
    )
    parser.add_argument(
        "--port", type=int, default=8765, help="Local UI port, default: 8765"
    )
    parser.add_argument(
        "--timeout", type=int, default=900, help="Dockhand API timeout in seconds"
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")
    try:
        args.dockhand_url = validate_upstream_url(args.dockhand_url)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    server = DockhandManagerServer(
        ("127.0.0.1", args.port),
        DockhandManagerHandler,
        upstream_url=args.dockhand_url,
        timeout=args.timeout,
    )
    print(f"Dockhand Manager: http://127.0.0.1:{args.port}")
    print(f"Dockhand target:  {args.dockhand_url}")
    print("Listening on localhost only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Dockhand Manager...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
