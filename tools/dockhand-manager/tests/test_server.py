from __future__ import annotations

import http.client
import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("dockhand_manager_server", MODULE_PATH)
assert SPEC and SPEC.loader
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class FakeDockhandHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def log_message(self, _format, *args):
        return

    def _record(self, body: bytes = b"") -> None:
        type(self).requests.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "body": body,
            }
        )

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, status: int, payload: str) -> None:
        body = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._record()
        if self.path == "/api/health":
            self._text(200, "debug password=must-not-leak")
            return
        if self.path == "/api/environments":
            self._json(
                200,
                [
                    {
                        "id": 1,
                        "name": "test",
                        "hawserToken": "must-not-leak",
                        "tlsKey": "must-not-leak-either",
                    }
                ],
            )
            return
        if self.path == "/api/git/stacks?env=1":
            self._json(200, [{"id": 5, "stackName": "demo"}])
            return
        self._json(404, {"error": "missing"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._record(body)
        self._json(
            201,
            {
                "id": 9,
                "name": "whatserv",
                "webhookSecret": "must-not-leak",
                "nested": {"access_token": "must-not-leak"},
            },
        )

    def do_DELETE(self):  # noqa: N802
        self._record()
        self._json(200, {"deleted": True})


class ContractTests(unittest.TestCase):
    def test_validate_upstream_origin(self):
        self.assertEqual(
            manager.validate_upstream_url("http://127.0.0.1:9853/"),
            "http://127.0.0.1:9853",
        )
        with self.assertRaises(ValueError):
            manager.validate_upstream_url("file:///app/data/database.sqlite")
        with self.assertRaises(ValueError):
            manager.validate_upstream_url("https://user:pass@example.com")
        with self.assertRaises(ValueError):
            manager.validate_upstream_url("https://example.com/dockhand")
        with self.assertRaises(ValueError):
            manager.validate_upstream_url("http://192.168.1.66:9853")
        self.assertEqual(
            manager.validate_upstream_url("https://dockhand.example.com/"),
            "https://dockhand.example.com",
        )

    def test_endpoint_allowlist(self):
        self.assertTrue(manager.is_allowed_endpoint("GET", "/api/environments"))
        self.assertTrue(manager.is_allowed_endpoint("POST", "/api/git/stacks"))
        self.assertTrue(manager.is_allowed_endpoint("DELETE", "/api/git/stacks/12"))
        self.assertFalse(manager.is_allowed_endpoint("GET", "/api/users"))
        self.assertFalse(manager.is_allowed_endpoint("POST", "/api/environments"))
        self.assertFalse(manager.is_allowed_endpoint("DELETE", "/api/git/stacks/../../users"))

    def test_query_validation(self):
        self.assertEqual(
            manager.build_upstream_path("GET", "/dockhand/api/git/stacks?env=2"),
            "/api/git/stacks?env=2",
        )
        self.assertEqual(
            manager.build_upstream_path(
                "DELETE", "/dockhand/api/git/stacks/7?env=2"
            ),
            "/api/git/stacks/7?env=2",
        )
        self.assertEqual(
            manager.build_upstream_path(
                "POST", "/dockhand/api/git/stacks/7/deploy?env=2"
            ),
            "/api/git/stacks/7/deploy?env=2",
        )
        with self.assertRaises(ValueError):
            manager.build_upstream_path("GET", "/dockhand/api/git/stacks?env=0")
        with self.assertRaises(ValueError):
            manager.build_upstream_path("GET", "/dockhand/api/git/stacks?env=1&url=http://evil")

    def test_recursive_redaction(self):
        value = {
            "id": 1,
            "webhookSecret": "secret",
            "tls_key": "private",
            "nested": [{"refreshToken": "token", "name": "safe"}],
            "api-key": "key",
            "env_file_content": "DATABASE_URL=secret",
            "sshPrivateKey": "private-key",
            "variables": [{"name": "DATABASE_URL", "value": "postgres://secret"}],
            "config": {"content": "services: secret"},
            "accessKey": "secret-access-key",
        }
        cleaned = manager.redact_sensitive(value)
        self.assertEqual(cleaned["id"], 1)
        self.assertEqual(cleaned["webhookSecret"], "[REDACTED]")
        self.assertEqual(cleaned["tls_key"], "[REDACTED]")
        self.assertEqual(cleaned["nested"][0]["refreshToken"], "[REDACTED]")
        self.assertEqual(cleaned["nested"][0]["name"], "safe")
        self.assertEqual(cleaned["api-key"], "[REDACTED]")
        self.assertEqual(cleaned["env_file_content"], "[REDACTED]")
        self.assertEqual(cleaned["sshPrivateKey"], "[REDACTED]")
        self.assertEqual(cleaned["variables"], "[REDACTED]")
        self.assertEqual(cleaned["config"], "[REDACTED]")
        self.assertEqual(cleaned["accessKey"], "[REDACTED]")


class ProxyIntegrationTests(unittest.TestCase):
    token = "dh_" + "a" * 40

    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeDockhandHandler)
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        upstream_url = f"http://127.0.0.1:{cls.upstream.server_port}"
        cls.proxy = manager.DockhandManagerServer(
            ("127.0.0.1", 0),
            manager.DockhandManagerHandler,
            upstream_url=upstream_url,
            timeout=5,
        )
        cls.proxy_thread = threading.Thread(target=cls.proxy.serve_forever, daemon=True)
        cls.proxy_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()

    def setUp(self):
        FakeDockhandHandler.requests.clear()

    def request(self, method: str, path: str, *, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        request_headers = dict(headers or {})
        encoded_body = None
        if body is not None:
            encoded_body = json.dumps(body).encode()
            request_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=encoded_body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()
        return response.status, response_headers, payload

    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def mutation_headers(self):
        headers = self.auth_headers()
        headers.update(
            {
                "Origin": f"http://127.0.0.1:{self.proxy.server_port}",
                "X-CSRF-Token": self.proxy.csrf_token,
            }
        )
        return headers

    def test_static_page_has_security_headers(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Dockhand Git Stack Manager", body)
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_invalid_host_is_rejected(self):
        status, _, body = self.request("GET", "/config", headers={"Host": "evil.example"})
        self.assertEqual(status, 400)
        self.assertIn(b"Invalid Host", body)

        status, _, _ = self.request(
            "GET", "/config", headers={"Host": f"127.0.0.1:{self.proxy.server_port + 1}"}
        )
        self.assertEqual(status, 400)

    def test_proxy_requires_token(self):
        status, _, _ = self.request("GET", "/dockhand/api/environments")
        self.assertEqual(status, 401)
        self.assertEqual(FakeDockhandHandler.requests, [])

    def test_get_is_forwarded_and_secrets_are_redacted(self):
        status, _, body = self.request(
            "GET", "/dockhand/api/environments", headers=self.auth_headers()
        )
        self.assertEqual(status, 200)
        decoded = json.loads(body)
        self.assertEqual(decoded[0]["name"], "test")
        self.assertEqual(decoded[0]["hawserToken"], "[REDACTED]")
        self.assertEqual(decoded[0]["tlsKey"], "[REDACTED]")
        self.assertEqual(FakeDockhandHandler.requests[0]["authorization"], f"Bearer {self.token}")

    def test_non_json_upstream_body_is_withheld(self):
        status, headers, body = self.request(
            "GET", "/dockhand/api/health", headers=self.auth_headers()
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        decoded = json.loads(body)
        self.assertIn("body withheld", decoded["message"])
        self.assertNotIn(b"must-not-leak", body)

    def test_env_query_is_forwarded(self):
        status, _, body = self.request(
            "GET", "/dockhand/api/git/stacks?env=1", headers=self.auth_headers()
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)[0]["stackName"], "demo")
        self.assertEqual(FakeDockhandHandler.requests[0]["path"], "/api/git/stacks?env=1")

    def test_unlisted_endpoint_is_blocked(self):
        status, _, _ = self.request(
            "GET", "/dockhand/api/users", headers=self.auth_headers()
        )
        self.assertEqual(status, 405)
        self.assertEqual(FakeDockhandHandler.requests, [])

    def test_mutation_requires_origin_and_csrf(self):
        status, _, _ = self.request(
            "POST",
            "/dockhand/api/git/repositories",
            body={"name": "whatserv"},
            headers=self.auth_headers(),
        )
        self.assertEqual(status, 403)
        self.assertEqual(FakeDockhandHandler.requests, [])

        bad_origin = self.mutation_headers()
        bad_origin["Origin"] = "http://evil.example"
        status, _, _ = self.request(
            "POST", "/dockhand/api/git/repositories", body={}, headers=bad_origin
        )
        self.assertEqual(status, 403)
        self.assertEqual(FakeDockhandHandler.requests, [])

        bad_csrf = self.mutation_headers()
        bad_csrf["X-CSRF-Token"] = "wrong"
        status, _, _ = self.request(
            "DELETE", "/dockhand/api/git/repositories/1", headers=bad_csrf
        )
        self.assertEqual(status, 403)
        self.assertEqual(FakeDockhandHandler.requests, [])

    def test_unneeded_http_methods_are_rejected(self):
        for method in ("PUT", "PATCH", "OPTIONS", "HEAD"):
            with self.subTest(method=method):
                status, _, _ = self.request(method, "/dockhand/api/git/repositories")
                self.assertEqual(status, 405)
        self.assertEqual(FakeDockhandHandler.requests, [])

    def test_mutation_is_forwarded_once_and_response_is_redacted(self):
        status, _, body = self.request(
            "POST",
            "/dockhand/api/git/repositories",
            body={"name": "whatserv"},
            headers=self.mutation_headers(),
        )
        self.assertEqual(status, 201)
        self.assertEqual(len(FakeDockhandHandler.requests), 1)
        decoded = json.loads(body)
        self.assertEqual(decoded["webhookSecret"], "[REDACTED]")
        self.assertEqual(decoded["nested"]["access_token"], "[REDACTED]")

    def test_stack_mutations_forward_environment_query(self):
        status, _, _ = self.request(
            "POST",
            "/dockhand/api/git/stacks/9/deploy?env=2",
            body={},
            headers=self.mutation_headers(),
        )
        self.assertEqual(status, 201)
        self.assertEqual(FakeDockhandHandler.requests[0]["path"], "/api/git/stacks/9/deploy?env=2")

        status, _, _ = self.request(
            "DELETE",
            "/dockhand/api/git/stacks/9?env=2",
            headers=self.mutation_headers(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(FakeDockhandHandler.requests[1]["path"], "/api/git/stacks/9?env=2")


if __name__ == "__main__":
    unittest.main()
