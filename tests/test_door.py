from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent import policy

ROOT = Path(__file__).resolve().parent.parent


def load_door():
    spec = importlib.util.spec_from_file_location("door_under_test", ROOT / "door" / "door.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


door_mod = load_door()


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    paths: list = []

    def log_message(self, fmt, *args):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        Upstream.paths.append(self.path)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = handle_any


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def serve(handler) -> ThreadingHTTPServer:
    server = QuietServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class DoorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Upstream.paths = []
        self.upstream = serve(Upstream)
        data = Path(self.tmp.name)
        (data / "canaries.json").write_text(json.dumps({"honeypot": {"admin_password": "BAIT-123"}}))
        env = {
            "DOOR_UPSTREAM": f"http://127.0.0.1:{self.upstream.server_address[1]}",
            "DOOR_DATA_DIR": str(data),
            "DOOR_ADMIN_SHA256": door_mod.hashlib.sha256(b"admin").hexdigest(),
            "DOOR_TARPIT_SECONDS": "0.4",
            "DOOR_TARPIT_PER_IP": "2",
            "DOOR_ALLOWLIST": "9.9.9.9",
        }
        self.door = door_mod.Door(door_mod.Config(env))
        self.server = serve(door_mod.make_handler(self.door))
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.upstream.shutdown()
        self.server.server_close()
        self.upstream.server_close()
        self.tmp.cleanup()

    def call(self, path: str, ip: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None) -> tuple:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers={"Sprite-Client-Ip": ip, **(headers or {})})
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, data, resp.getheaders())
        conn.close()
        return result

    def admin(self, method: str, path: str, payload=None) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = json.dumps(payload).encode() if payload is not None else None
        conn.request(method, "/_bouncer/" + path, body=body, headers={"Authorization": "Bearer admin"})
        status = conn.getresponse().status
        conn.close()
        return status

    def test_shield_refuses_attack_shaped_requests_only(self):
        route = "GET /rest/products/search"
        self.assertEqual(self.admin("PUT", "shield", {route: {"until": time.time() + 60, "reason": "proven"}}), 200)
        attack = "/rest/products/search?q=" + urllib.parse.quote("zz')) UNION SELECT email FROM Users--")
        status, body, _ = self.call(attack, "1.1.1.1")
        self.assertEqual((status, b"shielded" in body), (403, True))
        self.assertEqual(self.call("/rest/products/search?q=kid's%20juice", "1.1.1.1")[0], 200)
        self.assertEqual(self.call(attack, "9.9.9.9")[0], 200)
        self.assertEqual(self.call(attack.replace("search", "other"), "1.1.1.1")[0], 200)
        quoted = urllib.parse.quote(route, safe="")
        self.assertEqual(self.admin("DELETE", f"shield/{quoted}"), 200)
        self.assertEqual(self.call(attack, "1.1.1.1")[0], 200)

    def test_honeypot_tarpits_at_once_and_reuse_blocks_at_once(self):
        self.assertEqual(self.call("/.env", "2.2.2.2")[0], 200)
        started = time.time()
        self.assertEqual(self.call("/", "2.2.2.2")[0], 200)
        self.assertGreaterEqual(time.time() - started, 0.35)
        body = json.dumps({"email": "a@b.c", "password": "BAIT-123"}).encode()
        self.call("/rest/user/login", "2.2.2.2", "POST", body, {"Content-Type": "application/json"})
        self.assertEqual(self.call("/", "2.2.2.2")[0], 403)

    def test_bait_values_from_elsewhere_do_not_block(self):
        self.call("/?q=BAIT-123", "3.3.3.3")
        self.call("/", "3.3.3.4", headers={"Referer": "https://evil.example/?k=BAIT-123"})
        self.call("/.env", "3.3.3.5", headers={"Sec-Fetch-Site": "cross-site"})
        self.call("/?q=BAIT-123", "3.3.3.5", headers={"Sec-Fetch-Site": "cross-site"})
        for ip in ("3.3.3.3", "3.3.3.4", "3.3.3.5"):
            started = time.time()
            self.assertEqual(self.call("/", ip)[0], 200)
            self.assertLess(time.time() - started, 0.3)

    def test_tarpitted_client_cannot_skip_the_wait_with_parallel_requests(self):
        self.call("/.env", "4.4.4.4")
        results = []

        def one():
            started = time.time()
            status = self.call("/", "4.4.4.4")[0]
            results.append((status, time.time() - started))

        threads = [threading.Thread(target=one) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        fast_ok = [r for r in results if r[0] == 200 and r[1] < 0.3]
        self.assertEqual(fast_ok, [])
        self.assertEqual(sum(1 for r in results if r[0] == 429), 6)

    def test_ipv6_clients_are_grouped_by_slash_64(self):
        self.admin("PUT", "blocklist", {"2001:db8:1:2::/64": {"until": time.time() + 60, "reason": "test"}})
        self.assertEqual(self.call("/", "2001:db8:1:2::99")[0], 403)
        self.assertEqual(self.call("/", "2001:db8:1:2:aaaa::1")[0], 403)
        self.assertEqual(self.call("/", "2001:db8:1:3::1")[0], 200)

    def test_admin_delete_takes_targets_with_slashes_from_the_body(self):
        route = "GET /rest/products/search"
        self.admin("PUT", "shield", {route: {"until": time.time() + 60, "reason": "proven"}})
        self.admin("PUT", "blocklist", {"2001:db8:9:9::/64": {"until": time.time() + 60, "reason": "test"}})
        attack = "/rest/products/search?q=" + urllib.parse.quote("zz')) UNION SELECT 1--")
        self.assertEqual(self.call(attack, "1.1.1.2")[0], 403)
        self.assertEqual(self.admin("DELETE", "shield", {"target": route}), 200)
        self.assertEqual(self.call(attack, "1.1.1.2")[0], 200)
        self.assertEqual(self.admin("DELETE", "blocklist", {"target": "2001:db8:9:9::/64"}), 200)
        self.assertEqual(self.call("/", "2001:db8:9:9::1")[0], 200)
        self.assertEqual(self.admin("DELETE", "blocklist", {"target": 5}), 400)

    def test_raw_non_ascii_path_is_forwarded_percent_encoded(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: x\r\nSprite-Client-Ip: 5.5.5.5\r\nConnection: close\r\n\r\n")
            data = s.recv(4096)
        self.assertIn(b"200", data.split(b"\r\n", 1)[0])
        self.assertIn("/caf%C3%A9", Upstream.paths)

    def test_blocked_client_is_refused_before_its_body_is_read(self):
        self.admin("PUT", "blocklist", {"6.6.6.6": {"until": time.time() + 60, "reason": "test"}})
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"POST /rest/user/login HTTP/1.1\r\nHost: x\r\nSprite-Client-Ip: 6.6.6.6\r\nContent-Length: 1000000\r\n\r\n")
            data = s.recv(4096)
        self.assertIn(b"403", data.split(b"\r\n", 1)[0])

    def test_upstream_date_header_is_not_duplicated(self):
        _, _, headers = self.call("/", "7.7.7.7")
        self.assertEqual(sum(1 for k, _ in headers if k.lower() == "date"), 1)

    def test_door_and_agent_agree_on_attack_shape(self):
        self.assertEqual(door_mod.ATTACK.pattern, policy.ATTACK.pattern)


if __name__ == "__main__":
    unittest.main()
