from __future__ import annotations

import gzip
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
    seen: list = []

    def log_message(self, fmt, *args):
        pass

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        Upstream.paths.append(self.path)
        Upstream.seen.append((self.path, self.headers, body))
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
        Upstream.seen = []
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
        self.data = data
        self.door = door_mod.Door(door_mod.Config(env))
        self.pushed = []
        self.door.pusher.push = self.pushed.append
        self.server = serve(door_mod.make_handler(self.door))
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.door.close()
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

    def last_push(self, count: int) -> dict:
        deadline = time.time() + 3
        while len(self.pushed) < count and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(self.pushed), count)
        return self.pushed[-1]

    def log_lines(self, count: int) -> list:
        path = self.data / "access.log"
        deadline = time.time() + 3
        complete = lambda: path.read_text().split("\n")[:-1] if path.exists() else []
        while time.time() < deadline and len(complete()) < count:
            time.sleep(0.01)
        return complete()

    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(data)
            return s.recv(65536)

    def shield(self, route: str = "GET /rest/products/search") -> None:
        self.assertEqual(self.admin("PUT", "shield", {route: {"until": time.time() + 60, "reason": "proven"}}), 200)

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

    def test_door_flags_every_attack_the_agent_flags(self):
        for text in ATTACKS:
            if policy.ATTACK.search(text):
                self.assertTrue(door_mod.ATTACK.search(text), text)

    def test_detection_sees_through_encodings(self):
        for path in (
            "/rest/products/search?q=%2527%20or%201=1--",
            "/rest/products/search?q=%252527))%20union%20select%201",
            "/ftp/package.json.bak%2500.md",
            "/ftp/package.json.bak%00.md",
            "/ftp/x\\u0000.md",
            "/rest/products/search?q=admin'/**/or/**/1=1",
            "/rest/products/search?q=..%252f..%252fetc",
        ):
            self.assertTrue(door_mod.looks_like_attack(path), path)
        self.assertTrue(door_mod.looks_like_attack("/rest/user/login", '{"email":"\\u0027 or 1=1--"}'))
        self.assertTrue(door_mod.looks_like_attack("/rest/user/login", '{"email":"\' or 1=1--"}'))
        self.assertTrue(door_mod.looks_like_attack("/rest/user/login", '{"email":"\\u0027\\u002d\\u002d"}'))

    def test_attack_regex_covers_more_shapes_without_flagging_plain_text(self):
        for text in ATTACKS:
            self.assertTrue(door_mod.looks_like_attack("/x", text), text)
        for text in HARMLESS:
            self.assertFalse(door_mod.looks_like_attack("/rest/products/search?q=" + urllib.parse.quote(text)), text)

    def test_nul_byte_path_is_shielded_and_flagged(self):
        self.shield("GET /ftp/package.json.bak%2500.md")
        self.assertEqual(self.call("/ftp/package.json.bak%2500.md", "1.1.1.1")[0], 403)
        self.assertEqual(self.call("/ftp/package.json.bak%2500.md", "9.9.9.9")[0], 200)
        self.assertTrue(self.last_push(2)["attack_shaped"])
        self.assertFalse(self.door.is_quiet("GET", "/ftp/a%2500.md"))

    def test_shield_matches_route_like_express_and_for_every_method(self):
        self.shield()
        q = "?q=" + urllib.parse.quote("')) union select 1--")
        for path in ("/REST/Products/Search", "/rest/products/search/", "//rest//products//search", "/rest/products/%73earch"):
            self.assertEqual(self.call(path + q, "1.1.1.1")[0], 403, path)
        self.assertEqual(self.call("/rest/products/search" + q, "1.1.1.1", "POST", b"x")[0], 403)
        self.assertEqual(self.call("/rest/products/search", "1.1.1.1", "POST", b'{"q":{"$ne":1}}')[0], 403)
        data = self.raw(f"GET http://x/rest/products/search{q} HTTP/1.1\r\nHost: x\r\nSprite-Client-Ip: 1.1.1.1\r\nConnection: close\r\n\r\n".encode())
        self.assertIn(b"403", data.split(b"\r\n", 1)[0])
        self.assertEqual(self.call("/rest/products/search?q=apple", "1.1.1.1", "POST", b"x")[0], 200)
        self.assertEqual(self.call("/rest/products/searchx" + q, "1.1.1.1")[0], 200)

    def test_gzip_body_is_inspected_and_recorded_decoded(self):
        self.shield("POST /rest/user/login")
        attack = json.dumps({"email": "' or 1=1--", "password": "x"}).encode()
        headers = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", gzip.compress(attack), headers)[0], 403)
        harmless = gzip.compress(json.dumps({"email": "a@b.c", "password": "x"}).encode())
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", harmless, headers)[0], 200)
        self.assertEqual(Upstream.seen[-1][2], harmless)
        record = self.last_push(2)
        self.assertEqual((record["body"], record["decoded_from"]), ('{"email": "a@b.c", "password": "x"}', {"content_encoding": "gzip"}))
        self.assertNotIn("Content-Encoding", record.get("headers", {}))

    def test_non_utf8_charset_is_decoded_for_detection(self):
        self.shield("POST /rest/user/login")
        body = json.dumps({"email": "' or 1=1--"}).encode("utf-16")
        headers = {"Content-Type": "application/json; charset=utf-16"}
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", body, headers)[0], 403)
        record = self.last_push(1)
        self.assertEqual((record["body"], record["ctype"]), ('{"email": "\' or 1=1--"}', "application/json; charset=utf-8"))
        self.assertEqual(record["decoded_from"], {"charset": "utf-16"})

    def test_undecodable_body_is_attack_shaped_only_on_shielded_routes(self):
        bomb = gzip.compress(b"a" * (door_mod.MAX_DECODED_BODY + 10))
        headers = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", bomb, headers)[0], 200)
        self.assertTrue(self.last_push(1)["decode_failed"])
        self.shield("POST /rest/user/login")
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", bomb, headers)[0], 403)
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", b"\xff\xfe'", {"Content-Type": "text/plain; charset=bogus"})[0], 403)
        self.assertEqual(self.call("/rest/user/login", "1.1.1.1", "POST", b"x", {"Content-Encoding": "br"})[0], 403)

    def test_padded_body_is_truncated_but_still_flagged(self):
        body = json.dumps({"pad": "a" * 70000, "email": "' or 1=1--"}).encode()
        self.call("/rest/user/login", "1.1.1.1", "POST", body, {"Content-Type": "application/json"})
        record = self.last_push(1)
        self.assertEqual((record["truncated"], record["attack_shaped"]), (True, True))
        self.assertNotIn("or 1=1", record["body"])
        self.call("/rest/user/login", "1.1.1.1", "POST", b'{"email":"a@b.c"}', {"Content-Type": "application/json"})
        self.assertNotIn("attack_shaped", self.last_push(2))

    def test_access_log_redacts_secrets_but_record_keeps_them(self):
        token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOjF9.c2lnbmF0dXJlLXNlY3JldA"
        self.call("/rest/basket/1", "1.1.1.1", headers={"Authorization": "Bearer " + token, "Cookie": "token=" + token, "X-User-Email": "someone@example.com"})
        pushed = self.last_push(1)
        log = "\n".join(self.log_lines(1))
        self.assertNotIn(token, log)
        self.assertNotIn("someone@example.com", log)
        logged = json.loads(log.splitlines()[-1])["headers"]
        self.assertEqual(logged["Authorization"], f"Bearer eyJhbG...[{len(token)}]")
        self.assertEqual(logged["Cookie"], f"token=...[{len(token) + 6}]")
        self.assertEqual(pushed["headers"]["Authorization"], "Bearer " + token)

    def test_access_log_redacts_secret_body_fields_but_record_keeps_them(self):
        body = json.dumps({"email": "a@b.c", "password": "hunter2", "securityAnswer": "fluffy", "totpToken": 123456}).encode()
        self.call("/rest/user/login", "1.1.1.1", "POST", body, {"Content-Type": "application/json"})
        form = b"email=a%40b.c&newPassword=hunter2&q=pass"
        self.call("/rest/user/change", "1.1.1.1", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"})
        self.last_push(2)
        self.assertEqual(self.pushed[0]["body"], body.decode())
        logged = [json.loads(line)["body"] for line in self.log_lines(2)[-2:]]
        for text in logged:
            self.assertNotIn("hunter2", text)
            self.assertNotIn("fluffy", text)
            self.assertNotIn("123456", text)
        self.assertEqual(json.loads(logged[0]), {"email": "a@b.c", "password": "[redacted 7]", "securityAnswer": "[redacted 6]", "totpToken": "[redacted 6]"})
        self.assertEqual(logged[1], "email=a%40b.c&newPassword=[redacted 7]&q=pass")

    def test_unsigned_or_alg_none_jwt_is_attack_shaped(self):
        def jwt(alg, sig):
            seg = lambda o: door_mod.base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
            return f"{seg({'alg': alg, 'typ': 'JWT'})}.{seg({'data': {'email': 'admin@juice-sh.op'}})}.{sig}"

        self.assertTrue(door_mod.jwt_tampered({"Authorization": "Bearer " + jwt("none", "")}))
        self.assertTrue(door_mod.jwt_tampered({"Authorization": "bearer " + jwt("NoNe", "abc")}))
        self.assertTrue(door_mod.jwt_tampered({"Authorization": "Bearer " + jwt("RS256", "")}))
        self.assertTrue(door_mod.jwt_tampered({"Cookie": "a=b; token=" + jwt("none", "")}))
        self.assertFalse(door_mod.jwt_tampered({"Authorization": "Bearer " + jwt("RS256", "c2ln")}))
        self.assertFalse(door_mod.jwt_tampered({"Authorization": "Bearer opaque.token", "Cookie": "language=en"}))
        self.shield("GET /rest/basket/1")
        self.assertEqual(self.call("/rest/basket/1", "1.1.1.1", headers={"Authorization": "Bearer " + jwt("none", "")})[0], 403)
        self.assertEqual(self.call("/rest/basket/1", "1.1.1.1", headers={"Authorization": "Bearer " + jwt("RS256", "c2ln")})[0], 200)

    def test_idle_timeout_does_not_cut_the_tarpit_and_busy_server_answers_503(self):
        cfg = door_mod.Config({"DOOR_UPSTREAM": f"http://127.0.0.1:{self.upstream.server_address[1]}", "DOOR_DATA_DIR": str(self.data / "b"),
                               "DOOR_IDLE_SECONDS": "0.2", "DOOR_TARPIT_SECONDS": "0.4", "DOOR_MAX_THREADS": "1"})
        door = door_mod.Door(cfg)
        server = door_mod.make_server(door, ("127.0.0.1", 0))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        try:
            door.mark_bait("8.8.8.8")
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Sprite-Client-Ip": "8.8.8.8"})
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
            time.sleep(0.3)
            idle = socket.create_connection(("127.0.0.1", port), timeout=5)
            time.sleep(0.05)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                self.assertIn(b"503", s.recv(4096).split(b"\r\n", 1)[0])
            self.assertEqual(idle.recv(10), b"")
            idle.close()
            time.sleep(0.05)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Sprite-Client-Ip": "8.8.4.4"})
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            door.close()

    def test_list_writes_are_batched_and_capped(self):
        lists = door_mod.Lists(self.data / "batched.json", flush_seconds=60, cap=10)
        try:
            for i in range(25):
                lists.add("block", f"10.0.0.{i}", 100 + i, "test", set())
            self.assertFalse((self.data / "batched.json").exists())
            self.assertLessEqual(len(lists.data["block"]), 10)
            self.assertIn("10.0.0.24", lists.data["block"])
            self.assertNotIn("10.0.0.0", lists.data["block"])
            lists.flush()
            self.assertEqual(set(json.loads((self.data / "batched.json").read_text())["block"]), set(lists.data["block"]))
        finally:
            lists.close()

    def test_strict_chunked_and_content_length_parsing(self):
        head = b"POST /x HTTP/1.1\r\nHost: x\r\nSprite-Client-Ip: 1.1.1.1\r\nConnection: close\r\n"
        for size in (b"0x5", b"+5", b"1_0", b" 5", b"-5"):
            data = self.raw(head + b"Transfer-Encoding: chunked\r\n\r\n" + size + b"\r\nhello\r\n0\r\n\r\n")
            self.assertIn(b"400", data.split(b"\r\n", 1)[0], size)
        for te in (b"gzip, chunked", b"chunked, identity", b"xchunked"):
            data = self.raw(head + b"Transfer-Encoding: " + te + b"\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            self.assertIn(b"400", data.split(b"\r\n", 1)[0], te)
        for cl in (b"+5", b"5_0", b"0x5"):
            data = self.raw(head + b"Content-Length: " + cl + b"\r\n\r\nhello")
            self.assertIn(b"400", data.split(b"\r\n", 1)[0], cl)
        data = self.raw(head + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
        self.assertIn(b"400", data.split(b"\r\n", 1)[0])
        data = self.raw(head + b"Transfer-Encoding: Chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n")
        self.assertIn(b"200", data.split(b"\r\n", 1)[0])
        self.assertEqual(Upstream.seen[-1][2], b"hello")

    def test_unblock_also_forgets_the_bait(self):
        self.call("/.env", "2.2.2.3")
        body = json.dumps({"email": "a@b.c", "password": "BAIT-123"}).encode()
        self.call("/rest/user/login", "2.2.2.3", "POST", body, {"Content-Type": "application/json"})
        self.assertEqual(self.call("/", "2.2.2.3")[0], 403)
        self.assertEqual(self.admin("DELETE", "blocklist", {"target": "2.2.2.3"}), 200)
        self.assertEqual(self.admin("DELETE", "tarpit", {"target": "2.2.2.3"}), 200)
        self.assertNotIn("2.2.2.3", self.door.lists.snapshot()["bait"])
        self.call("/rest/user/login", "2.2.2.3", "POST", body, {"Content-Type": "application/json"})
        self.assertEqual(self.call("/", "2.2.2.3")[0], 200)

    def test_client_forwarding_headers_are_replaced_in_any_case(self):
        self.call("/", "1.2.3.4", headers={"x-forwarded-for": "6.6.6.6", "X-REAL-IP": "6.6.6.6", "forwarded": "for=6.6.6.6"})
        headers = Upstream.seen[-1][1]
        self.assertEqual(headers.get_all("X-Forwarded-For"), ["1.2.3.4"])
        self.assertIsNone(headers.get("X-Real-IP"))
        self.assertIsNone(headers.get("Forwarded"))

    def test_server_header_has_no_trailing_space(self):
        status, _, headers = self.call("/.env", "1.2.3.5")
        self.assertEqual([v for k, v in headers if k.lower() == "server"], ["bouncer-door"])


ATTACKS = (
    "zz')) UNION SELECT email FROM Users--",
    "' or 1=1--",
    "admin'--",
    "1) or 1=1--",
    "' or '1'='1",
    "x' AND password IS NOT NULL--",
    "<svg/onload=alert(1)>",
    "<img src=x onmouseover=alert(1)>",
    "<body onfocus=alert(1)>",
    '" onmouseover="alert(1)',
    "<iframe src=\"javascript:alert(1)\">",
    "java\tscript:alert(1)",
    '{"email":{"$regex":".*"}}',
    '{"id":{"$nin":[]}}',
    '{"$or":[{"a":1}]}',
    '{"id":{"$in":[1]}}',
    '{"a":{"$exists":true}}',
    '{"a":{"$elemMatch":{}}}',
    '{"$where":"sleep(1000)"}',
    '{"id":{"$ne":-1}}',
    '{"a":{"$gt":""}}',
    '{"a":{"$lt":"z"}}',
    "email[$ne]=x",
    "1 AND sleep(5)",
    "../../etc/passwd",
    "..\\..\\windows",
    "<script>alert(1)</script>",
    "1 union/**/select 2",
    "x' -- y",
)
HARMLESS = (
    "O'Neil -- great",
    "kid's juice",
    "Season 2 -- the best",
    "apple juice (1000ml)",
    "online orders",
    '{"onSale":true}',
    "I'd say $5 is fine",
    "rock & roll",
    "it is not nullified",
    "or 1 more",
)


if __name__ == "__main__":
    unittest.main()
