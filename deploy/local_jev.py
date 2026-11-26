from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_plus

ATTACK = re.compile(r"union\s+select|'\s*or\s|1\s*=\s*1|--\s|<script|onerror\s*=|onload\s*=|javascript:|\.\./|\$where|\$ne|sleep\(", re.I)
SCANNER = re.compile(r"sqlmap|zgrab|nikto|nmap|masscan|nuclei|wpscan|dirbuster|gobuster|wp-login|phpmyadmin|\.php", re.I)
REQUEST = re.compile(r"<request>(.*)</request>", re.S)


def answer(state: str) -> dict:
    match = REQUEST.search(state)
    text = unquote_plus(unquote_plus(match.group(1) if match else state))
    if ATTACK.search(text):
        score, action = 0.97, "replay"
    elif SCANNER.search(text):
        score, action = 0.6, "ignore"
    else:
        score, action = 0.05, "ignore"
    return {
        "model": "local-jev-stand-in",
        "answers": {
            "malicious": {"type": "noul", "noul": score},
            "action": {"type": "choice", "choice": action, "confidence": 0.85, "probabilities": {action: 0.85}},
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            data = json.dumps(answer(str(body.get("state", "")))).encode()
            status = 200
        except ValueError:
            data, status = b'{"error":"bad json"}', 400
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8083
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
