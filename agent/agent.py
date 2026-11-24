from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import random
import re
import sys
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from . import net, persona
from .fix import Claude, Fixer, GitHub
from .jev import Jev
from .replay import INCONCLUSIVE, MINOR, NOT_REPRODUCED, PROVEN, Replayer

SUSPICIOUS = re.compile(
    r"""(['"`<>;$]|%27|%22|%3c|%3e|\.\./|\.\.%2f|--|/\*|\bunion\b|\bselect\b|\bsleep\(|\bor\s+1=1|\$ne|\$where|\$gt|etc/passwd|<script|onerror=|javascript:|\{\{|\$\{)""",
    re.IGNORECASE,
)
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|zgrab|masscan|nmap|dirbuster|gobuster|ffuf|wpscan|acunetix|python-requests|go-http-client|curl/|wget/|libwww", re.IGNORECASE)
PROBE_PATH = re.compile(r"\.(php|asp|aspx|jsp|cgi)\b|/wp-|/\.git|/\.env|/phpmyadmin|/cgi-bin|/actuator|/boaform|/HNAP1|/vendor/", re.IGNORECASE)

TSV_COLUMNS = ["ts", "ip", "method", "path", "kind", "jev_malicious", "jev_action", "jev_confidence", "decision", "replay_verdict", "evidence", "line"]

class Config:
    def __init__(self, env=os.environ):
        self.port = int(env.get("AGENT_PORT", "8080"))
        self.data_dir = Path(env.get("AGENT_DATA_DIR", "./agent-data"))
        self.events_sha256 = env.get("AGENT_EVENTS_SHA256", "")
        self.dash_sha256 = env.get("AGENT_DASH_SHA256", "")
        self.jev_url = env.get("JEV_URL", "")
        self.runner_url = env.get("RUNNER_URL", "")
        self.door_url = env.get("DOOR_URL", "").rstrip("/")
        self.door_token = env.get("DOOR_TOKEN", "")
        self.runner_token = env.get("RUNNER_TOKEN", "")
        self.owner_ips = {ip.strip() for ip in env.get("OWNER_IPS", "").split(",") if ip.strip()}
        self.block_seconds = int(env.get("BLOCK_SECONDS", "900"))
        self.tarpit_seconds = int(env.get("TARPIT_SECONDS", "600"))
        self.dedupe_seconds = int(env.get("DEDUPE_SECONDS", "600"))
        self.replay_threshold = float(env.get("REPLAY_THRESHOLD", "0.9"))
        self.fix_mode = env.get("FIX_MODE", "off")
        self.anthropic_url = env.get("ANTHROPIC_URL", "")
        self.github_url = env.get("GITHUB_URL", "")
        self.github_repo = env.get("GITHUB_REPO", "aotakeda/juice-shop")
        self.github_branch = env.get("GITHUB_BRANCH", "master")
        self.fix_model = env.get("FIX_MODEL", "claude-opus-5-5")
        self.fix_per_hour = int(env.get("FIX_PER_HOUR", "3"))
        self.app_description = env.get(
            "APP_DESCRIPTION",
            "OWASP Juice Shop, an Angular + Express + SQLite online juice store with a REST API under /rest and /api. Not WordPress, no PHP.",
        )

def shape(event: dict) -> str:
    path = event.get("path", "")
    bare, _, query = path.partition("?")
    keys = ",".join(sorted(parse_qs(query, keep_blank_values=True).keys()))
    return f"{event.get('method')} {bare}?{keys}"

class Brain:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.tsv = cfg.data_dir / "decisions.tsv"
        if not self.tsv.exists():
            self.tsv.write_text("\t".join(TSV_COLUMNS) + "\n")
        self.jev = Jev(cfg.jev_url, cfg.app_description) if cfg.jev_url else None
        self.replayer = Replayer(cfg.runner_url, cfg.runner_token) if cfg.runner_url else None
        self.fixer = None
        if cfg.fix_mode in ("dry_run", "pr") and cfg.anthropic_url and cfg.github_url and cfg.runner_url:
            self.fixer = Fixer(
                cfg.fix_mode,
                Claude(cfg.anthropic_url, cfg.fix_model),
                GitHub(cfg.github_url, cfg.github_repo, cfg.github_branch),
                cfg.runner_url,
                cfg.runner_token,
                max_per_hour=cfg.fix_per_hour,
            )
        self.inbox: queue.Queue = queue.Queue(maxsize=20000)
        self.recent: deque = deque(maxlen=300)
        self.seen: dict = {}
        self.per_ip: dict = {}
        self.honeypot_visits: dict = {}
        self.shame: Counter = Counter()
        self.stats: Counter = Counter()
        self.incidents: list = []
        self.listeners: list = []
        self.lock = threading.Lock()
        self.rng = random.Random()
        threading.Thread(target=self._work, daemon=True).start()

    def submit(self, events: list):
        for e in events:
            try:
                self.inbox.put_nowait(e)
            except queue.Full:
                self.stats["dropped"] += 1

    def _work(self):
        while True:
            event = self.inbox.get()
            net.hold_awake("bouncer-incident", 300)
            try:
                self.handle(event)
            except Exception as exc:
                self.emit({"ts": time.time(), "ip": event.get("ip"), "path": event.get("path"), "decision": "error", "line": f"agent error: {exc}"[:300]})
            if self.inbox.empty():
                net.release_awake("bouncer-incident")

    def history(self, ip: str) -> str:
        items = self.per_ip.get(ip, [])[-5:]
        return "; ".join(f"{d['method']} {d['path'][:80]} -> {d['decision']}" for d in items)

    def handle(self, event: dict):
        ip = event.get("ip", "?")
        kind = event.get("kind", "request")
        self.stats["events"] += 1
        record = {
            "ts": event.get("ts", time.time()),
            "ip": ip,
            "method": event.get("method"),
            "path": event.get("path", ""),
            "kind": kind,
            "ua": event.get("ua", ""),
        }
        if kind in ("refused", "tarpitted"):
            self.stats[kind] += 1
            return
        if kind == "honeypot":
            self.honeypot_visits[ip] = record["ts"]
            self.shame[event.get("path", "")] += 1
            self.set_list("tarpit", ip, self.cfg.tarpit_seconds, "took the honeypot .env")
            return self.decide(record, "tarpit", line=persona.line("honeypot", self.rng))
        if kind == "canary_reuse":
            story = ""
            if self.honeypot_visits:
                origin_ip, origin_ts = max(self.honeypot_visits.items(), key=lambda kv: kv[1])
                who = "this same client" if origin_ip == ip else f"{self.mask(origin_ip)}"
                story = f" Keys were taken from the fake .env by {who} at {time.strftime('%H:%M:%S', time.gmtime(origin_ts))} UTC."
            self.set_list("block", ip, self.cfg.block_seconds, "reused honeypot credentials")
            return self.decide(record, "block", line=persona.line("canary_reuse", self.rng) + story)
        if event.get("path", "").startswith("/socket.io/"):
            self.stats["prefiltered"] += 1
            return
        text = f"{event.get('path', '')} {event.get('body', '')}"
        suspicious = bool(SUSPICIOUS.search(text))
        key = (ip, shape(event), hashlib.sha256(text.encode()).hexdigest() if suspicious else "")
        prior = self.seen.get(key)
        if prior and record["ts"] - prior["ts"] < self.cfg.dedupe_seconds:
            prior["count"] += 1
            self.stats["deduped"] += 1
            return
        scanner = bool(SCANNER_UA.search(event.get("ua", "")))
        probe = bool(PROBE_PATH.search(event.get("path", "")))
        failed = (event.get("status") or 0) >= 400
        if not (suspicious or scanner or probe or failed):
            self.stats["prefiltered"] += 1
            return
        self.seen[key] = {"ts": record["ts"], "count": 1}
        if probe:
            self.shame[event.get("path", "").split("?", 1)[0]] += 1
        triage = self.jev.triage(event, self.history(ip)) if self.jev else {"ok": False, "error": "jev not configured"}
        record["jev"] = triage
        if not triage.get("ok"):
            action = "watch"
        else:
            action = triage.get("action") or "watch"
            if action in ("block", "tarpit") and (triage.get("confidence") or 0) < 0.5 and (triage.get("malicious") or 0) < 0.8:
                action = "watch"
            if (triage.get("malicious") or 0) >= self.cfg.replay_threshold and action in ("block", "tarpit") and not probe:
                action = "replay"
        if action == "replay" and self.replayer:
            self.decide(record, "replay", line=persona.line("replay", self.rng))
            result = self.replayer.run(event)
            record = dict(record)
            record["replay"] = result
            verdict = result["verdict"]
            if verdict == PROVEN:
                self.set_list("block", ip, self.cfg.block_seconds, "proven exploit: " + result["why"][:120])
                incident = {"ts": time.time(), "ip": ip, "event": event, "replay": result}
                self.incidents.append(incident)
                self.decide(record, "block", line=persona.line("proven", self.rng))
                if self.fixer:
                    queued = self.fixer.submit(incident, self.fix_report)
                    incident["fix"] = {"status": queued, "line": "Fix queued." if queued == "queued" else f"No fix attempt: {queued}."}
                return
            if verdict == NOT_REPRODUCED:
                if (triage.get("malicious") or 0) >= 0.7:
                    self.set_list("tarpit", ip, self.cfg.tarpit_seconds, "failed attack attempt")
                    return self.decide(record, "tarpit", line=persona.line("not_reproduced", self.rng))
                return self.decide(record, "watch", line=persona.line("not_reproduced", self.rng))
            if verdict == INCONCLUSIVE:
                return self.decide(record, "watch", line=persona.line("inconclusive", self.rng))
            if verdict == MINOR:
                return self.decide(record, "watch", line=persona.line("minor", self.rng))
            return self.decide(record, "watch", line=f"Back room is jammed ({result.get('why')}). Watching instead.")
        if action == "block":
            self.set_list("block", ip, self.cfg.block_seconds, "jev: block")
            return self.decide(record, "block", line=persona.line("block", self.rng))
        if action == "tarpit":
            self.set_list("tarpit", ip, self.cfg.tarpit_seconds, "jev: tarpit")
            return self.decide(record, "tarpit", line=persona.line("tarpit", self.rng))
        if action == "ignore":
            return self.decide(record, "ignore", line=persona.line("ignore_probe" if (probe or scanner) else "ignore", self.rng))
        return self.decide(record, "watch", line=persona.line("watch", self.rng))

    def fix_report(self, incident: dict, fix: dict):
        incident["fix"] = fix
        event = incident["event"]
        record = {"ts": time.time(), "ip": incident["ip"], "method": event.get("method"), "path": event.get("path", ""), "kind": "fix"}
        record["replay"] = {"verdict": fix.get("status", "").upper(), "evidence": {k: fix[k] for k in ("file", "pr_url") if fix.get(k)}}
        self.decide(record, "fix", line=fix.get("line", ""))

    def set_list(self, kind: str, ip: str, seconds: int, reason: str) -> bool:
        if ip in self.cfg.owner_ips or not self.cfg.door_url:
            return False
        endpoint = "blocklist" if kind == "block" else "tarpit"
        status, _, _ = net.request(
            f"{self.cfg.door_url}/_bouncer/{endpoint}",
            "PUT",
            {ip: {"until": time.time() + seconds, "reason": reason}},
            timeout=15,
            headers={"Authorization": f"Bearer {self.cfg.door_token}"} if self.cfg.door_token else None,
        )
        self.stats[f"{kind}_sent" if status == 200 else f"{kind}_failed"] += 1
        return status == 200

    def mask(self, ip: str) -> str:
        return "you (owner)" if ip in self.cfg.owner_ips else ip

    def decide(self, record: dict, decision: str, line: str):
        record = dict(record)
        if record.get("ip") in self.cfg.owner_ips and decision in ("block", "tarpit"):
            decision = "would_" + decision
            line = f"That's you, boss. Anyone else gets a {decision[6:]} here. ({line})"
        record["decision"] = decision
        record["line"] = line
        self.stats[decision] += 1
        self.per_ip.setdefault(record["ip"], []).append(record)
        self.per_ip[record["ip"]] = self.per_ip[record["ip"]][-20:]
        self.write_tsv(record)
        self.emit(record)

    def write_tsv(self, r: dict):
        jev = r.get("jev") or {}
        rep = r.get("replay") or {}
        row = [
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.get("ts", time.time()))),
            r.get("ip", ""),
            r.get("method") or "",
            r.get("path", "")[:300],
            r.get("kind", ""),
            str(jev.get("malicious", "")),
            str(jev.get("action", "")),
            str(jev.get("confidence", "")),
            r.get("decision", ""),
            rep.get("verdict", ""),
            json.dumps(rep.get("evidence", {}), separators=(",", ":")) if rep else "",
            r.get("line", ""),
        ]
        clean = [str(c).replace("\t", " ").replace("\n", " ") for c in row]
        with self.lock:
            with self.tsv.open("a") as f:
                f.write("\t".join(clean) + "\n")

    def public_view(self, r: dict) -> dict:
        jev = r.get("jev") or {}
        rep = r.get("replay") or {}
        return {
            "ts": r.get("ts"),
            "ip": self.mask(r.get("ip", "")),
            "method": r.get("method"),
            "path": (r.get("path") or "")[:200],
            "decision": r.get("decision"),
            "line": r.get("line"),
            "malicious": jev.get("malicious"),
            "jev_action": jev.get("action"),
            "confidence": jev.get("confidence"),
            "verdict": rep.get("verdict"),
            "why": rep.get("why"),
        }

    def emit(self, record: dict):
        view = self.public_view(record)
        self.recent.append(view)
        for q in list(self.listeners):
            try:
                q.put_nowait(view)
            except queue.Full:
                pass

    @staticmethod
    def fix_view(fix: dict | None) -> dict | None:
        if not fix:
            return None
        url = fix.get("pr_url") or ""
        return {
            "status": fix.get("status"),
            "line": fix.get("line"),
            "file": fix.get("file"),
            "summary": fix.get("summary"),
            "diff": (fix.get("diff") or "")[:6000],
            "pr_url": url if url.startswith("https://github.com/") else "",
        }

    def state(self) -> dict:
        return {
            "stats": dict(self.stats),
            "recent": list(self.recent)[-100:],
            "shame": [{"path": p, "count": c, "caption": persona.shame_caption(p, c)} for p, c in self.shame.most_common(10)],
            "incidents": [
                {"ts": i["ts"], "ip": self.mask(i["ip"]), "path": i["event"].get("path"), "why": i["replay"].get("why"), "fix": self.fix_view(i.get("fix"))}
                for i in self.incidents[-20:]
            ],
        }

DASHBOARD = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Bouncer</title><style>
:root{--bg:#0e0e12;--fg:#ececf1;--mute:#8b8b99;--card:#18181f;--line:#26262f;--red:#ff5d5d;--amber:#ffb547;--green:#4ade80;--blue:#7aa2ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 ui-sans-serif,system-ui,-apple-system,sans-serif}
header{padding:20px 16px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
h1{margin:0;font-size:22px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute);margin:0 0 10px}
main{display:grid;grid-template-columns:2fr 1fr;gap:16px;padding:16px;max-width:1200px;margin:auto}@media(max-width:800px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stats{display:flex;gap:18px;flex-wrap:wrap;color:var(--mute)}.stats b{color:var(--fg);font-size:18px;display:block}
.ev{border-top:1px solid var(--line);padding:10px 0}.ev:first-child{border-top:0}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;margin-right:6px;background:var(--line)}
.block{background:var(--red);color:#000}.tarpit{background:var(--amber);color:#000}.replay{background:var(--blue);color:#000}.ignore{background:#2a2a33}.watch{background:#3a3a46}.would_block,.would_tarpit{background:#3a3a46;outline:1px dashed var(--red)}
.PROVEN{background:var(--red);color:#000}.fix,.READY,.PR_OPENED{background:var(--green);color:#000}.FAILED,.PR_FAILED{background:var(--amber);color:#000}
pre{font:12px/1.4 ui-monospace,monospace;background:#0b0b0f;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:360px}.add{color:var(--green)}.del{color:var(--red)}a{color:var(--blue)}.NOT_REPRODUCED{background:var(--green);color:#000}
code{font:12px ui-monospace,monospace;color:var(--mute);word-break:break-all}.line{margin:4px 0 0}.meta{color:var(--mute);font-size:12px}
</style></head><body><header><h1>Bouncer</h1><span class=meta>Personal security agent at the door of a deliberately vulnerable OWASP Juice Shop</span></header>
<main><section class=card><h2>Tonight at the door</h2><div class=stats id=stats></div><div id=feed></div></section>
<aside><div class="card"><h2>Wall of shame</h2><div id=shame></div></div><div class="card" style="margin-top:16px"><h2>Proven break-ins</h2><div id=inc></div></div></aside></main>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=ts=>new Date(ts*1000).toLocaleTimeString();
function ev(e){const pct=v=>v==null?'':Math.round(v*100)+'%';return `<div class=ev><span class="tag ${esc(e.decision)}">${esc(e.decision)}</span>${e.verdict?`<span class="tag ${esc(e.verdict)}">${esc(e.verdict)}</span>`:''}<span class=meta>${t(e.ts)} · ${esc(e.ip)}${e.malicious!=null?` · Jev: attack ${pct(e.malicious)}, says ${esc(e.jev_action)} (${pct(e.confidence)} sure)`:''}</span><div><code>${esc(e.method)} ${esc(e.path)}</code></div><p class=line>${esc(e.line)}${e.why?` <span class=meta>(${esc(e.why)})</span>`:''}</p></div>`}
const colour=d=>esc(d).split('\\n').map(l=>l.startsWith('+')&&!l.startsWith('+++')?`<span class=add>${l}</span>`:l.startsWith('-')&&!l.startsWith('---')?`<span class=del>${l}</span>`:l).join('\\n');
function fx(f){if(!f)return '';return `<p class=line><span class="tag ${esc((f.status||'').toUpperCase())}">fix: ${esc(f.status)}</span>${esc(f.line)}${f.pr_url?` <a href="${esc(f.pr_url)}" target=_blank rel=noopener>pull request</a>`:''}</p>${f.summary?`<p class="line meta">${esc(f.summary)}</p>`:''}${f.diff?`<details><summary class=meta>patch for ${esc(f.file)}</summary><pre>${colour(f.diff)}</pre></details>`:''}`}
const feed=document.getElementById('feed');
function render(s){const st=s.stats||{};document.getElementById('stats').innerHTML=[['events','seen'],['prefiltered','waved through'],['replay','replayed'],['block','bounced'],['tarpit','slow-laned'],['refused','refused at door']].map(([k,l])=>`<div><b>${st[k]||0}</b>${l}</div>`).join('');
document.getElementById('shame').innerHTML=(s.shame||[]).map(x=>`<div class=ev><code>${esc(x.path)}</code><p class=line>${esc(x.caption)}</p></div>`).join('')||'<p class=meta>Nobody embarrassing yet.</p>';
document.getElementById('inc').innerHTML=(s.incidents||[]).map(x=>`<div class=ev><span class=meta>${t(x.ts)} · ${esc(x.ip)}</span><div><code>${esc(x.path)}</code></div><p class=line>${esc(x.why)}</p>${fx(x.fix)}</div>`).join('')||'<p class=meta>No proven break-ins.</p>'}
fetch('api/state').then(r=>r.json()).then(s=>{render(s);feed.innerHTML=(s.recent||[]).slice().reverse().map(ev).join('')});
const es=new EventSource('stream');es.onmessage=m=>{feed.insertAdjacentHTML('afterbegin',ev(JSON.parse(m.data)));fetch('api/state').then(r=>r.json()).then(render)};
</script></body></html>"""

LOGIN = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Bouncer</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e0e12;color:#ececf1;font:16px system-ui,sans-serif}form{display:flex;gap:8px;padding:16px}input,button{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #333;background:#18181f;color:inherit}</style></head>
<body><form method=post action=login><input type=password name=passphrase placeholder="What's the password?" autofocus><button>Let me in</button></form></body></html>"""

def make_handler(brain: Brain):
    cfg = brain.cfg

    def cookie_value() -> str:
        return hmac.new(cfg.dash_sha256.encode(), b"bouncer-dashboard", hashlib.sha256).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "bouncer"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def reply(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def bearer_ok(self, expected_sha: str) -> bool:
            header = self.headers.get("Authorization", "")
            if not expected_sha or not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(hashlib.sha256(header[7:].encode()).hexdigest(), expected_sha)

        def dash_ok(self) -> bool:
            if not cfg.dash_sha256:
                return False
            cookies = dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p)
            return hmac.compare_digest(cookies.get("bouncer", ""), cookie_value())

        def body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n > 0 else b""

        def do_POST(self):
            data = self.body()
            if self.path == "/events":
                if not self.bearer_ok(cfg.events_sha256):
                    return self.reply(404, b"not found", "text/plain")
                try:
                    events = json.loads(data).get("events", [])
                except (ValueError, AttributeError):
                    return self.reply(400, b"bad json", "text/plain")
                brain.submit(events)
                return self.reply(202, json.dumps({"accepted": len(events)}).encode(), "application/json")
            if self.path == "/login":
                given = parse_qs(data.decode("utf-8", "replace")).get("passphrase", [""])[0]
                if cfg.dash_sha256 and hmac.compare_digest(hashlib.sha256(given.encode()).hexdigest(), cfg.dash_sha256):
                    return self.reply(
                        303,
                        b"",
                        "text/plain",
                        {"Location": "./", "Set-Cookie": f"bouncer={cookie_value()}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800"},
                    )
                time.sleep(1)
                return self.reply(401, LOGIN.encode(), "text/html; charset=utf-8")
            return self.reply(404, b"not found", "text/plain")

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                return self.reply(200, b"ok", "text/plain")
            if not self.dash_ok():
                return self.reply(200, LOGIN.encode(), "text/html; charset=utf-8")
            if path == "/":
                return self.reply(200, DASHBOARD.encode(), "text/html; charset=utf-8")
            if path == "/api/state":
                return self.reply(200, json.dumps(brain.state()).encode(), "application/json")
            if path == "/stream":
                return self.stream()
            return self.reply(404, b"not found", "text/plain")

        def stream(self):
            q: queue.Queue = queue.Queue(maxsize=500)
            brain.listeners.append(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                while True:
                    try:
                        item = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except OSError:
                pass
            finally:
                brain.listeners.remove(q)

    return Handler

def main():
    cfg = Config()
    brain = Brain(cfg)
    server = ThreadingHTTPServer(("0.0.0.0", cfg.port), make_handler(brain))
    server.daemon_threads = True
    print(json.dumps({"agent": "listening", "port": cfg.port, "jev": bool(cfg.jev_url), "runner": bool(cfg.runner_url), "door": bool(cfg.door_url)}), flush=True)
    server.serve_forever()

if __name__ == "__main__":
    sys.exit(main())
