<h1><img src="assets/bouncer-mark.svg" alt="" width="28" height="28" align="absmiddle">&nbsp;Bouncer</h1>

A personal night-shift security agent with a nightclub bouncer's manners, running on Fly Sprites. It stands at the door of a side project—here, a deliberately vulnerable shop ([OWASP Juice Shop fork](https://github.com/aotakeda/juice-shop))—watches every request while you sleep, proves real break-ins on an air-gapped stunt double before acting, and leaves a verified pull request waiting for you to review:

1. **Door** (`door/`) proxies the shop, logs traffic, serves a fake `/.env` honeypot, refuses blocked IPs and slows down scanners.
2. **Triage** (`agent/jev.py`) asks Jev (TypeSafe connector) how malicious a request looks and what to do.
3. **Replay** (`runner/`) re-runs suspicious requests against a harmless control on an air-gapped copy of the shop (`egress: deny *`, minimal privileges), reset before every run. Proof is an app-agnostic canary account leak or Juice Shop's built-in challenge oracle.
4. **Verdict.** Non-probe traffic is never blocked on a guess—proven attackers are bounced for 5 minutes (`BLOCK_SECONDS`). Honeypot visitors are tarpitted, and blocked immediately if they reuse the fake credentials.
5. **Fix** (`agent/fix.py`) finds the route's source file on GitHub, asks Claude for a minimal patch, and asks Claude separately for up to four other ways into the same hole. The stunt double tries those variants before the patch (resetting after each solved challenge), applies the patch, rebuilds with `tsc`, replays the original attack, normal smoke/control checks and every variant, then rolls back. Only a patch that compiles, blocks the attack and all variants without crashing, and leaves normal behaviour unchanged goes forward as a pull request (example: [PR #1](https://github.com/aotakeda/juice-shop/pull/1)).

## Architecture

```
Internet ──► bh-app (role:app, egress: api.sprites.dev only)
              │  door.py (:8080) ──► Juice Shop (:3000)
              │  [POST /events via Custom API connector]
              ▼
             bh-bouncer (role:bouncer, egress: api.sprites.dev only)
              │  agent.py (:8080) — live SSE dashboard + unblock control
              ├──► TypeSafe connector (Jev System One triage)
              ├──► Anthropic connector (Claude patch + attack variants)
              ├──► GitHub connector (scoped to aotakeda/juice-shop)
              ├──► Custom API connector ──► bh-app /_bouncer/* (block/tarpit/unblock)
              └──► Custom API connector ──► bh-replay /replay /patch /reset /health
                                              │
                                             bh-replay (egress: DENY *, minimal privileges)
                                              runner.py (:8080) ──► Stunt-double Juice Shop (:3000)
```

No Sprite holds a single raw secret: inbound tokens are stored only as SHA-256 hashes, every outbound secret lives in the Sprites gateway, and `agent/net.py` holds wake-locks via `/.sprite/api.sock` so auto-sleeping Sprites never cut off an in-flight replay or build.

## Try it

| | |
|---|---|
| Shop (attack this) | https://bh-app-ykmo.sprites.app |
| Dashboard | https://bh-bouncer-ykmo.sprites.app (passphrase in the submission notes) |
| Example Bouncer PR | https://github.com/aotakeda/juice-shop/pull/1 |

Open the dashboard first, then run these in order from a terminal (if you get blocked, click **Unblock** in the dashboard's **Blocked right now** panel to jump straight to the next test):

**1. Knock on a WordPress door (Most probed paths, no block):**

```bash
curl -s -A 'zgrab/0.x' https://bh-app-ykmo.sprites.app/wp-login.php
```

**2. Take the `/.env` bait (tarpit), then reuse the fake credentials (block):**

```bash
curl -s https://bh-app-ykmo.sprites.app/.env
```

Try logging in to the shop with the `ADMIN_EMAIL` and `ADMIN_PASSWORD` from that fake file to trigger an instant canary-reuse block, then click **Unblock** on the dashboard.

**3. Dump the users table through product search (UNION injection + canary proof + live patch & variants):**

```bash
curl -s -A 'sqlmap/1.8' "https://bh-app-ykmo.sprites.app/rest/products/search?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"zz')) UNION SELECT id,email,password,'4','5','6','7','8','9','10' FROM Users--\"))")"
```

**4. Log in as the admin without a password (SQL injection → reuses existing [PR #1](https://github.com/aotakeda/juice-shop/pull/1)):**

```bash
curl -s -A 'sqlmap/1.8' -H 'Content-Type: application/json' -d '{"email":"'"'"' or 1=1-- judge1","password":"x"}' https://bh-app-ykmo.sprites.app/rest/user/login
```

## What to expect

- The dashboard shows the request, Jev's score, the replay verdict and the bouncer's line within a few seconds.
- After a **proven** attack your IP is blocked from the shop for 5 minutes (`403`). The dashboard stays reachable and lets you unblock yourself in one click under **Blocked right now** so you can try the other commands immediately.
- The same request from the same IP within 10 minutes is counted once (change the text after `--` in the payload to re-trigger).
- After taking the `/.env` bait, requests from that IP are held for 10 seconds each (up to five at a time), for 10 minutes. That is the tarpit, not an outage.
- Blocks and tarpits are per IP, so people behind one shared address are blocked together. The owner can adjust the duration with `BLOCK_SECONDS`.
- The owner's IP is never blocked; Bouncer says what it would have done. To see a real block from the owner's network, add `-H 'X-Bouncer-Stranger: 1'` to the request, then click **Unblock** on the dashboard or run `./deploy/deploy.sh unblock owner-as-stranger`.
- If the hole already has an open Bouncer pull request (the login injection has [PR #1](https://github.com/aotakeda/juice-shop/pull/1)), the incident links straight to it. A hole without one goes through the fix step (1–2 minutes) and shows the patch diff and before/after variants table right on the dashboard.
- Each source file gets at most one open pull request, and at most 3 new fix attempts run per hour.
- **Scope note:** Canary-leak detection, honeypots, Jev triage and the Claude patch/variant verifier are app-agnostic; OWASP Juice Shop adds a convenient `/api/Challenges` exploit oracle alongside the canary checks. Normal `200`/`201` requests without suspicious syntax or scanner headers are prefiltered before triage to keep noise low.

## Run it yourself

Python 3 standard library only.

```bash
python3 -m unittest discover -s tests
```

`deploy/deploy.sh` creates or updates the three internal Custom API links between the Sprites, deploys the three services and locks egress (`./deploy/deploy.sh all`). `FIX_MODE` is `dry_run` (patch is verified on the stunt double without opening a PR) or `pr`.

The script assumes:

- the `sprite` CLI is installed and logged in;
- three Sprites named `bh-app`, `bh-replay` and `bh-bouncer` already exist, with the shop Sprite labelled `role:app` and the agent Sprite labelled `role:bouncer` (the links' access policies refer to those labels);
- TypeSafe, Anthropic and GitHub connectors are already set up in the Sprites account (the script looks them up by provider);
- optionally, an `OWNER_IP=<your public IP>` line in `.secrets`, so you are never blocked yourself.

To rotate the dashboard passphrase, change `DASH_PASSPHRASE` in `.secrets` and run `./deploy/deploy.sh services` again. To pull a merged Bouncer PR onto the shop and stunt double, run `./deploy/deploy.sh refresh`.

Every block can also be inspected or undone from the CLI:

```bash
./deploy/deploy.sh blocks
./deploy/deploy.sh unblock 203.0.113.7
```
