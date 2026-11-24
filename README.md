# Bouncer

A security agent with a nightclub bouncer's manners, running on Fly Sprites. It stands in front of a deliberately vulnerable shop ([OWASP Juice Shop fork](https://github.com/aotakeda/juice-shop)), watches every request, and when something looks like a break-in it proves it before acting:

1. **Door** (`door/`) proxies the shop, logs traffic, serves a honeypot, refuses blocked IPs and slows down scanners.
2. **Triage** (`agent/jev.py`) asks Jev (TypeSafe connector) how malicious a request looks.
3. **Replay** (`runner/`) re-runs suspicious requests on a locked copy of the shop with no internet access, reset before every run. Proof is a solved Juice Shop challenge or a leaked canary account planted on the copy.
4. **Verdict.** Proven attackers are blocked for 15 minutes. Honeypot visitors are tarpitted, and blocked if they reuse the fake credentials.
5. **Fix** (`agent/fix.py`) finds the route's source file on GitHub, asks Claude for a minimal patch, and asks Claude separately for up to four other ways into the same hole. The replay copy tries those variants, applies the patch, rebuilds, replays the attack, the variants and some normal requests, then rolls back. Only a patch that compiles, stops the attack and every variant, and leaves normal behaviour unchanged goes forward, as a pull request on the shop's repo.

The three Sprites talk only through Sprites connectors. Secrets live in the gateway, not on the machines, and egress is locked down.

## Try it

| | |
|---|---|
| Shop (attack this) | https://bh-app-ykmo.sprites.app |
| Dashboard | https://bh-bouncer-ykmo.sprites.app (passphrase in the submission notes) |

Open the dashboard first, then try one of these from a terminal.

**Log in as the admin without a password (SQL injection):**

```bash
curl -s -A 'sqlmap/1.8' -H 'Content-Type: application/json' -d '{"email":"'"'"' or 1=1-- judge1","password":"x"}' https://bh-app-ykmo.sprites.app/rest/user/login
```

**Dump the users table through product search (UNION injection):**

```bash
curl -s -A 'sqlmap/1.8' "https://bh-app-ykmo.sprites.app/rest/products/search?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"zz')) UNION SELECT id,email,password,'4','5','6','7','8','9','10' FROM Users--\"))")"
```

**Take the bait:**

```bash
curl -s https://bh-app-ykmo.sprites.app/.env
```

Then log in to the shop with the admin email and password you found in that file.

## What to expect

- The dashboard shows the request, Jev's score, the replay verdict and the bouncer's line within a few seconds.
- After a **proven** attack your IP is blocked from the shop for 15 minutes (`403`). The dashboard stays reachable. Use a different network, or change the text after `--` in the payload and wait, to try again later.
- The same request from the same IP within 10 minutes is counted once.
- After taking the `/.env` bait, requests from that IP are held for 10 seconds each (up to five at a time), for 10 minutes. That is the tarpit, not an outage.
- Blocks and tarpits are per IP, so people behind one shared address are blocked together. The owner can shorten blocks by deploying with `BLOCK_SECONDS` set.
- The owner's IP is never blocked; Bouncer says what it would have done. To see a real block from the owner's network, add `-H 'X-Bouncer-Stranger: 1'` to the request, then clear it with `./deploy/deploy.sh unblock owner-as-stranger`.
- If the hole already has an open Bouncer pull request (the login injection has one), the incident shows only a link to that pull request, which carries the diff and the verification table. A hole without one goes through the fix step, which takes one to two minutes, and the incident then shows the patch, its diff and the variants tried before and after it.
- Each source file gets one pull request. If the hole you found already has an open Bouncer pull request, you get a link to that one instead of a duplicate. At most 3 new fix attempts run per hour.

## Limits

- One replay can't prove an attack that needs a logged-in session or several steps. Those are marked inconclusive and watched.
- Bouncer acts after the fact. The first request reaches the real shop while the copy is being tested. The block stops what follows, and only from that IP.
- Request bodies over 64 KB are cut before replay and marked inconclusive.
- Request bodies, including credentials on login requests, are logged at the door and shown to Jev when a request looks suspicious or fails. Fine for a demo shop, not for production.
- Fixes are limited to a single route file under `routes/` (the replay copy additionally refuses to write anything outside `routes/`, `lib/`, `models/` or `server.ts`), and nothing merges without the owner.
- The attack text is part of what Claude reads when writing a patch. The patch is confined to one file, tested on the isolated copy and never merged without the owner, which is what limits a prompt-injection attempt.
- The live demo runs in dry run: patches are tested and shown on the dashboard, and pull requests are switched on only for the owner's own runs.

## Run it yourself

Python 3 standard library only.

```bash
python3 -m unittest discover -s tests
```

`deploy/deploy.sh` creates the three internal Custom API links between the Sprites, deploys the three services and locks egress (`./deploy/deploy.sh all`). `FIX_MODE` is `dry_run` (patch is tested but no pull request) or `pr`.

The script assumes:

- the `sprite` CLI is installed and logged in;
- three Sprites named `bh-app`, `bh-replay` and `bh-bouncer` already exist, with the shop Sprite labelled `role:app` and the agent Sprite labelled `role:bouncer` (the links' access policies refer to those labels);
- TypeSafe, Anthropic and GitHub connectors are already set up in the Sprites account (the script looks them up by provider);
- optionally, an `OWNER_IP=<your public IP>` line in `.secrets`, so you are never blocked yourself.

To rotate the dashboard passphrase, change `DASH_PASSPHRASE` in `.secrets` and run `./deploy/deploy.sh services` again.

Every block can be undone with one command:

```bash
./deploy/deploy.sh blocks
```

```bash
./deploy/deploy.sh unblock 203.0.113.7
```
