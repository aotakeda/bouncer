# Bouncer

A security agent with a nightclub bouncer's manners, running on Fly Sprites. It stands in front of a deliberately vulnerable shop ([OWASP Juice Shop fork](https://github.com/aotakeda/juice-shop)), watches every request, and when something looks like a break-in it proves it before acting:

1. **Door** (`door/`) proxies the shop, logs traffic, serves a honeypot, refuses blocked IPs and slows down scanners.
2. **Triage** (`agent/jev.py`) asks Jev (TypeSafe connector) how malicious a request looks.
3. **Replay** (`runner/`) re-runs suspicious requests on a locked copy of the shop with no internet access, reset before every run. Proof is a solved Juice Shop challenge or a leaked canary account planted on the copy.
4. **Verdict.** Proven attackers are blocked for 15 minutes. Honeypot visitors are tarpitted, and blocked if they reuse the fake credentials.
5. **Fix** (`agent/fix.py`) finds the route's source file on GitHub, asks Claude for a minimal patch, then applies it on the replay copy, rebuilds, replays the attack and some normal requests, and rolls back. Only a patch that compiles, stops the attack and leaves normal behaviour unchanged goes forward, as a pull request on the shop's repo.

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
- The fix step takes one to two minutes. The incident then shows the patch, its diff and, when a pull request exists, a link to it.
- Each source file gets one pull request. If the hole you found already has an open Bouncer pull request, you get a link to that one instead of a duplicate. At most 3 new fix attempts run per hour.

## Run it yourself

Python 3 standard library only.

```bash
python3 -m unittest discover -s tests
```

`deploy/deploy.sh` creates the connectors, deploys the three services and locks egress (`./deploy/deploy.sh all`). `FIX_MODE` is `dry_run` (patch is tested but no pull request) or `pr`.
