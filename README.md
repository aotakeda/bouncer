<h1><img src="assets/bouncer-mark.svg" alt="" width="28" height="28" align="absmiddle">&nbsp;Bouncer</h1>

Bouncer is a personal security agent for small side projects that can't afford a dedicated Security Engineer. I built it on Fly.io Sprites for the [Fly.io Hacksgiving](https://fly.io/hacksgiving). It runs on three Sprites and uses three Sprites connectors: **TypeSafe** for Jev, **Anthropic** for Claude, and **GitHub** for the pull requests.

It watches every request going to your app. When one looks like an attack, Bouncer sends it again to an isolated copy of the app. If the attack works there, Bouncer blocks the attacker, writes a fix, tests the fix on the copy and opens a pull request for you to review. It never blocks on a guess.

[![Bouncer demo: an attack is replayed on an isolated copy, proven and blocked](assets/bouncer-demo.gif)](https://youtu.be/hoPfVTCOYbQ)

**[Watch the 80-second demo](https://youtu.be/hoPfVTCOYbQ)**

The video is a scripted re-creation of the dashboard and the pull request, not a screen recording. The live demo below is the real thing. Music: "Happiness" and "Nightfall" by Scott Buckley ([www.scottbuckley.com.au](https://www.scottbuckley.com.au)), released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Both are excerpted, and the opening of "Happiness" is distorted.

| Part | Runs on |
|---|---|
| Shop and proxy | Fly.io Sprite `bh-app` |
| Replay server, an isolated copy of the shop with no internet access | Fly.io Sprite `bh-replay` |
| Agent and dashboard | Fly.io Sprite `bh-bouncer` |
| Triage | TypeSafe's Jev System One, through the Sprites **TypeSafe** connector |
| Patches and attack versions | Claude, through the Sprites **Anthropic** connector |
| Pull requests | The Sprites **GitHub** connector |

The app in this demo is a fork of [OWASP Juice Shop](https://github.com/aotakeda/juice-shop), a web shop with known security holes.

## Try the live demo

| What | Where |
|---|---|
| Shop (send the attacks here) | https://bh-app-ykmo.sprites.app |
| Dashboard | https://bh-bouncer-ykmo.sprites.app |
| Fix for the login hole | https://github.com/aotakeda/juice-shop/pull/3 |
| Fix for the search hole | https://github.com/aotakeda/juice-shop/pull/4 |

1. Open the dashboard and log in. **The passphrase is in the Hacksgiving submission form**, in the answer to "Is there anything else you'd like the judges to know?".
2. Keep the dashboard open while you run the tests below in order. You only need `curl`.

> **CAUTION:** Blocks and slowdowns apply to your whole IP address. Anyone else on your network gets blocked or slowed down with you.

> **CAUTION:** Tests 2, 3 and 4 send real attacks. Send them only to the demo shop above or to your own local copy, never to another site.

The Sprites go to sleep when nobody uses them, so your first request can take around 10 seconds, and the first replay after a quiet spell can take around 20 seconds while the replay server wakes up.

On the Sprites a block lands about 10 to 20 seconds after the attack (about 3 seconds locally). If the dashboard stops updating or asks for the passphrase again, log in again.

The dashboard shows each request's outcome as **Allowed**, **Testing**, **Slowed** or **Blocked**. The agent's decisions behind them are `ignore` or `watch`, `replay`, `tarpit` and `block`.

### Test 1: Send a scanner request

```bash
curl -s -A 'zgrab/0.x' https://bh-app-ykmo.sprites.app/wp-login.php
```

What you should see:

- The shop returns its normal page.
- The dashboard shows the request as **Allowed** (`ignore`), and `/wp-login.php` appears under **Probed paths**. The count doesn't go up for repeats from the same client.
- You are not blocked or slowed down. A single probe is always allowed, whatever Jev says. A client that probes 5 different paths within 10 minutes gets slowed down.

### Test 2: Take the bait, then use it

1. Fetch the fake `.env` file:

   ```bash
   curl -s https://bh-app-ykmo.sprites.app/.env
   ```

2. Put its `ADMIN_EMAIL` and `ADMIN_PASSWORD` values into this command, then run it:

   ```bash
   curl -s -H 'Content-Type: application/json' -d '{"email":"ADMIN_EMAIL","password":"ADMIN_PASSWORD"}' https://bh-app-ykmo.sprites.app/rest/user/login
   ```

What you should see:

- Step 1 returns a fake `.env` file, and the dashboard shows it as **Slowed** (`tarpit`). Fetching it again doesn't add more rows.
- From then on, each of your requests takes 10 seconds, for 10 minutes. That's the slowdown, not an outage. Bouncer still checks everything you send while you're slowed down, so an attack that works still gets you blocked.
- Step 2 takes 10 seconds and the shop returns `401`.
- You're blocked right after that. The shop returns `403` for 5 minutes.
- The dashboard shows **Blocked**, and the **Blocked** panel gives the reason "reused honeypot credentials".

To keep going, find your IP address in the dashboard's **Blocked** panel and click **Unblock**. That clears the block, the slowdown and the record that you took the bait.

### Test 3: Dump the users table through product search

```bash
curl -s -A 'sqlmap/1.8' "https://bh-app-ykmo.sprites.app/rest/products/search?q=zz%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword%2C%274%27%2C%275%27%2C%276%27%2C%277%27%2C%278%27%2C%279%27%2C%2710%27%20FROM%20Users--%20demo1"
```

Then open [pull request #4](https://github.com/aotakeda/juice-shop/pull/4) and click **Unblock** on the dashboard.

What you should see:

- The shop returns `200` with user emails and password hashes in `data`, because the fix isn't merged yet. If someone else proved this hole in the last 24 hours, the route is shielded instead and the shop returns `403` with "This route is shielded until its security fix is merged". Both are expected.
- The dashboard shows a high Jev score and **Testing** while the attack is replayed, then **Blocked**. The request's replay result is **proven**, and the signal says "Proven on the stunt double": the attack leaked test-account values that a harmless control request didn't. A shielded attack is still replayed on the unpatched copy, so you see it proven either way.
- Within about 10 to 20 seconds of the attack you're blocked for 5 minutes, and the route is shielded.
- The fix links to pull request #4 instead of opening a second one for the same file.
- Pull request #4 shows the patch, the test results from the replay server, and a table of attack versions before and after the patch.

### Test 4: Log in as admin without a password

```bash
curl -s -A 'sqlmap/1.8' -H 'Content-Type: application/json' -d '{"email":"'"'"' or 1=1-- demo1","password":"x"}' https://bh-app-ykmo.sprites.app/rest/user/login
```

Then click **Unblock** on the dashboard.

What you should see:

- The shop returns `200` with an admin login token, or `403` if the route is already shielded.
- The dashboard shows **Blocked**, with the replay result **proven**: the attack solved the Juice Shop "Login Admin" challenge.
- Within about 10 to 20 seconds of the attack you're blocked, and the route is shielded.
- The fix links to [pull request #3](https://github.com/aotakeda/juice-shop/pull/3).

### Running a test again

After you click **Unblock**:

- Sending exactly the same attack again gets you blocked right away, without another replay. The dashboard says it's the same trick that already worked.
- Changing the text after `--`, for example from `demo1` to `demo2`, counts as a new attack. You see the whole replay again.

Bouncer remembers proven attacks for 24 hours, also across restarts.

## How it works

1. **Proxy** (`door/`). Every request to the shop goes through the proxy, which logs it with tokens, passwords and secret query parameters redacted. The proxy serves a fake `/.env` file as bait, slows down some clients and refuses blocked ones. It slows a client down the moment it takes the bait, and blocks it the moment it reuses the bait, without waiting for the agent. It refuses requests with conflicting body lengths, such as two `Content-Length` headers or both `Content-Length` and `Transfer-Encoding` (on the Sprites, the edge already resolves that second case before the proxy sees it). Before checking a request, it undoes the tricks attackers use to hide one: repeated URL encoding, `\'`-style escapes, SQL comments, null bytes, and gzip or UTF-16 bodies.
   - The client's address comes from the `Sprite-Client-Ip` header, which the Sprites edge sets. A value sent by the client is overwritten, so it can't be forged. When `TRUSTED_PROXIES` is set, the header is only honoured from those addresses. A value that isn't a valid IP address, or that comes from an untrusted peer, is logged and the connection's own address is used instead.
   - Each client gets at most 32 open connections and 30 seconds to send a request, so one slow client can't tie up the shop for everyone.
2. **Triage** (`agent/jev.py`). Unusual requests go to TypeSafe's Jev System One model, which scores how malicious they look. The request text is marked as untrusted in the prompt, and passwords, tokens, cookie values and other secrets are masked before it's sent. The agent masks them the same way in everything it writes to disk. A request shaped like a known attack (SQL or NoSQL injection, path traversal, script injection, a forged login token) always goes to replay, whatever Jev says.
3. **Replay** (`runner/`). High-scoring requests go to the replay server. It keeps 4 copies of the shop started and waiting, each with its own fresh database, so a replay doesn't wait for a restart. It takes a fresh copy and sends the attack next to a harmless control request. A used copy restarts in the background. The attack counts as real if it leaks a test account's data, solves a Juice Shop challenge, or sends injected HTML or script back unescaped in an HTML page.
4. **Decision**. Bouncer blocks an IP address only when it has proof: the attack worked on the replay server, or the same client took the fake `/.env` and then reused its credentials. A block lasts 5 minutes. If a high-scoring attack fails on the replay server, Bouncer only slows the client down for 10 minutes. A suspicious score alone never causes a block.
   - A request a real browser sent from inside another site's page doesn't get its sender blocked, even when the attack is proven. The sender is slowed down instead, the route is still shielded and the attack still shows up on the dashboard. This stops a third-party page from getting its visitors blocked by making their browsers send an attack. Bait values reused this way, or from a client that never took the bait, are only logged.
   - A request only counts as sent from another site's page if it carries the full set of browser headers: `Sec-Fetch-Site` set to `cross-site` or `same-site`, plus `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, and a browser user agent. A lone `Sec-Fetch-Site` header from a tool like curl doesn't count.
   - Because those headers can still be faked, a client that sends 3 proven attacks this way within 10 minutes gets blocked anyway.
   - Repeating an attack that was already proven gets an immediate block, without another replay.
   - IPv6 clients are grouped by `/64`, so rotating addresses inside one network doesn't escape a block.
5. **Shield**. When an attack is proven, the proxy shields that route for 24 hours: requests to it that look like an attack get `403` before they reach the shop, whatever their method, path case, trailing slash, encoding or `;` parameters. Normal requests to the route still work. The agent still replays the refused attack on the unpatched replay server, so the attacker is blocked if it would have worked. Active shields are listed in the dashboard's Blocked panel and on the signal, each with a Remove shield button. Run `./deploy/deploy.sh refresh` after merging a fix to pull it and lift the shields.
6. **Fix** (`agent/fix.py`). For a real attack, Claude writes a small patch for the source file that handles the route. Claude is told to fix the root cause, never to filter keywords, and the patch can't add imports or touch dependency files. Claude also writes up to four other versions of the attack and a true/false pair of requests that would reveal a blind injection. The replay server sends all of them to unpatched copies, applies the patch, compiles the code, restarts the copies on the new code and sends them again, along with some normal requests. The requests are spread over the copies and run at the same time. A copy is swapped for a fresh one as soon as a request changes it. On the Sprites the whole test takes about 16 seconds, 5 of them compiling. Bouncer opens a pull request only if:
   - the original attack worked before the patch,
   - after the patch, the attack and every version of it have no effect,
   - the true/false pair can no longer be told apart, if it could be before,
   - and normal requests give the same status, item count and body as before, including one with an apostrophe in a legitimate value. A request that crashed with a `5xx` before the patch may change.

   Anything inconclusive, such as a failed reset, counts as a failure. Attacks that carry a real session cookie or login token, or that change data, always come back inconclusive, so Bouncer doesn't write fixes for them. The pull request shows which versions of the attack worked before the patch. It also says the patch came from an attacker's request, so review the whole diff, not just the test results.

### Terms

| Term | What it means here |
|---|---|
| Shop | The live Juice Shop that anyone can open. |
| Replay server | The isolated copy of the shop where Bouncer tests attacks and patches. |
| Warm pool | The copies of the shop that the replay server keeps started and waiting, each with a fresh database. Each replay takes a fresh copy from the pool. |
| Stunt double | The dashboard's name for a replay copy. "Proven on the stunt double" means the attack worked on a fresh copy from the warm pool. |
| Honeypot | The fake `/.env` file. It contains fake credentials. |
| Canary | A fake value that Bouncer watches for, such as the honeypot credentials or the replay server's test account. |
| Tarpit | A 10-second delay on every request from one IP address. A slowed client gets at most 2 delayed requests at a time; extra parallel requests get `429`. |
| Shield | A route the proxy protects after an attack on it is proven. Attack-shaped requests to it get `403` until the fix is merged. |
| Block | The proxy refuses every request from one IP address with HTTP `403`. |
| Allowed, Testing, Slowed, Blocked | The outcomes the dashboard shows for a request. Allowed means it went through (`ignore` or `watch`), Testing means it's being replayed (`replay`), Slowed means the client is tarpitted (`tarpit`), and Blocked means the client is blocked (`block`). A request a shield turned away shows as Refused by shield. |
| Dashboard | The page that shows requests, scores, decisions and fixes as they happen. |

## Run your own copy

You need:

- The `sprite` CLI, installed and logged in.
- TypeSafe, Anthropic and GitHub connectors in your Sprites account. The GitHub connector needs write access to the contents and pull requests of the Juice Shop fork that the pull requests go to.
- Your own fork of Juice Shop. Set `FORK` to its clone URL. `deploy.sh` derives `GITHUB_REPO` from it; set `GITHUB_BRANCH` if your default branch isn't `master`.

`deploy.sh all` creates the three Sprites `bh-app`, `bh-replay` and `bh-bouncer` with the labels the connectors need, if they don't exist yet. To create them on their own, run `./deploy/deploy.sh create`.
- Python 3.9 or newer. Bouncer uses only the standard library.

Then:

1. Run the tests:

   ```bash
   python3 -m unittest discover -s tests
   ```

2. Optional: add `OWNER_IP=<your public IP>` to `.secrets`. Bouncer never blocks, slows down or shields that address; the dashboard shows what would have happened instead, such as `would_block`. To get real blocks from it, add `-H 'X-Bouncer-Stranger: 1'` to a request, and undo them with `./deploy/deploy.sh unblock owner-as-stranger`.
3. Deploy everything:

   ```bash
   FORK=https://github.com/<you>/juice-shop.git FIX_MODE=pr ./deploy/deploy.sh all
   ```

The script creates `.secrets` if it's missing, installs the shop on two Sprites, links the Sprites, starts the services and locks down network access. It prints the shop and dashboard URLs. The dashboard passphrase is `DASH_PASSPHRASE` in `.secrets`.

> **CAUTION:** `FIX_MODE` defaults to `dry_run`, which tests patches but never opens a pull request. Pass `FIX_MODE=pr` every time you run `deploy.sh services` or `deploy.sh all`.

### Day-to-day commands

| To | Run |
|---|---|
| List blocks, slowdowns and shields | `./deploy/deploy.sh blocks` |
| Remove a block and slowdown (IPv4 address or IPv6 `/64`) | `./deploy/deploy.sh unblock 203.0.113.7` |
| Lift all shields | `./deploy/deploy.sh unshield` |
| Change the dashboard passphrase (this signs everyone out) | Edit `DASH_PASSPHRASE` in `.secrets`, then `FIX_MODE=pr ./deploy/deploy.sh services` |
| Pull merged fixes onto the shop and replay server, then lift the shields | `./deploy/deploy.sh refresh` |
| Change the block length (default 300 seconds) | `BLOCK_SECONDS=600 FIX_MODE=pr ./deploy/deploy.sh services` |

### Limits

- One open pull request per source file at most.
- At most 3 new fix attempts per hour.
- At most 50 slowed requests at once across all clients.
- Fix results live in memory. After a restart, the agent finds its open pull requests again on GitHub. Before reusing a pull request, it checks that it's still open. If GitHub can't be reached, it opens no pull request and tries again on the next attack.
- Proven attacks are kept for 24 hours in `agent-data/proven.json`, so they survive a restart. Dashboard sessions are signed tokens, so they survive a restart too; `agent-data/dash-sessions.json` only holds a hash of signed-out sessions.
- Requests that get a normal response (status below 400) skip triage unless they contain attack syntax or scanner headers.
- Shields match the attacked path after normalizing it, not route patterns like `/api/Users/:id`.
- Bouncer proves server-side attacks: a replay counts as proof when it leaks a canary or solves a Juice Shop challenge. For reflected XSS, the most it can show is that the payload came back unescaped in an HTML page. It doesn't run JavaScript, so client-side bugs such as DOM XSS are flagged and slowed down, but never proven or blocked.
- Only attack-shaped requests are triaged. Access-control bugs, such as reading another user's basket (IDOR) or downloading files straight from `/ftp`, look like normal requests, so they pass through untriaged.
- The owner IP is never locked out of the dashboard login. When `TRUSTED_PROXIES` is set, or the address comes from the connection itself, other addresses are locked out for 10 minutes after 5 wrong passphrases; otherwise they are slowed to one try every 10 seconds. After 20 wrong passphrases in 10 minutes from anyone, every login is slowed.

### Settings

Every setting has a default that works on Sprites. These are the ones you're most likely to change:

| Setting | Part | Default | What it does |
|---|---|---|---|
| `BLOCK_SECONDS` | deploy | `300` | How long a block lasts |
| `FORK`, `GITHUB_REPO`, `GITHUB_BRANCH` | deploy, agent | `aotakeda/juice-shop`, `master` | Where the app comes from and where pull requests go |
| `APP_DESCRIPTION` | deploy, agent | Juice Shop | What the app is, for Jev and Claude. `deploy.sh` writes it to a file, so commas are fine |
| `AGENT_WORKERS` | agent | `2` | How many requests are triaged at once |
| `PROBE_TARPIT_PATHS` | agent | `5` | Different probe paths in 10 minutes before a client is slowed down. `0` turns it off |
| `FOREIGN_BLOCK_AFTER`, `FOREIGN_WINDOW_SECONDS` | agent | `3`, `600` | Proven attacks from other sites' pages before the sender is blocked anyway |
| `DOOR_MAX_CONNS_PER_IP` | proxy | `32` | Open connections per client |
| `DOOR_REQUEST_SECONDS` | proxy | `30` | Time a client gets to send a whole request |
| `DOOR_TRUST_CLIENT_IP_HEADER`, `BOUNCER_TRUST_CLIENT_IP_HEADER` | proxy, agent | on | Read the client address from `Sprite-Client-Ip`. Turn it off when nothing in front of Bouncer sets the header |
| `TRUSTED_PROXIES` (or `DOOR_TRUSTED_PROXIES`, `BOUNCER_TRUSTED_PROXIES`) | proxy, agent | any peer | Comma-separated IPs or CIDRs allowed to set `Sprite-Client-Ip`. Setting it also turns on the hard per-address login lock |
| `RUNNER_MAX_THREADS` | runner | `32` | Requests the replay server handles at once; extra ones get 503 |
| `DOOR_HOST`, `BOUNCER_HOST`, `RUNNER_HOST` | all | `0.0.0.0` | Address each part listens on |
| `REPLAY_COPIES` | deploy, local | `4` on Sprites, `3` locally | Copies of the shop the replay server keeps started. Each one uses about 200 MB |

## Run it on your computer

You can try everything except the patch and the pull request without Sprites. You need Git, Node.js 22 or newer and Python 3.9 or newer.

```bash
./deploy/local.sh up
```

The first run clones Juice Shop into `local-run/` and installs it, which takes a few minutes. The script then starts the shop, the replay server with its 3 copies of the shop, the agent and the proxy, all on `127.0.0.1`, and prints the shop and dashboard addresses and the dashboard passphrase. The shop is on http://127.0.0.1:8000 and the dashboard on http://127.0.0.1:8001.

- Run the tests above against `http://127.0.0.1:8000`.
- Everything comes from `127.0.0.1`, so add `-H 'Sprite-Client-Ip: 203.0.113.7'` to act as a different client.
- Jev is replaced by a simple stand-in (`deploy/local_jev.py`) that scores requests with a few patterns. Claude and GitHub are only reachable through the Sprites connectors, so the fix step is off.
- `./deploy/local.sh blocks` lists blocks, slowdowns and shields, and `./deploy/local.sh unblock 203.0.113.7` removes one.
- `./deploy/local.sh down` stops everything.

## Protect a different app

These parts already work with any HTTP app:

- The proxy, request log, slowdowns and blocks.
- The honeypot and the check for its fake credentials.
- Jev triage.
- Replaying an attack next to a control request.
- The pull request step.

These parts all assume Juice Shop, so you'd need to change them:

1. **Repository.** Set `FORK` (and `GITHUB_BRANCH` if needed) when you run `deploy.sh`. It passes `GITHUB_REPO` and `GITHUB_BRANCH` to the agent.
2. **App description.** Set `APP_DESCRIPTION` when you run `deploy.sh`. Claude and Jev read it, and the default describes Juice Shop.
3. **Route finder and patches.** `agent/route_finder.py` reads `server.ts` and looks for Express routes like `app.get('/path', handler)`, and Claude's prompts expect a TypeScript route file. Rewrite them if your app isn't Express and TypeScript.
4. **Install and start.** `deploy/deploy.sh` clones the Juice Shop fork (`FORK`), runs `npm install` and starts `node build/app` on port 3000. Update `install_juice`, `refresh_juice`, `deploy_door` and `deploy_runner`. The replay server starts its own copies with `RUNNER_NODE` and `RUNNER_APP_ENTRY` (default `node build/app`) and gives each one a `PORT`, from `RUNNER_POOL_BASE_PORT` (default `3100`) up. The copies share the code and `node_modules`, and each gets its own `data`, `ftp`, `uploads`, `logs`, `i18n` and `frontend/dist`. If your app writes anywhere else, add it to `COPIED_DIRS` in `runner/runner.py`. Keep `RUNNER_POOL_DIR` on a fast local disk, because each copy rebuilds its database every time it starts. `deploy.sh` puts the copies in `/tmp`, where a disk sync is about 20 times faster than in `/home/sprite`. The copies can't reach the internet, so start-up checks that call out fail at once instead of waiting for a timeout. Set `RUNNER_POOL_SIZE=0` to go back to one copy restarted with `RUNNER_RESET_CMD`.
5. **Build.** The replay server compiles patches with `RUNNER_BUILD_CMD` (default `./node_modules/.bin/tsc`) into `RUNNER_BUILD_DIR` (default `build`). Point these at your build.
6. **Ready check.** The replay server polls `RUNNER_READY_PATH` (default `/rest/admin/application-version`) to know when the copy is up. Use a path your app has.
7. **Test account.** `plant_canary` in `runner/runner.py` creates the canary account with `POST /api/Users`. Change it to your app's sign-up route.
8. **Normal checks.** `smoke` in `runner/runner.py` sends a Juice Shop search and login, and `normal_requests` in `agent/fix.py` builds route-specific ones from the control request. Replace the Juice Shop ones with normal requests for your app.
9. **Challenge check.** The replay server also reads Juice Shop's `/api/Challenges`. Other apps don't have it, so Bouncer falls back to the canary check alone.
