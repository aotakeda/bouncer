<h1><img src="assets/bouncer-mark.svg" alt="" width="28" height="28" align="absmiddle">&nbsp;Bouncer</h1>

Bouncer is a personal security agent for small side projects that can't afford a dedicated Security Engineer. It runs on Fly Sprites and I've created it for the [Fly.io Hacksgiving](https://fly.io/hacksgiving).

The idea behind it is to watch every request going to your app. When it looks like an attack, Bouncer will send it again to an isolated copy of the app. If the attack works there, Bouncer will block the attacker. Then it goes on to write a fix, tests it on the copy and opens a PR for you to review.

The app in this demo is a fork of [OWASP Juice Shop](https://github.com/aotakeda/juice-shop), a web shop with known security holes.

## How it works

1. **Proxy** (`door/`). Every request to the shop goes through the proxy, which logs it. The proxy also serves a fake `/.env` file as bait, slows down some clients and refuses blocked ones.
2. **Triage** (`agent/jev.py`). Unusual requests go to the Jev System One model, which scores how malicious they look.
3. **Replay** (`runner/`). High-scoring requests go to the replay server, an isolated copy of the shop with no internet access. The replay server resets the copy and sends the attack next to a harmless control request. The attack counts as real if it leaks a test account's data or solves a Juice Shop challenge.
4. **Decision**. Bouncer blocks an IP address only when it has proof. Either the attack worked on the replay server, or the client reused the fake credentials from `/.env`. A block lasts 5 minutes. If a high-scoring attack fails on the replay server, Bouncer only slows the client down. A suspicious score alone never causes a block.
5. **Fix** (`agent/fix.py`). For a real attack, Claude writes a small patch for the source file that handles the route. Claude also writes up to four other versions of the attack. The replay server applies the patch, compiles the code, then sends the original attack, the other versions and some normal requests. Bouncer opens a pull request only if EVERY attack fails and normal requests still behave the same.

### Terms

| Term | What it means here |
|---|---|
| Shop | The live Juice Shop that anyone can open. |
| Replay server | The isolated copy of the shop where Bouncer tests attacks and patches. |
| Honeypot | The fake `/.env` file. It contains fake credentials. |
| Canary | A fake value that Bouncer watches for, such as the honeypot credentials or the replay server's test account. |
| Tarpit | A 10-second delay on every request from one IP address. |
| Block | The proxy refuses every request from one IP address with HTTP `403`. |
| Dashboard | The page that shows requests, scores, decisions and fixes as they happen. |

## Try the live demo

### Before you start

You need:

- A terminal with `curl` and `python3`.
- The dashboard passphrase, which is in the google form's `Is there anything else you'd like the judges to know?` answer.

| What | Where |
|---|---|
| Shop (send the attacks here) | https://bh-app-ykmo.sprites.app |
| Dashboard | https://bh-bouncer-ykmo.sprites.app |
| Fix for the login hole | https://github.com/aotakeda/juice-shop/pull/1 |
| Fix for the search hole | https://github.com/aotakeda/juice-shop/pull/2 |

> **CAUTION:** Blocks and tarpits apply to your whole IP address. Anyone else on your network gets blocked or slowed down with you.

> **CAUTION:** Tests 2, 3 and 4 send real attacks. Send them only to the demo shop above, never to another site.

1. Open the dashboard and log in with the passphrase.
2. Keep the dashboard open while you run the tests in order.

The Sprites go to sleep when nobody uses them, so your first request can take around 10 seconds from my testing.

### Test 1: Send a scanner request

Run:

```bash
curl -s -A 'zgrab/0.x' https://bh-app-ykmo.sprites.app/wp-login.php
```

What you should see:

- The shop returns its normal page.
- The dashboard shows the request as `ignore`, and `/wp-login.php` appears under **Most probed paths**.
- You are not blocked.

### Test 2: Take the bait, then use it

1. Fetch the fake `.env` file:

   ```bash
   curl -s https://bh-app-ykmo.sprites.app/.env
   ```

2. Copy the `ADMIN_EMAIL` and `ADMIN_PASSWORD` values from the output.
3. Put them into this command in place of `ADMIN_EMAIL` and `ADMIN_PASSWORD`, then run it:

   ```bash
   curl -s -H 'Content-Type: application/json' -d '{"email":"ADMIN_EMAIL","password":"ADMIN_PASSWORD"}' https://bh-app-ykmo.sprites.app/rest/user/login
   ```

What you should see:

- Step 1 returns a fake `.env` file, and the dashboard shows `tarpit`.
- From then on, each of your requests takes 10 seconds, for 10 minutes. That's the tarpit (not an outage).
- Step 3 takes 10 seconds and the shop returns `401`.
- About 10 seconds later you're blocked. The shop returns `403` for 5 minutes.
- The dashboard shows `block` with the reason "reused honeypot credentials".

To keep going, find your IP address in the dashboard's **Blocked right now** panel and click **Unblock**. That clears both the block and the tarpit.

### Test 3: Dump the users table through product search

1. Run:

   ```bash
   curl -s -A 'sqlmap/1.8' "https://bh-app-ykmo.sprites.app/rest/products/search?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"zz')) UNION SELECT id,email,password,'4','5','6','7','8','9','10' FROM Users-- demo1\"))")"
   ```

2. Open [pull request #2](https://github.com/aotakeda/juice-shop/pull/2) to see the fix.
3. Click **Unblock** on the dashboard.

What you should see:

- The shop returns `200` with user emails and password hashes in `data`. The attack still works on the live shop because the fix isn't merged yet.
- The dashboard shows a high Jev score, then `replay`, then `PROVEN`: the attack leaked canary values that the control request didn't.
- About 20 seconds after the attack you're blocked for 5 minutes.
- The fix links to pull request #2 instead of opening a second one for the same file.
- Pull request #2 shows the patch and the test results from the replay server. A table shows each attack version before and after the patch.

### Test 4: Log in as admin without a password

1. Run:

   ```bash
   curl -s -A 'sqlmap/1.8' -H 'Content-Type: application/json' -d '{"email":"'"'"' or 1=1-- demo1","password":"x"}' https://bh-app-ykmo.sprites.app/rest/user/login
   ```

2. Click **Unblock** on the dashboard.

What you should see:

- The shop returns `200` with an admin login token.
- The dashboard shows `PROVEN`: the attack solved the Juice Shop "Login Admin" challenge.
- About 15 seconds after the attack you're blocked.
- The fix links to [pull request #1](https://github.com/aotakeda/juice-shop/pull/1).

### Running a test again

Bouncer counts the same request from the same IP address only once every 10 minutes. To repeat test 3 or 4, change the text after `--`, for example from `demo1` to `demo2`.

### If you're the owner

Bouncer never blocks or slows down the IP address in `OWNER_IP` in `.secrets`. For that address, the dashboard shows what would have happened to anyone else, such as `would_block`.

To get a real block from the owner's address, add `-H 'X-Bouncer-Stranger: 1'` to any test command. To undo it, click **Unblock** on the dashboard or run:

```bash
./deploy/deploy.sh unblock owner-as-stranger
```

## Next step: protect a different app

These parts already work with any HTTP app:

- The proxy, request log, tarpit and blocks.
- The honeypot and the check for its fake credentials.
- Jev triage.
- Replaying an attack next to a control request.
- The Claude patch, the attack versions and the pull request.

These parts all assume Juice Shop, so you'd need to change them:

1. **Repository.** Set `GITHUB_REPO` and `GITHUB_BRANCH` for the agent (defaults: `aotakeda/juice-shop` and `master`). `deploy/deploy.sh` doesn't set them yet, so add them to the `--env` list in `deploy_agent`.
2. **App description.** Set `APP_DESCRIPTION` for the agent. Claude and Jev read it, and the default describes Juice Shop.
3. **Route finder.** `agent/route_finder.py` reads `server.ts` and looks for Express routes like `app.get('/path', handler)`. Rewrite it if your app isn't Express and TypeScript.
4. **Install and start.** `deploy/deploy.sh` clones the Juice Shop fork (`FORK`), runs `npm install` and starts `node build/app` on port 3000. Update `install_juice`, `refresh_juice`, `deploy_door` and `deploy_runner`.
5. **Build.** The replay server compiles patches with `RUNNER_BUILD_CMD` (default `./node_modules/.bin/tsc`) into `RUNNER_BUILD_DIR` (default `build`). Point these at your build.
6. **Ready check.** The replay server polls `RUNNER_READY_PATH` (default `/rest/admin/application-version`) to know when the copy is up. Use a path your app has.
7. **Test account.** `plant_canary` in `runner/runner.py` creates the canary account with `POST /api/Users`. Change it to your app's sign-up route.
8. **Normal checks.** `smoke` in `runner/runner.py` sends a Juice Shop search and login. Replace them with normal requests for your app.
9. **Challenge check.** The replay server also reads Juice Shop's `/api/Challenges`. Other apps don't have it, so Bouncer falls back to the canary check alone.

## Run your own copy

You need:

- The `sprite` CLI, installed and logged in.
- Three Sprites named `bh-app`, `bh-replay` and `bh-bouncer`, with `bh-app` labelled `role:app` and `bh-bouncer` labelled `role:bouncer`.
- TypeSafe, Anthropic and GitHub connectors in your Sprites account.
- Python 3. Bouncer uses only the standard library.

Then:

1. Run the tests:

   ```bash
   python3 -m unittest discover -s tests
   ```

2. Optional: add `OWNER_IP=<your public IP>` to `.secrets` so Bouncer never blocks you.
3. Deploy everything:

   ```bash
   FIX_MODE=pr ./deploy/deploy.sh all
   ```

The script creates `.secrets` if it's missing, installs the shop on two Sprites, links the Sprites, starts the services and locks down network access. It prints the shop and dashboard URLs. The dashboard passphrase is `DASH_PASSPHRASE` in `.secrets`.

> **CAUTION:** `FIX_MODE` defaults to `dry_run`, which tests patches but never opens a pull request. Pass `FIX_MODE=pr` every time you run `deploy.sh services` or `deploy.sh all`.

### Day-to-day commands

| To | Run |
|---|---|
| List blocks and tarpits | `./deploy/deploy.sh blocks` |
| Remove a block and tarpit | `./deploy/deploy.sh unblock 203.0.113.7` |
| Change the dashboard passphrase | Edit `DASH_PASSPHRASE` in `.secrets`, then `FIX_MODE=pr ./deploy/deploy.sh services` |
| Pull merged fixes onto the shop and replay server | `./deploy/deploy.sh refresh` |
| Change the block length (default 300 seconds) | `BLOCK_SECONDS=600 FIX_MODE=pr ./deploy/deploy.sh services` |

### Limits

- One open pull request per source file at most.
- At most 3 new fix attempts per hour.
- Fix results live in memory. After a restart, the agent finds its open pull requests again on GitHub.
- Normal `200` and `201` requests skip triage unless they contain attack syntax or scanner headers.

You probably won't reach the end of this readme but if you did, thank you for your time :)
