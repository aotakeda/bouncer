#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${BOUNCER_LOCAL_DIR:-$ROOT/local-run}"
FORK="${FORK:-https://github.com/aotakeda/juice-shop.git}"
DOOR_PORT="${DOOR_PORT:-8000}"
AGENT_PORT="${AGENT_PORT:-8001}"
RUNNER_PORT="${RUNNER_PORT:-8002}"
JEV_PORT="${JEV_PORT:-8003}"
APP_PORT="${APP_PORT:-3000}"
REPLAY_PORT="${REPLAY_PORT:-3001}"
REPLAY_COPIES="${REPLAY_COPIES:-3}"
STEP="${1:-up}"

say() { printf '\n== %s\n' "$*"; }
sha() { printf %s "$1" | shasum -a 256 | cut -d' ' -f1; }
rand() { python3 -c 'import secrets;print(secrets.token_urlsafe(24))'; }

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing $1: $2" >&2; exit 1; }
}

check_tools() {
  need git "install git"
  need node "install Node.js 22 or newer"
  need npm "install Node.js 22 or newer"
  need python3 "install Python 3.9 or newer"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "Python 3.9 or newer is required" >&2; exit 1; }
}

write_helpers() {
  mkdir -p "$RUN/logs" "$RUN/pids" "$RUN/door-data" "$RUN/agent-data"
  cat > "$RUN/loopback.js" <<'JS'
const net = require('node:net')
const listen = net.Server.prototype.listen
net.Server.prototype.listen = function (...args) {
  if ((typeof args[0] === 'number' || /^\d+$/.test(String(args[0]))) && typeof args[1] !== 'string') args.splice(1, 0, '127.0.0.1')
  return listen.apply(this, args)
}
JS
  rm -f "$RUN/reset-replay.sh"
}

write_secrets() {
  if [ ! -f "$RUN/secrets.env" ]; then
    umask 077
    {
      echo "DOOR_SECRET=$(rand)"
      echo "RUNNER_SECRET=$(rand)"
      echo "EVENTS_SECRET=$(rand)"
      echo "DASH_PASSPHRASE=local-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
    } > "$RUN/secrets.env"
  fi
  if [ ! -f "$RUN/door-data/canaries.json" ]; then
    python3 -c "
import json,secrets,sys
t=lambda p,n: p+secrets.token_hex(n)
json.dump({'honeypot':{'admin_email':'ops-'+secrets.token_hex(3)+'@juice-sh.op','admin_password':t('Velvet-Rope-',6),'aws_key_id':'AKIA'+secrets.token_hex(8).upper(),'aws_secret':t('',20),'stripe_key':t('sk_live_',12)}},open(sys.argv[1],'w'),indent=2)" "$RUN/door-data/canaries.json"
  fi
}

step_install() {
  check_tools
  mkdir -p "$RUN"
  if [ ! -f "$RUN/juice/build/app.js" ]; then
    say "cloning and installing Juice Shop (takes a few minutes)"
    rm -rf "$RUN/juice"
    git clone --depth 1 "$FORK" "$RUN/juice" >/dev/null 2>&1
    (cd "$RUN/juice" && npm install --no-audit --no-fund > "$RUN/npm-install.log" 2>&1) || { echo "npm install failed, see $RUN/npm-install.log" >&2; exit 1; }
  fi
  if [ ! -f "$RUN/juice-replay/build/app.js" ]; then
    say "copying Juice Shop for the replay server"
    rm -rf "$RUN/juice-replay"
    cp -R "$RUN/juice" "$RUN/juice-replay"
  fi
}

start() {
  local name="$1"; shift
  if [ -f "$RUN/pids/$name.pid" ] && kill -0 "$(cat "$RUN/pids/$name.pid")" 2>/dev/null; then
    echo "$name already running"
    return
  fi
  nohup "$@" >> "$RUN/logs/$name.log" 2>&1 < /dev/null &
  echo $! > "$RUN/pids/$name.pid"
}

wait_port() {
  local port="$1" name="$2" i
  for i in $(seq 1 120); do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(s.connect_ex(('127.0.0.1', int(sys.argv[1]))))" "$port"; then
      return 0
    fi
    sleep 1
  done
  echo "$name never opened port $port, see $RUN/logs/$name.log" >&2
  return 1
}

step_up() {
  step_install
  write_helpers
  write_secrets
  set -a; . "$RUN/secrets.env"; set +a
  say "starting Juice Shop, Jev stand-in, runner with $REPLAY_COPIES replay copies, agent and door"
  (cd "$RUN/juice" && PORT=$APP_PORT NODE_ENV=production start app node --require "$RUN/loopback.js" build/app)
  start jev python3 "$ROOT/deploy/local_jev.py" "$JEV_PORT"
  (cd "$ROOT" && RUNNER_HOST=127.0.0.1 RUNNER_PORT=$RUNNER_PORT RUNNER_SECRET_SHA256="$(sha "$RUNNER_SECRET")" \
    RUNNER_POOL_SIZE=$REPLAY_COPIES RUNNER_POOL_BASE_PORT=$REPLAY_PORT RUNNER_APP_DIR="$RUN/juice-replay" \
    start runner python3 runner/runner.py)
  (cd "$ROOT" && BOUNCER_HOST=127.0.0.1 AGENT_PORT=$AGENT_PORT AGENT_DATA_DIR="$RUN/agent-data" \
    AGENT_EVENTS_SHA256="$(sha "$EVENTS_SECRET")" AGENT_DASH_SHA256="$(sha "$DASH_PASSPHRASE")" \
    JEV_URL=http://127.0.0.1:$JEV_PORT/v1/systemone RUNNER_URL=http://127.0.0.1:$RUNNER_PORT RUNNER_TOKEN="$RUNNER_SECRET" \
    DOOR_URL=http://127.0.0.1:$DOOR_PORT DOOR_TOKEN="$DOOR_SECRET" FIX_MODE=dry_run \
    start agent python3 -m agent.agent)
  (cd "$ROOT" && DOOR_HOST=127.0.0.1 DOOR_PORT=$DOOR_PORT DOOR_UPSTREAM=http://127.0.0.1:$APP_PORT DOOR_DATA_DIR="$RUN/door-data" \
    DOOR_ADMIN_SHA256="$(sha "$DOOR_SECRET")" DOOR_EVENTS_URL=http://127.0.0.1:$AGENT_PORT/events DOOR_EVENTS_TOKEN="$EVENTS_SECRET" \
    start door python3 door/door.py)
  wait_port "$APP_PORT" app
  wait_port "$REPLAY_PORT" runner
  wait_port "$RUNNER_PORT" runner
  wait_port "$AGENT_PORT" agent
  wait_port "$DOOR_PORT" door
  say "ready"
  echo "shop (send attacks here): http://127.0.0.1:$DOOR_PORT"
  echo "dashboard:                http://127.0.0.1:$AGENT_PORT  (passphrase: $DASH_PASSPHRASE)"
  echo "pretend to be another client with -H 'Sprite-Client-Ip: 203.0.113.7'"
  echo "stop everything with ./deploy/local.sh down"
}

step_down() {
  local f pid
  for f in "$RUN"/pids/*.pid; do
    [ -f "$f" ] || continue
    pid="$(cat "$f")"
    kill "$pid" 2>/dev/null || true
    rm -f "$f"
  done
  echo "stopped"
}

step_status() {
  local f
  for f in "$RUN"/pids/*.pid; do
    [ -f "$f" ] || continue
    if kill -0 "$(cat "$f")" 2>/dev/null; then echo "$(basename "$f" .pid): running"; else echo "$(basename "$f" .pid): stopped"; fi
  done
}

step_door_admin() {
  set -a; . "$RUN/secrets.env"; set +a
  curl -s -X "$1" -H "Authorization: Bearer $DOOR_SECRET" "http://127.0.0.1:$DOOR_PORT/_bouncer/$2"
}

case "$STEP" in
  install) step_install ;;
  up) step_up ;;
  down) step_down ;;
  status) step_status ;;
  blocks) step_door_admin GET blocklist; echo ;;
  unblock)
    key="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "${2:?usage: local.sh unblock <ip>}")"
    for kind in blocklist tarpit; do printf '%s: ' "$kind"; step_door_admin DELETE "$kind/$key"; echo; done ;;
  *) echo "usage: local.sh [up|down|status|install|blocks|unblock <ip>]" >&2; exit 1 ;;
esac
