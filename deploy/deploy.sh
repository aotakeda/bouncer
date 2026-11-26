#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS="$ROOT/.secrets"
APP=bh-app
REPLAY=bh-replay
AGENT=bh-bouncer
FORK="${FORK:-https://github.com/aotakeda/juice-shop.git}"
GITHUB_REPO="${GITHUB_REPO:-$(printf %s "$FORK" | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##')}"
GITHUB_BRANCH="${GITHUB_BRANCH:-master}"
REMOTE=/home/sprite/bouncer
STEP="${1:-all}"
FIX_MODE="${FIX_MODE:-dry_run}"

export PATH="$HOME/.local/bin:$PATH"

say() { printf '\n== %s\n' "$*"; }
sx() { local s="$1"; shift; sprite exec --no-stdin -s "$s" -- "$@"; }
sha() { printf %s "$1" | shasum -a 256 | cut -d' ' -f1; }
rand() { python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; }
api() { sprite api "$@" 2>/dev/null; }

if [ ! -f "$SECRETS" ]; then
  umask 077
  {
    echo "DOOR_SECRET=$(rand)"
    echo "RUNNER_SECRET=$(rand)"
    echo "EVENTS_SECRET=$(rand)"
    echo "DASH_PASSPHRASE=$(python3 -c 'import secrets;print("-".join(secrets.choice(["juice","velvet","rope","neon","door","list","bouncer","night","club","mango","kiwi","lemon"]) for _ in range(4))+"-"+secrets.token_hex(8))')"
  } > "$SECRETS"
fi
set -a; . "$SECRETS"; set +a

url_of() { { sprite info -s "$1" 2>/dev/null || true; } | awk '/^URL:/{print $2}'; }

policy() {
  local s="$1" rules="$2"
  api -s "$s" /policy/network -- -s -f -X POST -H 'Content-Type: application/json' -d "{\"rules\":$rules}" >/dev/null || {
    echo "network policy update failed on $s" >&2
    return 1
  }
}

CONNECTIONS_JSON=""
fetch_connections() {
  local raw attempt
  for attempt in 1 2 3; do
    raw="$(api /oauth/connections -- -s || true)"
    if printf '%s' "$raw" | python3 -c 'import sys,json; d=json.load(sys.stdin); L=d if isinstance(d,list) else d.get("connections",d.get("data")); assert isinstance(L,list)' 2>/dev/null; then
      CONNECTIONS_JSON="$raw"
      return 0
    fi
    sleep 2
  done
  echo "failed to fetch /oauth/connections" >&2
  return 1
}

connections_json() {
  if [ -z "$CONNECTIONS_JSON" ]; then
    fetch_connections
  fi
  printf '%s' "$CONNECTIONS_JSON"
}

link_id() {
  connections_json | python3 -c "
import sys,json
d=json.load(sys.stdin)
L=d if isinstance(d,list) else d.get('connections',d.get('data',[]))
print(next((c['id'] for c in L if c.get('provider_account_name')==sys.argv[1]),''))" "$1"
}

link() {
  local name="$1" base="$2" token="$3" label="$4" endpoints="$5" policy id
  policy="{\"sprite_labels\":[\"$label\"],\"allowed_endpoints\":$endpoints}"
  id="$(link_id "$name")"
  if [ -z "$id" ]; then
    id="$(api /oauth/connections/custom_api -- -s -X POST -H 'Content-Type: application/json' -d @- <<JSON | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("connection") or d)["id"])'
{"name":"$name","description":"bouncer link","base_api_url":"$base","access_token":"$token","auth_method":"header","access_policy":$policy}
JSON
)"
    CONNECTIONS_JSON=""
  fi
  api "/oauth/connections/$id" -- -s -X PATCH -H 'Content-Type: application/json' -d "{\"access_policy\":$policy}" >/dev/null
  echo "$id"
}

need_id() {
  local label="$1" val="$2"
  if [ -z "$val" ]; then
    echo "missing Sprites connector: $label" >&2
    exit 1
  fi
}

connector_id() {
  connections_json | python3 -c "
import sys,json
d=json.load(sys.stdin)
L=d if isinstance(d,list) else d.get('connections',d.get('data',[]))
print(next((c['id'] for c in L if c['provider']==sys.argv[1]),''))" "$1"
}

push_code() {
  local s="$1"; shift
  sx "$s" mkdir -p "$REMOTE"
  for dir in "$@"; do
    sprite file push -p -r -s "$s" "$ROOT/$dir" "$REMOTE/$dir" >/dev/null
  done
}

install_juice() {
  local s="$1"
  policy "$s" '[{"include":"defaults"}]'
  sx "$s" sh -c "test -f ~/juice-shop/build/app.js || (rm -rf ~/juice-shop && git clone --depth 1 $FORK ~/juice-shop >/dev/null 2>&1 && cd ~/juice-shop && npm install --no-audit --no-fund >/tmp/npm-install.log 2>&1) && echo '$s juice ready'"
}

refresh_juice() {
  local s="$1" owner="$2"
  policy "$s" '[{"include":"defaults"}]'
  sx "$s" sh -c "cd ~/juice-shop && git pull --ff-only >/dev/null 2>&1 && ./node_modules/.bin/tsc >/tmp/tsc.log 2>&1 && sprite-env services restart $owner >/dev/null 2>&1 && echo '$s juice refreshed'"
}

service() {
  local s="$1" name="$2"; shift 2
  sx "$s" sh -c "sprite-env services delete $name >/dev/null 2>&1 || true"
  sx "$s" sprite-env services create "$name" "$@" --no-stream >/dev/null
}

APP_URL="$(url_of $APP)"; REPLAY_URL="$(url_of $REPLAY)"; AGENT_URL="$(url_of $AGENT)"
GW=https://api.sprites.dev/v1/gateway
LOCKED_EGRESS='[{"domain":"api.sprites.dev","action":"allow"},{"domain":"*","action":"deny"}]'

door_admin() {
  curl -s -X "$1" -H "Authorization: Bearer $DOOR_SECRET" "$APP_URL/_bouncer/$2"
}

step_create() {
  local name label existing
  existing="$(sprite list 2>/dev/null || true)"
  for pair in "$APP:role:app" "$REPLAY:role:replay" "$AGENT:role:bouncer"; do
    name="${pair%%:*}"; label="${pair#*:}"
    if printf '%s\n' "$existing" | grep -qx "$name"; then
      sprite info -s "$name" 2>/dev/null | grep -q "$label" || echo "$name exists but lacks label $label: run sprite config update -s $name --label $label" >&2
    else
      sprite create --skip-console --label "$label" "$name" >/dev/null
      echo "$name created, labelled $label"
    fi
  done
  APP_URL="$(url_of $APP)"; REPLAY_URL="$(url_of $REPLAY)"; AGENT_URL="$(url_of $AGENT)"
}

wait_each() {
  local failed=0 label pid
  while [ "$#" -ge 2 ]; do
    label="$1" pid="$2"; shift 2
    if ! wait "$pid"; then
      echo "FAILED: $label" >&2
      failed=1
    fi
  done
  return "$failed"
}

step_install() {
  local app_pid replay_pid
  say "installing Juice Shop on $APP and $REPLAY"
  install_juice "$APP" & app_pid=$!
  install_juice "$REPLAY" & replay_pid=$!
  if ! wait_each "install on $APP" "$app_pid" "install on $REPLAY" "$replay_pid"; then
    step_lock || echo "lock after failed install also failed, check network policies" >&2
    echo "Juice Shop install failed; see /tmp/npm-install.log on the failing Sprite" >&2
    exit 1
  fi
}

step_refresh() {
  local app_pid replay_pid
  say "refreshing Juice Shop on $APP and $REPLAY"
  refresh_juice "$APP" juice & app_pid=$!
  refresh_juice "$REPLAY" runner & replay_pid=$!
  if ! wait_each "refresh on $APP" "$app_pid" "refresh on $REPLAY" "$replay_pid"; then
    step_lock || echo "lock after failed refresh also failed, check network policies" >&2
    echo "Juice Shop refresh failed (git pull, tsc in /tmp/tsc.log, or restart); shields stay up" >&2
    exit 1
  fi
  step_lock
  clear_shields
}

clear_shields() {
  local route
  door_admin GET blocklist | python3 -c '
import sys,json
for route in (json.load(sys.stdin).get("shield") or {}):
    print(route)' | while IFS= read -r route; do
    printf 'unshield %s: ' "$route"
    door_admin DELETE "shield/$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$route")"
    echo
  done
}

step_links() {
  say "creating secret links"
  fetch_connections
  link bh-link-events "$AGENT_URL" "$EVENTS_SECRET" role:app '["/events"]' >/dev/null
  link bh-link-door "$APP_URL" "$DOOR_SECRET" role:bouncer '["/_bouncer/*"]' >/dev/null
  link bh-link-replay "$REPLAY_URL" "$RUNNER_SECRET" role:bouncer '["/replay","/reset","/patch","/health"]' >/dev/null
}

plant_canaries() {
  sx "$APP" sh -c "mkdir -p $REMOTE/door-data && cd $REMOTE/door-data && test -f canaries.json || python3 -c \"
import json,secrets
t=lambda p,n: p+secrets.token_hex(n)
json.dump({'honeypot':{'admin_email':'ops-'+secrets.token_hex(3)+'@juice-sh.op','admin_password':t('Velvet-Rope-',6),'aws_key_id':'AKIA'+secrets.token_hex(8).upper(),'aws_secret':t('',20),'stripe_key':t('sk_live_',12)}},open('canaries.json','w'),indent=2)\""
}

deploy_door() {
  local events_id="$1"
  say "door on $APP"
  plant_canaries
  service "$APP" juice --cmd node --args build/app --dir /home/sprite/juice-shop --env "PORT=3000,NODE_ENV=production"
  service "$APP" door --cmd python3 --args "$REMOTE/door/door.py" --dir "$REMOTE" --http-port 8080 \
    --env "DOOR_DATA_DIR=$REMOTE/door-data,DOOR_ADMIN_SHA256=$(sha "$DOOR_SECRET"),DOOR_EVENTS_URL=$GW/custom_api/$events_id/events,DOOR_ALLOWLIST=${OWNER_IP:-},DOOR_BLOCK_SECONDS=${BLOCK_SECONDS:-300}"
  sprite config update -s "$APP" --url-auth public >/dev/null
}

deploy_runner() {
  say "runner on $REPLAY"
  sx "$REPLAY" sh -c "sprite-env services delete juice >/dev/null 2>&1 || true"
  service "$REPLAY" runner --cmd python3 --args "$REMOTE/runner/runner.py" --dir "$REMOTE" --http-port 8080 \
    --env "RUNNER_SECRET_SHA256=$(sha "$RUNNER_SECRET"),RUNNER_POOL_SIZE=${REPLAY_COPIES:-4},RUNNER_APP_DIR=/home/sprite/juice-shop,RUNNER_POOL_DIR=/tmp/juice-shop-pool"
  sprite config update -s "$REPLAY" --url-auth public >/dev/null
}

deploy_agent() {
  local replay_id="$1" door_id="$2" jev_id="$3" claude_id="$4" github_id="$5"
  say "agent on $AGENT"
  if [ -n "${APP_DESCRIPTION:-}" ]; then
    printf '%s\n' "$APP_DESCRIPTION" | sprite exec -s "$AGENT" -- sh -c "mkdir -p $REMOTE/agent-data && cat > $REMOTE/agent-data/app_description.txt"
  else
    sx "$AGENT" rm -f "$REMOTE/agent-data/app_description.txt"
  fi
  service "$AGENT" agent --cmd python3 --args "-m,agent.agent" --dir "$REMOTE" --http-port 8080 \
    --env "AGENT_DATA_DIR=$REMOTE/agent-data,AGENT_EVENTS_SHA256=$(sha "$EVENTS_SECRET"),AGENT_DASH_SHA256=$(sha "$DASH_PASSPHRASE"),JEV_URL=$GW/typesafe/$jev_id/v1/systemone,RUNNER_URL=$GW/custom_api/$replay_id,DOOR_URL=$GW/custom_api/$door_id,OWNER_IPS=${OWNER_IP:-},BLOCK_SECONDS=${BLOCK_SECONDS:-300},SHIELD_SECONDS=${SHIELD_SECONDS:-86400},FIX_MODE=$FIX_MODE,GITHUB_REPO=$GITHUB_REPO,GITHUB_BRANCH=$GITHUB_BRANCH,APP_DESCRIPTION_FILE=$REMOTE/agent-data/app_description.txt,ANTHROPIC_URL=$GW/anthropic/$claude_id,GITHUB_URL=$GW/github/$github_id"
  sprite config update -s "$AGENT" --url-auth public >/dev/null
}

step_services() {
  local events_id door_id replay_id jev_id claude_id github_id
  fetch_connections
  events_id="$(link_id bh-link-events)"; door_id="$(link_id bh-link-door)"; replay_id="$(link_id bh-link-replay)"
  jev_id="$(connector_id typesafe)"; claude_id="$(connector_id anthropic)"; github_id="$(connector_id github)"
  need_id bh-link-events "$events_id"; need_id bh-link-door "$door_id"; need_id bh-link-replay "$replay_id"
  need_id typesafe "$jev_id"; need_id anthropic "$claude_id"; need_id github "$github_id"

  say "deploying code"
  push_code "$APP" door
  push_code "$REPLAY" runner
  push_code "$AGENT" agent

  deploy_door "$events_id"
  deploy_runner
  deploy_agent "$replay_id" "$door_id" "$jev_id" "$claude_id" "$github_id"
}

step_lock() {
  say "locking down"
  policy "$APP" "$LOCKED_EGRESS"
  policy "$AGENT" "$LOCKED_EGRESS"
  policy "$REPLAY" '[{"domain":"*","action":"deny"}]'
  api -s "$REPLAY" /policy/privileges -- -s -f -X POST -H 'Content-Type: application/json' -d '{"profile":"minimal","noNewPrivileges":true}' >/dev/null || {
    echo "privilege profile update failed on $REPLAY" >&2
    return 1
  }
}

step_blocks() {
  door_admin GET blocklist | python3 -c '
import sys,json,time
d=json.load(sys.stdin)
for kind,entries in d.items():
    for ip,e in (entries or {}).items():
        left=max(0,int(e.get("until",0)-time.time()))
        print("%-9s %-40s %5ds  %s" % (kind, ip, left, str(e.get("reason",""))[:80]))'
}

step_unblock() {
  local ip="${1:?usage: deploy.sh unblock <ip>}" kind key
  key="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$ip")"
  for kind in blocklist tarpit; do printf '%s: ' "$kind"; door_admin DELETE "$kind/$key"; echo; done
}

summary() {
  say "done"
  echo "app:       $APP_URL"
  echo "dashboard: $AGENT_URL  (passphrase in .secrets)"
}

case "$STEP" in
  all) step_create; step_install; step_links; step_services; step_lock; summary ;;
  create|install|refresh|links|services|lock) "step_$STEP"; summary ;;
  blocks) step_blocks ;;
  unblock) step_unblock "${2:-}" ;;
  unshield) clear_shields ;;
  *) echo "usage: deploy.sh [all|create|install|refresh|links|services|lock|blocks|unblock <ip>|unshield]" >&2; exit 1 ;;
esac
