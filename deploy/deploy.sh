#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECRETS="$ROOT/.secrets"
APP=bh-app
REPLAY=bh-replay
AGENT=bh-bouncer
FORK=https://github.com/aotakeda/juice-shop.git
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
    echo "DASH_PASSPHRASE=$(python3 -c 'import secrets;print("-".join(secrets.choice(["juice","velvet","rope","neon","door","list","bouncer","night","club","mango","kiwi","lemon"]) for _ in range(4)))')"
  } > "$SECRETS"
fi
set -a; . "$SECRETS"; set +a

url_of() { sprite info -s "$1" 2>/dev/null | awk '/^URL:/{print $2}'; }

policy() {
  local s="$1" rules="$2"
  api -s "$s" /policy/network -- -s -X POST -H 'Content-Type: application/json' -d "{\"rules\":$rules}" >/dev/null
}

link() {
  local name="$1" base="$2" token="$3" label="$4" endpoints="$5" policy id
  policy="{\"sprite_labels\":[\"$label\"],\"allowed_endpoints\":$endpoints}"
  id="$(api /oauth/connections/custom_api -- -s -X POST -H 'Content-Type: application/json' -d @- <<JSON | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("connection") or d)["id"])'
{"name":"$name","description":"bouncer link","base_api_url":"$base","access_token":"$token","auth_method":"header","access_policy":$policy}
JSON
)"
  api "/oauth/connections/$id" -- -s -X PATCH -H 'Content-Type: application/json' -d "{\"access_policy\":$policy}" >/dev/null
  echo "$id"
}

connector_id() {
  api /oauth/connections -- -s | python3 -c "
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

service() {
  local s="$1" name="$2"; shift 2
  sx "$s" sh -c "sprite-env services delete $name >/dev/null 2>&1 || true"
  sx "$s" sprite-env services create "$name" "$@" --no-stream >/dev/null
}

APP_URL="$(url_of $APP)"; REPLAY_URL="$(url_of $REPLAY)"; AGENT_URL="$(url_of $AGENT)"

if [ "$STEP" = all ] || [ "$STEP" = install ]; then
  say "installing Juice Shop on $APP and $REPLAY"
  install_juice "$APP" &
  install_juice "$REPLAY" &
  wait
fi

if [ "$STEP" = all ] || [ "$STEP" = links ]; then
  say "creating secret links"
  link bh-link-events "$AGENT_URL" "$EVENTS_SECRET" role:app '["/events"]' >/dev/null
  link bh-link-door "$APP_URL" "$DOOR_SECRET" role:bouncer '["/_bouncer/*"]' >/dev/null
  link bh-link-replay "$REPLAY_URL" "$RUNNER_SECRET" role:bouncer '["/replay","/reset","/patch","/health"]' >/dev/null
fi

if [ "$STEP" = all ] || [ "$STEP" = services ]; then
  GW=https://api.sprites.dev/v1/gateway
  id_of() {
    api /oauth/connections -- -s | python3 -c "
import sys,json
d=json.load(sys.stdin)
L=d if isinstance(d,list) else d.get('connections',d.get('data',[]))
print(next((c['id'] for c in L if c.get('provider_account_name')==sys.argv[1]),''))" "$1"
  }
  EVENTS_ID="$(id_of bh-link-events)"; DOOR_ID="$(id_of bh-link-door)"; REPLAY_ID="$(id_of bh-link-replay)"; JEV_ID="$(connector_id typesafe)"; CLAUDE_ID="$(connector_id anthropic)"; GITHUB_ID="$(connector_id github)"

  say "deploying code"
  push_code "$APP" door
  push_code "$REPLAY" runner
  push_code "$AGENT" agent

  say "door on $APP"
  sx "$APP" sh -c "mkdir -p $REMOTE/door-data && cd $REMOTE/door-data && test -f canaries.json || python3 -c \"
import json,secrets
t=lambda p,n: p+secrets.token_hex(n)
json.dump({'honeypot':{'admin_email':'ops-'+secrets.token_hex(3)+'@juice-sh.op','admin_password':t('Velvet-Rope-',6),'aws_key_id':'AKIA'+secrets.token_hex(8).upper(),'aws_secret':t('',20),'stripe_key':t('sk_live_',12)}},open('canaries.json','w'),indent=2)\""
  service "$APP" juice --cmd node --args build/app --dir /home/sprite/juice-shop --env "PORT=3000,NODE_ENV=production"
  service "$APP" door --cmd python3 --args "$REMOTE/door/door.py" --dir "$REMOTE" --http-port 8080 \
    --env "DOOR_DATA_DIR=$REMOTE/door-data,DOOR_ADMIN_SHA256=$(sha "$DOOR_SECRET"),DOOR_EVENTS_URL=$GW/custom_api/$EVENTS_ID/events,DOOR_ALLOWLIST=${OWNER_IP:-}"
  sprite config update -s "$APP" --url-auth public >/dev/null

  say "runner on $REPLAY"
  service "$REPLAY" juice --cmd node --args build/app --dir /home/sprite/juice-shop --env "PORT=3000,NODE_ENV=production"
  service "$REPLAY" runner --cmd python3 --args "$REMOTE/runner/runner.py" --dir "$REMOTE" --http-port 8080 \
    --env "RUNNER_SECRET_SHA256=$(sha "$RUNNER_SECRET")"
  sprite config update -s "$REPLAY" --url-auth public >/dev/null

  say "agent on $AGENT"
  service "$AGENT" agent --cmd python3 --args "-m,agent.agent" --dir "$REMOTE" --http-port 8080 \
    --env "AGENT_DATA_DIR=$REMOTE/agent-data,AGENT_EVENTS_SHA256=$(sha "$EVENTS_SECRET"),AGENT_DASH_SHA256=$(sha "$DASH_PASSPHRASE"),JEV_URL=$GW/typesafe/$JEV_ID/v1/systemone,RUNNER_URL=$GW/custom_api/$REPLAY_ID,DOOR_URL=$GW/custom_api/$DOOR_ID,OWNER_IPS=${OWNER_IP:-},FIX_MODE=$FIX_MODE,ANTHROPIC_URL=$GW/anthropic/$CLAUDE_ID,GITHUB_URL=$GW/github/$GITHUB_ID"
  sprite config update -s "$AGENT" --url-auth public >/dev/null
fi

if [ "$STEP" = all ] || [ "$STEP" = lock ]; then
  say "locking down"
  policy "$APP" '[{"domain":"api.sprites.dev","action":"allow"},{"domain":"*","action":"deny"}]'
  policy "$AGENT" '[{"domain":"api.sprites.dev","action":"allow"},{"domain":"*","action":"deny"}]'
  policy "$REPLAY" '[{"domain":"*","action":"deny"}]'
  api -s "$REPLAY" /policy/privileges -- -s -X POST -H 'Content-Type: application/json' -d '{"profile":"minimal","noNewPrivileges":true}' >/dev/null
fi

door_admin() {
  curl -s -X "$1" -H "Authorization: Bearer $DOOR_SECRET" "$APP_URL/_bouncer/$2"
}

if [ "$STEP" = blocks ]; then
  door_admin GET blocklist | python3 -c '
import sys,json,time
d=json.load(sys.stdin)
for kind,entries in d.items():
    for ip,e in (entries or {}).items():
        left=max(0,int(e.get("until",0)-time.time()))
        print("%-9s %-40s %5ds  %s" % (kind, ip, left, str(e.get("reason",""))[:80]))'
  exit 0
fi

if [ "$STEP" = unblock ]; then
  IP="${2:?usage: deploy.sh unblock <ip>}"
  for kind in blocklist tarpit; do printf '%s: ' "$kind"; door_admin DELETE "$kind/$IP"; echo; done
  exit 0
fi

say "done"
echo "app:       $APP_URL"
echo "dashboard: $AGENT_URL  (passphrase in .secrets)"
