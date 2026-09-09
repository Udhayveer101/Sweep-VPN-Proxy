#!/usr/bin/env bash
# Deploy *your own* relay Worker and print the two values the app needs.
#
# There is no shared Worker. Every install that wants the WSS relay leg deploys
# this to its own Cloudflare account, on the free plan. That is not politeness:
# a Worker relaying other people's TCP is an open proxy wearing one account's
# name, and the account that owns it is the one that gets banned for whatever
# goes through it. Yours should carry only your traffic.
#
#   ./Tools/worker-tunnel/deploy.sh
#
# Needs: a (free) Cloudflare account, and npx. It will open a browser to log in
# the first time.
set -euo pipefail

cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
LOCAL="$ROOT/Config/Local.xcconfig"

command -v npx >/dev/null || { echo "npx not found — install Node.js first" >&2; exit 1; }

# A fresh token per deploy. 32 hex characters from the system CSPRNG; the
# Worker compares it in constant time, so there is nothing to gain by guessing
# at it slowly.
TOKEN=$(openssl rand -hex 16)

echo "==> deploying sweep-relay-mirror to your Cloudflare account"
npx --yes wrangler deploy

echo "==> setting TUNNEL_TOKEN"
printf '%s' "$TOKEN" | npx --yes wrangler secret put TUNNEL_TOKEN

# `wrangler deploy` prints the URL, but parsing its output is brittle across
# versions. Ask for the subdomain instead and build the name we deployed under.
SUB=$(npx --yes wrangler whoami 2>/dev/null | sed -n 's/.*\([a-z0-9-]*\)\.workers\.dev.*/\1/p' | head -1)
URL="https://sweep-relay-mirror.${SUB:-<your-subdomain>}.workers.dev"

cat <<TXT

Done. Your Worker:

  URL    $URL
  token  $TOKEN

Two ways to use it — either is enough:

  1. Paste both into the running app: Settings ▸ relay list ▸ "Mirror URL…".
     No rebuild, and it survives an app update.
  2. Put them in $LOCAL and rebuild:

       SWEEP_TUNNEL_URL = ${URL/:\/\//:\/\$()\/}
       SWEEP_TUNNEL_TOKEN = $TOKEN
       SWEEP_RELAY_MIRROR_URL = ${URL/:\/\//:\/\$()\/}/

     (the \$() is not a typo — an xcconfig treats // as a comment.)

Keep the token to yourself. Anyone holding it can open TCP connections through
your account, to any host on the current VPN Gate relay list.
TXT
