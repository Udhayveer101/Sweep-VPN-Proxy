#!/usr/bin/env bash
# Add a VPS to the fleet and re-sign the server list, in one command.
#
#   sweep-fleet.sh add <label> <user@host> <CC> [city] [provider]
#   sweep-fleet.sh rebuild          re-sign after editing fleet/fleet.json
#   sweep-fleet.sh list
#
# `add` provisions the box with Server/install.sh, reads the keys it prints,
# appends them to fleet/fleet.json, then rebuilds and signs the bundle and drops
# it into the app resources. Nothing is copied by hand, so adding the fourth
# server costs the same as the first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLEET_DIR="$ROOT/fleet"
FLEET="$FLEET_DIR/fleet.json"
SIGNING_KEY="$ROOT/sweep-config.key"
SIGNED="$ROOT/Apps/Shared/sweep-config.sig.json"

die() { echo "error: $*" >&2; exit 1; }

[[ -f "$SIGNING_KEY" ]] || die "no signing key at $SIGNING_KEY — run: swift run --package-path Tools/sweep-sign sweep-sign keygen sweep-config.key"
mkdir -p "$FLEET_DIR"
[[ -f "$FLEET" ]] || echo '{"minimumAppBuild":1,"validDays":90,"version":0,"servers":[]}' > "$FLEET"

# Bundles are rejected if the version ever goes backwards. A counter starting at
# 1 breaks the moment a device has already stored a higher version (a reinstall,
# a rebuilt fleet), so the version is the issue time in epoch seconds — monotonic
# by construction, with no state to keep in sync.
rebuild() {
  local next
  next=$(date +%s)
  python3 - "$FLEET" "$next" <<'PY'
import json,sys
p,n=sys.argv[1],int(sys.argv[2])
d=json.load(open(p)); d['version']=n
json.dump(d,open(p,'w'),indent=2)
PY
  [[ $(python3 -c "import json;print(len(json.load(open('$FLEET'))['servers']))") -gt 0 ]] \
    || die "fleet is empty — add a server first"
  swift run --package-path "$ROOT/Tools/sweep-catalog" sweep-catalog \
    personal "$FLEET" "$FLEET_DIR/bundle.json" >/dev/null
  swift run --package-path "$ROOT/Tools/sweep-sign" sweep-sign \
    sign "$SIGNING_KEY" "$FLEET_DIR/bundle.json" "$SIGNED"
  echo "signed bundle -> $SIGNED (version $next)"
  echo "rebuild the app to pick it up: xcodegen generate && xcodebuild ..."
}

case "${1:-}" in
add)
  LABEL="${2:?usage: add <label> <user@host> <CC> [city] [provider]}"
  TARGET="${3:?missing user@host}"
  CC="${4:?missing 2-letter country code}"
  CITY="${5:-}"
  PROVIDER="${6:-}"
  HOST="${TARGET#*@}"

  echo "==> copying provisioning files to $TARGET"
  ssh "$TARGET" 'mkdir -p ~/sweep-server'
  scp -q "$ROOT"/Server/{install.sh,nftables.conf,unbound.conf,sshd_hardening.conf,wg0.conf.template,sweepbridge.service,shadowsocks.service} \
      "$TARGET:~/sweep-server/"

  echo "==> provisioning (needs sudo on the box)"
  OUT=$(ssh "$TARGET" "chmod +x ~/sweep-server/install.sh && sudo ~/sweep-server/install.sh $LABEL")
  echo "$OUT"

  SERVER_PUB=$(echo "$OUT" | sed -n 's/^server public key: *//p' | tail -1)
  SS_PSK=$(echo "$OUT" | sed -n 's/^shadowsocks psk: *//p' | tail -1)
  [[ -n "$SERVER_PUB" ]] || die "could not read the server public key from install.sh output"

  python3 - "$FLEET" "$LABEL" "$HOST" "$SERVER_PUB" "$SS_PSK" "$CC" "$CITY" "$PROVIDER" <<'PY'
import json,sys
p,label,host,pub,psk,cc,city,provider = sys.argv[1:9]
d=json.load(open(p))
d['servers']=[s for s in d['servers'] if s['id']!=label]
d['servers'].append({
  "id": label,
  "name": (f"{city}, {cc.upper()}" if city else label),
  "countryCode": cc.upper(),
  "cityName": city or None,
  "provider": provider or None,
  "host": host,
  "publicKey": pub,
  # Every server is its own tunnel, so the device can hold the same
  # in-tunnel address on each one — matches wg0.conf.template's /32 peer.
  "tunnelAddress": "10.64.0.2",
  "tunnelAddressV6": "fd00:64::2",
  "dns": ["10.64.0.1"],
  "filteringDNS": [],
  "shadowsocksKey": psk or None,
  # Rungs 3/4 need a TLS certificate on the box; enable them once one exists.
  "rungs": [1,2,5,7]
})
json.dump(d,open(p,'w'),indent=2)
print(f"fleet now has {len(d['servers'])} server(s)")
PY
  rebuild
  ;;

rebuild) rebuild ;;

list)
  python3 -c "
import json
for s in json.load(open('$FLEET'))['servers']:
    print(f\"{s['id']:<16} {s['host']:<16} {s['countryCode']}\")"
  ;;

*) die "usage: sweep-fleet.sh add|rebuild|list" ;;
esac
