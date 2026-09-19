#!/bin/bash
# Measure what the tunnel actually does over time: throughput, and every
# interruption, with its cause.
#
# Nothing in this repo moved a byte over a real tunnel before this, and nothing
# measured how long a session held. Every number in the code comments is a
# one-off manual reading, which is how a throughput and disconnect regression
# rode from v1.3.0 to v1.4.0 without anything failing.
#
# Usage: Tools/soak.sh [minutes] [socks host:port]
#   Tools/soak.sh 30              # normal mode, through the local proxy
#   Tools/soak.sh 30 127.0.0.1:1081   # straight at usque, skipping LocalProxy
#
# Run it once BEFORE a change and once after, on the same network in the same
# hour, or the comparison means nothing.
set -uo pipefail

MINUTES="${1:-30}"
PROXY="${2:-127.0.0.1:1080}"
# 10MB over TLS from a host that is not Cloudflare, so the measurement is not
# taken inside the thing being measured.
URL="${SOAK_URL:-https://proof.ovh.net/files/10Mb.dat}"
JOURNAL="$HOME/Library/Group Containers/group.com.sweep.vpn/events.jsonl"
[ -f "$JOURNAL" ] || JOURNAL="$HOME/Library/Application Support/SweepVPN/events.jsonl"
OUT="${SOAK_OUT:-$(mktemp -d)/soak}"
mkdir -p "$OUT"

echo "soak: ${MINUTES}m through $PROXY -> $OUT"
[ -f "$JOURNAL" ] && wc -l < "$JOURNAL" > "$OUT/journal.start" || echo 0 > "$OUT/journal.start"

END=$(( $(date +%s) + MINUTES * 60 ))
SAMPLES="$OUT/samples.tsv"
: > "$SAMPLES"
ok=0; fail=0; longest=0; streak=0

while [ "$(date +%s)" -lt "$END" ]; do
  t0=$(date +%s)
  # --max-time bounds a stall so one hang does not eat the whole window; the
  # failure itself is the datum we are here for.
  bytes=$(curl -sS --socks5-hostname "$PROXY" --max-time 60 -o /dev/null \
                -w '%{size_download}' "$URL" 2>"$OUT/last.err")
  rc=$?
  t1=$(date +%s); dt=$(( t1 - t0 )); [ "$dt" -eq 0 ] && dt=1

  if [ "$rc" -eq 0 ] && [ "${bytes:-0}" -gt 0 ]; then
    mbps=$(echo "scale=2; $bytes * 8 / $dt / 1000000" | bc)
    printf '%s\tok\t%s\t%s\n' "$t1" "$mbps" "$dt" >> "$SAMPLES"
    ok=$(( ok + 1 )); streak=$(( streak + dt ))
    [ "$streak" -gt "$longest" ] && longest=$streak
    printf '  %s  %6s Mbit/s\n' "$(date +%H:%M:%S)" "$mbps"
  else
    printf '%s\tfail\t0\t%s\t%s\n' "$t1" "$dt" "$(tr -d '\n' < "$OUT/last.err" | cut -c1-120)" >> "$SAMPLES"
    fail=$(( fail + 1 )); streak=0
    printf '  %s  FAILED (curl %s) %s\n' "$(date +%H:%M:%S)" "$rc" "$(tr -d '\n' < "$OUT/last.err" | cut -c1-80)"
  fi
  sleep 5
done

echo
echo "=== soak result: ${MINUTES}m through $PROXY ==="
median=$(awk -F'\t' '$2=="ok"{print $3}' "$SAMPLES" | sort -n | awk '{a[NR]=$1} END{if(NR)print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2; else print "n/a"}')
echo "transfers:        $ok ok, $fail failed"
echo "median:           $median Mbit/s"
echo "longest unbroken: ${longest}s"

# What the app itself thought was happening over the same window. "restarting"
# is the line that must not appear: it is the cold restart that took the SOCKS
# listener down with it.
if [ -f "$JOURNAL" ]; then
  start=$(cat "$OUT/journal.start")
  tail -n "+$(( start + 1 ))" "$JOURNAL" > "$OUT/journal.slice" 2>/dev/null
  echo
  echo "journal over the same window:"
  for k in restarting lost connected stalled disconnected exited watching; do
    n=$(grep -c "\"kind\":\"$k\"" "$OUT/journal.slice" 2>/dev/null || echo 0)
    [ "$n" -gt 0 ] && printf '  %-14s %s\n' "$k" "$n"
  done
  echo "  (full slice: $OUT/journal.slice)"
else
  echo
  echo "journal not found at $JOURNAL — run the app once so it exists"
fi
echo
echo "samples: $SAMPLES"
