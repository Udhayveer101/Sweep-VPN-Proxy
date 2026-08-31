#!/usr/bin/env bash
# Provision a Debian/Ubuntu VPS as a Sweep VPN endpoint. Run as root.
# Idempotent. Does NOT touch the signing key — that lives offline.
set -euo pipefail

DEVICE_LABEL="${1:?usage: install.sh <device-label>}"

apt-get update
apt-get install -y wireguard unbound nftables shadowsocks-libev ca-certificates

# The transport bridge that serves the non-UDP rungs. Build it once with
# `cargo build --release` in Server/sweepbridge and copy the binary here.
if [[ -f "$(dirname "$0")/sweepbridge/target/release/sweepbridge" ]]; then
  install -m 755 "$(dirname "$0")/sweepbridge/target/release/sweepbridge" /usr/local/bin/sweepbridge
fi

install -d -m 700 /etc/wireguard
cd /etc/wireguard

if [[ ! -f server.key ]]; then
  umask 077
  wg genkey > server.key
  wg pubkey < server.key > server.pub
fi

# Per-device keys are generated ON THE DEVICE in production; this path exists so
# a first peer can be bootstrapped from the server for testing.
if [[ ! -f "peer-${DEVICE_LABEL}.key" ]]; then
  umask 077
  wg genkey > "peer-${DEVICE_LABEL}.key"
  wg pubkey < "peer-${DEVICE_LABEL}.key" > "peer-${DEVICE_LABEL}.pub"
  wg genpsk > "peer-${DEVICE_LABEL}.psk"
fi

sed -e "s|__SERVER_PRIVATE_KEY__|$(cat server.key)|" \
    -e "s|__DEVICE_LABEL__|${DEVICE_LABEL}|" \
    -e "s|__DEVICE_PUBLIC_KEY__|$(cat "peer-${DEVICE_LABEL}.pub")|" \
    -e "s|__DEVICE_PSK__|$(cat "peer-${DEVICE_LABEL}.psk")|" \
    "$(dirname "$0")/wg0.conf.template" > /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

install -m 644 "$(dirname "$0")/nftables.conf" /etc/nftables.conf
install -m 644 "$(dirname "$0")/unbound.conf" /etc/unbound/unbound.conf.d/sweep.conf
install -m 644 "$(dirname "$0")/sshd_hardening.conf" /etc/ssh/sshd_config.d/99-sweep.conf

install -d -m 750 /etc/sweep /etc/sweep/tls

# Shadowsocks-2022 pre-shared key (rung 5). Put the same value in the signed
# bundle's endpoint secret.
if [[ ! -f /etc/sweep/shadowsocks.env ]]; then
  umask 077
  echo "SS_PSK=$(head -c 32 /dev/urandom | base64)" > /etc/sweep/shadowsocks.env
fi

install -m 644 "$(dirname "$0")/sweepbridge.service" /etc/systemd/system/sweepbridge.service
install -m 644 "$(dirname "$0")/shadowsocks.service" /etc/systemd/system/sweep-shadowsocks.service
systemctl daemon-reload

systemctl enable --now nftables
systemctl restart unbound
systemctl enable --now wg-quick@wg0
systemctl enable --now sweep-shadowsocks
# The bridge only starts once a certificate exists for the TLS/QUIC rungs.
if [[ -s /etc/sweep/tls/fullchain.pem && -s /etc/sweep/tls/privkey.pem ]]; then
  systemctl enable --now sweepbridge
else
  echo "NOTE: /etc/sweep/tls/{fullchain,privkey}.pem missing — TLS and QUIC rungs are off."
  echo "      Issue a certificate for your hostname, then: systemctl enable --now sweepbridge"
fi
systemctl restart ssh || systemctl restart sshd

echo "shadowsocks psk:   $(grep -o '[^=]*$' /etc/sweep/shadowsocks.env)"
echo "server public key: $(cat server.pub)"
echo "peer public key:   $(cat "peer-${DEVICE_LABEL}.pub")"
echo "peer psk:          $(cat "peer-${DEVICE_LABEL}.psk")"
echo
echo "Put the SERVER public key and endpoint into the config bundle JSON, then"
echo "sign it offline with: sweep-sign sign <private.key> bundle.json bundle.sig.json"
