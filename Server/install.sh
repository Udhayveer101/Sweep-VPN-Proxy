#!/usr/bin/env bash
# Provision a Debian/Ubuntu VPS as a Sweep VPN endpoint. Run as root.
# Idempotent. Does NOT touch the signing key — that lives offline.
set -euo pipefail

DEVICE_LABEL="${1:?usage: install.sh <device-label>}"

apt-get update
apt-get install -y wireguard unbound nftables

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

systemctl enable --now nftables
systemctl restart unbound
systemctl enable --now wg-quick@wg0
systemctl restart ssh || systemctl restart sshd

echo "server public key: $(cat server.pub)"
echo "peer public key:   $(cat "peer-${DEVICE_LABEL}.pub")"
echo "peer psk:          $(cat "peer-${DEVICE_LABEL}.psk")"
echo
echo "Put the SERVER public key and endpoint into the config bundle JSON, then"
echo "sign it offline with: sweep-sign sign <private.key> bundle.json bundle.sig.json"
