#!/bin/sh
# Install ipv6-sync. Run as root:  sudo ./install.sh
# Secrets are asked interactively if missing, or taken from DUCKDNS_TOKEN / ROUTER_PASSWORD
# (sudo -E ./install.sh). Re-running keeps existing config and secrets.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
etc=/etc/ipv6-sync

install -d -m 0755 -o root -g root "$etc"
[ -f "$etc/ipv6-sync.conf" ] || install -m 0644 "$here/ipv6-sync.conf" "$etc/ipv6-sync.conf"
install -m 0644 "$here/README.md" "$etc/README.md"
install -m 0755 "$here/ipv6-sync.py" /usr/local/sbin/ipv6-sync
install -m 0644 "$here/ipv6-sync.service" /etc/systemd/system/ipv6-sync.service

secret() {  # secret FILE ENVVAR PROMPT
    [ -s "$etc/$1" ] && return 0
    val=$(eval "printf %s \"\${$2:-}\"")
    if [ -z "$val" ]; then
        [ -t 0 ] || { echo "no $1: set $2 or run interactively"; exit 1; }
        printf '%s: ' "$3"; stty -echo; read -r val; stty echo; echo
    fi
    [ -n "$val" ] || { echo "empty $1, aborting"; exit 1; }
    (umask 077; printf '%s\n' "$val" > "$etc/$1")
}
secret duckdns_token   DUCKDNS_TOKEN   "DuckDNS token"
secret router_password ROUTER_PASSWORD "Linksys admin password"
chown root:root "$etc/duckdns_token" "$etc/router_password"
chmod 0600 "$etc/duckdns_token" "$etc/router_password"

systemctl daemon-reload
echo "== dry run (changes nothing):"
(set -a; . "$etc/ipv6-sync.conf"; set +a
 /usr/local/sbin/ipv6-sync --once --dry-run --credentials-dir "$etc") || true
echo
echo "== Then:  systemctl enable --now ipv6-sync   ;  journalctl -u ipv6-sync -f"
