#!/bin/sh
# Install the reverse tunnel service on machine A. Run as root:  sudo ./install.sh
# Edit tunnel.conf next to this script first (or /etc/reverse-tunnel/tunnel.conf afterwards).
# Optional: KEY=/path/to/existing_private_key sudo -E ./install.sh  to use an existing key.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
etc=/etc/reverse-tunnel

install -d -m 0755 -o root -g root "$etc"   # service user must read known_hosts; the key itself stays 0600
[ -f "$etc/tunnel.conf" ] || install -m 0644 "$here/tunnel.conf" "$etc/tunnel.conf"
install -m 0644 "$here/README.md" "$etc/README.md"
install -m 0644 "$here/reverse-tunnel.service" /etc/systemd/system/reverse-tunnel.service

# Secret: private key (root-only on disk, passed to the service via LoadCredential)
if [ ! -f "$etc/id_ed25519" ]; then
    if [ -n "${KEY:-}" ]; then
        install -m 0600 -o root -g root "$KEY" "$etc/id_ed25519"
    else
        ssh-keygen -q -t ed25519 -N '' -C "reverse-tunnel@$(hostname)" -f "$etc/id_ed25519"
    fi
fi
chmod 0600 "$etc/id_ed25519"

. "$etc/tunnel.conf"
# Pin B's host key (verify the fingerprints below against B: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)
if [ ! -s "$etc/known_hosts" ]; then
    ssh-keyscan -p "$REMOTE_SSH_PORT" "$REMOTE_HOST" 2>/dev/null > "$etc/known_hosts" || true
fi
chmod 0644 "$etc/known_hosts"
echo "== pinned host keys for $REMOTE_HOST (verify!):"
ssh-keygen -lf "$etc/known_hosts" || echo "   (none: could not reach $REMOTE_HOST, fill $etc/known_hosts manually)"

systemctl daemon-reload
echo
echo "== Put this line in ~$REMOTE_USER/.ssh/authorized_keys on $REMOTE_HOST:"
printf 'restrict,port-forwarding,permitlisten="%s" %s\n' "$REMOTE_PORT" "$(ssh-keygen -y -f "$etc/id_ed25519")"
echo
echo "== Then:  systemctl enable --now reverse-tunnel   ;  journalctl -u reverse-tunnel -f"
