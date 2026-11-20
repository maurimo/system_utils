# Reverse SSH tunnel: C -> B:REMOTE_PORT -> A:22

A (this host, behind NAT) keeps an outbound ssh connection to B with `-R`,
so B listens on REMOTE_PORT and forwards every connection back to A's sshd.

## Files (on A)
- `/etc/systemd/system/reverse-tunnel.service`  systemd unit (plain ssh, restarted by systemd; no autossh needed)
- `/etc/reverse-tunnel/tunnel.conf`             configuration
- `/etc/reverse-tunnel/id_ed25519`              secret key (root 0600, given to the service via LoadCredential)
- `/etc/reverse-tunnel/known_hosts`             pinned host key of B

## Setup on A
    $EDITOR tunnel.conf          # REMOTE_HOST, REMOTE_USER, REMOTE_PORT ...
    sudo ./install.sh            # or: sudo KEY=/path/to/key ./install.sh
    # (configure B, see below)
    sudo systemctl enable --now reverse-tunnel
    journalctl -u reverse-tunnel -f

## Setup on B (as root)
    useradd -m -s /usr/sbin/nologin tunnel
    install -d -m 700 -o tunnel -g tunnel ~tunnel/.ssh
    # paste the line printed by install.sh:
    #   restrict,port-forwarding,permitlisten="2222" ssh-ed25519 AAAA... reverse-tunnel@A
    $EDITOR ~tunnel/.ssh/authorized_keys && chown tunnel: ~tunnel/.ssh/authorized_keys && chmod 600 ~tunnel/.ssh/authorized_keys

Append to `/etc/ssh/sshd_config` (Match blocks must be at the end):

    Match User tunnel
        GatewayPorts clientspecified
        AllowTcpForwarding remote
        X11Forwarding no
        PermitTTY no
        ForceCommand /bin/false

Also make sure B drops dead sessions quickly, so the port is freed when A reconnects
(global section, before any Match):

    ClientAliveInterval 30
    ClientAliveCountMax 3

Then `sshd -t && systemctl reload ssh`, and open REMOTE_PORT/tcp in B's firewall / cloud security group.

## Use from C
    ssh -p 2222 user_on_A@B

## Notes
- Connections reach A's sshd from 127.0.0.1, so A's sshd is now Internet-exposed and
  fail2ban on A cannot see real client IPs: use key-only auth on A (`PasswordAuthentication no`).
- If the link dies, ServerAlive (90 s) makes ssh exit and systemd restarts it after 15 s;
  ExitOnForwardFailure ensures a reconnect that cannot bind the port is retried instead of idling.
