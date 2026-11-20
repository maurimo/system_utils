# system_utils

Small hardened systemd services for a home host behind NAT. Each folder has its own
`README.md` and an `install.sh` (run as root).

- **`reverse_tunnel/`**: keeps a persistent reverse SSH tunnel to a public VPS, so the
  host's sshd is reachable at `VPS:REMOTE_PORT` without opening ports on the home router.
- **`ipv6_sync/`**: follows the host's stable IPv6 address when the ISP prefix changes,
  updating a DuckDNS AAAA record and the Linksys router's IPv6 firewall rule for SSH.
