# ipv6-sync: follow this host's stable IPv6 address

The ISP prefix is dynamic, and the SLAAC "stable-privacy" address is derived from it, so the
whole address changes with the prefix. This service keeps two things pointed at it:

1. **DuckDNS**: `DUCKDNS_DOMAIN.duckdns.org` AAAA = stable address, no A record.
2. **Linksys router** (Security -> Firewall -> IPv6 port services): the rule whose
   description is `ROUTER_RULE_DESCRIPTION` (default `ssh`) gets the new address. Other rules
   are left untouched; the rule is created with `ROUTER_RULE_PORTS` if it does not exist.

"Stable address" = global, non-temporary, non-deprecated, non-ULA address on the interface
with the IPv6 default route, preferring the SLAAC `mngtmpaddr` one (the privacy/temporary
addresses used for outgoing connections are ignored).

## How it works
- `ip -6 monitor address` triggers a check a few seconds after any address change.
- A full check also runs every `CHECK_INTERVAL` seconds (default 600): it reads the
  router's rules and fixes them if they differ (router reset, manual edit), and retries
  failures with backoff. DuckDNS is updated when the address changes, plus once a day.
- The router is driven through JNAP (`POST /JNAP/`, the API behind the web UI), with
  `GetIPv6FirewallRules` / `SetIPv6FirewallRules`; the change is verified by reading back.

## Files
- `/usr/local/sbin/ipv6-sync`                  the script (Python 3, stdlib only)
- `/etc/systemd/system/ipv6-sync.service`      unit (DynamicUser, hardened)
- `/etc/ipv6-sync/ipv6-sync.conf`              configuration
- `/etc/ipv6-sync/duckdns_token`               secret, root 0600 (LoadCredential)
- `/etc/ipv6-sync/router_password`             secret, root 0600 (LoadCredential)
- `/var/lib/private/ipv6-sync/state.json`      last address pushed

## Setup
    sudo ./install.sh                  # asks for the token and router password, shows a dry run
    sudo systemctl enable --now ipv6-sync
    journalctl -u ipv6-sync -f

Manual check (as root):

    set -a; . /etc/ipv6-sync/ipv6-sync.conf; set +a
    ipv6-sync --once --dry-run --credentials-dir /etc/ipv6-sync

## Notes
- The router API is plain HTTP on the LAN, like the web UI itself: anyone sniffing the
  LAN could see the admin password. Keep the Wi-Fi WPA2/WPA3 and don't use this on an
  untrusted network.
- Changing the router password: update `/etc/ipv6-sync/router_password`, then
  `systemctl restart ipv6-sync`. Same for a regenerated DuckDNS token.
- The ufw rule on this host allows the *VPS* address as source, which is static, so it
  does not need updating.
