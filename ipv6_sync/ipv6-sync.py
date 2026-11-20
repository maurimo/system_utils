#!/usr/bin/python3 -I
"""Keep DuckDNS and the Linksys IPv6 firewall rule pointed at this host's stable IPv6 address.

Watches address changes (`ip -6 monitor address`) and also reconciles periodically, so it
recovers from router resets, manual edits and transient failures.

Configuration comes from the environment (see ipv6-sync.conf); secrets from files:
  $CREDENTIALS_DIRECTORY/duckdns_token  and  $CREDENTIALS_DIRECTORY/router_password
(set by systemd LoadCredential), or --credentials-dir DIR for manual runs.

Manual use:
  ipv6-sync --once --dry-run   show what would change, change nothing
  ipv6-sync --once             reconcile once and exit
"""
import argparse
import base64
import ipaddress
import json
import os
import select
import subprocess
import sys
import time
import urllib.parse
import urllib.request

IP = "/usr/bin/ip" if os.path.exists("/usr/bin/ip") else "/usr/sbin/ip"
JNAP = "http://linksys.com/jnap/firewall/"


def log(msg):
    print(msg, flush=True)


def conf(name, default=None):
    v = os.environ.get(name, "").strip()
    if v:
        return v
    if default is None:
        sys.exit(f"missing configuration: {name}")
    return default


def read_secret(creddir, name):
    path = os.path.join(creddir, name)
    try:
        with open(path) as f:
            s = f.read().strip()
    except OSError as e:
        sys.exit(f"cannot read secret {name}: {e.strerror}")
    if not s:
        sys.exit(f"secret {name} is empty")
    return s


# ---------------------------------------------------------------- address detection

def default_iface():
    out = subprocess.run([IP, "-j", "-6", "route", "show", "default"],
                         capture_output=True, text=True, check=True).stdout
    routes = json.loads(out or "[]")
    return routes[0]["dev"] if routes else None


def stable_address(iface):
    """Global, non-temporary, non-deprecated, non-ULA address; prefer SLAAC 'mngtmpaddr'."""
    if not iface:
        return None
    out = subprocess.run([IP, "-j", "-6", "addr", "show", "dev", iface, "scope", "global"],
                         capture_output=True, text=True, check=True).stdout
    cands = []
    for link in json.loads(out or "[]"):
        for a in link.get("addr_info", []):
            if a.get("family") != "inet6":
                continue
            if a.get("temporary") or a.get("deprecated") or a.get("tentative") or a.get("dadfailed"):
                continue
            addr = ipaddress.IPv6Address(a["local"])
            if not addr.is_global:          # excludes ULA fc00::/7, link-local, documentation...
                continue
            life = a.get("preferred_life_time", 0)
            life = 2**32 if life in ("forever", None) else int(life)
            cands.append((bool(a.get("mngtmpaddr")), life, str(addr)))
    if not cands:
        return None
    cands.sort(reverse=True)
    return cands[0][2]


# ---------------------------------------------------------------- DuckDNS

def duckdns_current(domain):
    """AAAA as published (best effort, via the system resolver; may be cached)."""
    import socket
    try:
        infos = socket.getaddrinfo(f"{domain}.duckdns.org", None, socket.AF_INET6)
        return {i[4][0] for i in infos}
    except OSError:
        return set()


def duckdns_update(domain, token, addr, dry_run):
    if dry_run:
        log(f"[dry-run] would set {domain}.duckdns.org AAAA={addr}, no A record")
        return True
    # ip= (empty) stops DuckDNS from auto-filling the A record with our IPv4.
    q = urllib.parse.urlencode({"domains": domain, "token": token, "ip": "", "ipv6": addr, "verbose": "true"})
    with urllib.request.urlopen(f"https://www.duckdns.org/update?{q}", timeout=30) as r:
        lines = r.read().decode(errors="replace").split("\n")
    if lines[0] != "OK":
        log(f"DuckDNS update FAILED (response {lines[0]!r}: wrong token or domain?)")
        return False
    log(f"DuckDNS {domain}.duckdns.org AAAA={addr}: {lines[-1] if len(lines) > 1 else 'OK'}")
    return True


# ---------------------------------------------------------------- Linksys (JNAP)

class Router:
    def __init__(self, base, user, password):
        self.url = base.rstrip("/") + "/JNAP/"
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def call(self, action, body=None):
        req = urllib.request.Request(self.url, data=json.dumps(body or {}).encode(), headers={
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": JNAP + action,
            "X-JNAP-Authorization": self.auth,
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.load(r)
        if res.get("result") != "OK":
            raise RuntimeError(f"router {action}: {res.get('result')} {res.get('error', '')}".strip())
        return res.get("output", {})


def parse_ports(spec):
    """'TCP:22' or 'TCP:22,UDP:6000-6010' -> JNAP portRanges."""
    out = []
    for item in spec.split(","):
        proto, _, ports = item.strip().partition(":")
        first, _, last = ports.partition("-")
        out.append({"protocol": proto.upper(), "firstPort": int(first), "lastPort": int(last or first)})
    return out


def same_addr(a, b):
    """The router stores addresses zero-padded (e.g. '0c40'), so compare parsed values."""
    try:
        return ipaddress.IPv6Address(a) == ipaddress.IPv6Address(b)
    except ValueError:
        return False


def router_sync(router, description, ports, addr, dry_run):
    rules = router.call("GetIPv6FirewallRules")["rules"]
    mine = [r for r in rules if r.get("description", "").lower() == description.lower()]
    if len(mine) > 1:
        log(f"warning: {len(mine)} router rules named {description!r}; updating all of them")
    if mine and all(same_addr(r["ipv6Address"], addr) and r["isEnabled"] for r in mine):
        return True, False
    if mine:
        for r in mine:
            log(f"router rule {r['description']!r}: {r['ipv6Address']} -> {addr}")
            r["ipv6Address"] = addr
            r["isEnabled"] = True
    else:
        log(f"router rule {description!r} not found: creating it for {addr} {ports}")
        rules.append({"isEnabled": True, "ipv6Address": addr, "portRanges": ports, "description": description})
    if dry_run:
        log("[dry-run] router not modified")
        return True, True
    router.call("SetIPv6FirewallRules", {"rules": rules})
    check = router.call("GetIPv6FirewallRules")["rules"]
    ok = any(r.get("description", "").lower() == description.lower() and same_addr(r["ipv6Address"], addr)
             for r in check)
    log("router rule updated" if ok else "router rule update did NOT stick")
    return ok, True


# ---------------------------------------------------------------- main loop

def reconcile(cfg, state, dry_run):
    iface = cfg["iface"] or default_iface()
    addr = stable_address(iface)
    if not addr:
        log(f"no stable global IPv6 address on {iface or '(no default route)'}; nothing to do")
        return True
    if addr != state.get("addr"):
        log(f"stable address on {iface}: {addr}" + (f" (was {state['addr']})" if state.get("addr") else ""))
    ok = True

    # DuckDNS: push when the address changed, after a failure, or once a day as a refresh.
    stale = time.time() - state.get("duck_time", 0) > 86400
    if addr != state.get("duck_addr") or stale:
        try:
            if duckdns_update(cfg["domain"], cfg["token"], addr, dry_run) and not dry_run:
                state["duck_addr"], state["duck_time"] = addr, time.time()
        except OSError as e:
            log(f"DuckDNS update failed: {e}")
            ok = False
    # Router: always compare against the router's actual rules (cheap LAN call).
    try:
        r_ok, changed = router_sync(cfg["router"], cfg["rule"], cfg["ports"], addr, dry_run)
        if not changed and addr != state.get("addr"):
            log(f"router rule {cfg['rule']!r} already allows {addr}")
        ok &= r_ok
    except (OSError, RuntimeError, KeyError, ValueError) as e:
        log(f"router sync failed: {e}")
        ok = False
    state["addr"] = addr
    return ok


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="reconcile once and exit")
    ap.add_argument("--dry-run", action="store_true", help="report what would change, change nothing")
    ap.add_argument("--credentials-dir", default=os.environ.get("CREDENTIALS_DIRECTORY"))
    args = ap.parse_args()
    if not args.credentials_dir:
        sys.exit("no credentials: run under systemd (LoadCredential) or pass --credentials-dir")

    cfg = {
        "iface": os.environ.get("IFACE", "").strip(),
        "domain": conf("DUCKDNS_DOMAIN"),
        "token": read_secret(args.credentials_dir, "duckdns_token"),
        "router": Router(conf("ROUTER_URL", "http://192.168.1.1"), conf("ROUTER_USER", "admin"),
                         read_secret(args.credentials_dir, "router_password")),
        "rule": conf("ROUTER_RULE_DESCRIPTION", "ssh"),
        "ports": parse_ports(conf("ROUTER_RULE_PORTS", "TCP:22")),
    }
    interval = int(conf("CHECK_INTERVAL", "600"))
    state_dir = os.environ.get("STATE_DIRECTORY", "")
    state_path = os.path.join(state_dir, "state.json") if state_dir and not args.dry_run else ""
    state = load_state(state_path) if state_path else {}

    if args.once:
        ok = reconcile(cfg, state, args.dry_run)
        save_state(state_path, state)
        sys.exit(0 if ok else 1)

    mon = subprocess.Popen([IP, "-6", "monitor", "address"], stdout=subprocess.PIPE, text=True, bufsize=1)
    log(f"watching IPv6 address changes; periodic check every {interval}s")
    retry = interval
    next_check = 0.0
    while True:
        now = time.monotonic()
        if now >= next_check:
            ok = reconcile(cfg, state, args.dry_run)
            save_state(state_path, state)
            # after a failure retry in 30s, then 60s, 120s, ... capped at the normal interval
            if ok:
                retry = interval
            else:
                retry = 30 if retry >= interval else min(interval, retry * 2)
            next_check = time.monotonic() + retry
        timeout = max(0.0, next_check - time.monotonic())
        ready, _, _ = select.select([mon.stdout], [], [], timeout)
        if ready:
            if not mon.stdout.readline():
                sys.exit("ip monitor exited")      # systemd restarts us
            # debounce: SLAAC/DAD produce bursts of events; settle for 5 s
            end = time.monotonic() + 5
            while select.select([mon.stdout], [], [], max(0.0, end - time.monotonic()))[0]:
                if not mon.stdout.readline():
                    sys.exit("ip monitor exited")
            next_check = 0.0


if __name__ == "__main__":
    main()
