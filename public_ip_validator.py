#!/usr/bin/env python3
"""
Public IP Validator
===================

Determines whether an IP address is a genuine ISP-assigned public IP.

Checks performed:
  1. What the Internet sees as your public IP (multiple echo services).
  2. Not private / CGNAT / reserved / otherwise non-public.
  3. ASN ownership - a real ISP, not a cloud/hosting provider (AWS, DigitalOcean, ...).
  4. Global routability (IANA + BGP announcement).
  5. Reverse DNS (PTR) with forward confirmation (FCrDNS).
  6. Consistency of the observed public IP across multiple providers.

Pure standard library - no dependencies. Python 3.8+.

Usage:
  python3 public_ip_validator.py                 # prompts for an IP (blank = auto-detect)
  python3 public_ip_validator.py 203.0.113.7     # validate a specific IP
  python3 public_ip_validator.py --json 203.0.113.7

Exit codes: 0 = looks valid / inconclusive, 1 = failed, 2 = usage error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

TIMEOUT = 6  # seconds per network operation

CYMRU_WHOIS = ("whois.cymru.com", 43)

# "What is my IP" echo services used for discovery + consistency checks.
IP_ECHO_SERVICES = {
    "ipify": "https://api64.ipify.org",
    "ifconfig.me": "https://ifconfig.me/ip",
    "icanhazip": "https://icanhazip.com",
    "ident.me": "https://api.ident.me",
    "ipinfo.io": "https://ipinfo.io/ip",
    "aws-checkip": "https://checkip.amazonaws.com",
}

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598

# AS names containing any of these keywords are treated as cloud / hosting /
# CDN networks rather than ISPs. Edit to taste.
HOSTING_ASN_KEYWORDS = (
    "AMAZON", "AWS", "DIGITALOCEAN", "MICROSOFT", "AZURE", "MSFT",
    "GOOGLE", "CLOUDFLARE", "ORACLE", "OVH", "HETZNER", "LINODE",
    "AKAMAI", "VULTR", "CHOOPA", "ALIBABA", "ALIYUN", "TENCENT",
    "SCALEWAY", "CONTABO", "LEASEWEB", "RACKSPACE", "SOFTLAYER",
    "KAMATERA", "UPCLOUD", "FASTLY", "DATACAMP", "WORLDSTREAM",
)

# AS names that contain a keyword above but are actually ISPs.
HOSTING_ASN_EXCEPTIONS = ("GOOGLE-FIBER",)

# PTR name fragments that suggest a residential/dynamic ISP assignment.
DYNAMIC_PTR_TOKENS = (
    "dynamic", "dyn.", "dyn-", "dhcp", "dsl", "adsl", "vdsl", "pool",
    "cable", "dial", "ppp", "cust", "broadband", "mobile", "lte",
    "wimax", "res.", "res-", "client", "fibra", "ftth", "gpon",
)

# PTR name fragments that suggest a static / server assignment.
STATIC_PTR_TOKENS = ("static", "mail", "mx.", "server", "vps", "dedicated", "colo")

PASS, WARN, FAIL, INFO, ERROR = "PASS", "WARN", "FAIL", "INFO", "ERROR"
SYMBOLS = {PASS: "✓", WARN: "⚠", FAIL: "✗", INFO: "ℹ", ERROR: "!"}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    status: str = INFO
    summary: str = ""
    details: list = field(default_factory=list)

    def add(self, line: str) -> None:
        self.details.append(line)


@dataclass
class AsnInfo:
    asn: Optional[int] = None
    as_name: str = ""
    prefix: str = ""
    country: str = ""
    registry: str = ""
    allocated: str = ""
    source: str = ""


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------

def http_get(url: str) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "public-ip-validator/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace").strip()


def fetch_public_ips() -> dict:
    """Query all echo services in parallel; name -> observed IP or None."""
    def fetch(item):
        name, url = item
        try:
            value = http_get(url)
            ipaddress.ip_address(value)  # sanity: must be a bare IP literal
            return name, value
        except Exception:
            return name, None

    with ThreadPoolExecutor(max_workers=len(IP_ECHO_SERVICES)) as pool:
        return dict(pool.map(fetch, IP_ECHO_SERVICES.items()))


def lookup_asn_cymru(ip_str: str) -> Optional[AsnInfo]:
    """Team Cymru whois (TCP/43). Returns AsnInfo, or None if unreachable."""
    try:
        with socket.create_connection(CYMRU_WHOIS, timeout=TIMEOUT) as sock:
            sock.sendall(f"-v {ip_str}\n".encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError:
        return None
    text = b"".join(chunks).decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line or "|" not in line or line.upper().startswith("AS "):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        if parts[0] in ("", "NA"):
            return AsnInfo(source="cymru")  # no ASN -> not announced
        try:
            asn = int(parts[0])
        except ValueError:
            continue
        return AsnInfo(
            asn=asn,
            prefix="" if parts[2] == "NA" else parts[2],
            country=parts[3],
            registry=parts[4],
            allocated=parts[5],
            as_name=parts[6],
            source="cymru",
        )
    return None


def lookup_asn_ipinfo(ip_str: str) -> Optional[AsnInfo]:
    """Fallback ASN lookup via ipinfo.io (rate-limited, no token needed)."""
    try:
        data = json.loads(http_get(f"https://ipinfo.io/{ip_str}/json"))
    except Exception:
        return None
    org = data.get("org", "") or ""
    info = AsnInfo(source="ipinfo.io", as_name=org,
                   country=data.get("country", ""))
    if org.upper().startswith("AS"):
        token = org.split(None, 1)
        try:
            info.asn = int(token[0][2:])
            if len(token) > 1:
                info.as_name = token[1]
        except ValueError:
            pass
    return info


def lookup_asn(ip_str: str) -> Optional[AsnInfo]:
    return lookup_asn_cymru(ip_str) or lookup_asn_ipinfo(ip_str)


def classify_asn(as_name: str) -> list:
    """Return the hosting/cloud keywords found in an AS name ([] = looks like an ISP)."""
    upper = as_name.upper()
    hits = [kw for kw in HOSTING_ASN_KEYWORDS if kw in upper]
    if any(exc in upper for exc in HOSTING_ASN_EXCEPTIONS) and "GOOGLE" in hits:
        hits.remove("GOOGLE")
    return hits


# --------------------------------------------------------------------------
# The six checks
# --------------------------------------------------------------------------

def check_public_ip_seen(echo: dict) -> Check:
    chk = Check("1. Public IP seen by the Internet")
    seen = {n: v for n, v in echo.items() if v}
    if not seen:
        chk.status = ERROR
        chk.summary = "no echo service could be reached"
        return chk
    for name, value in echo.items():
        chk.add(f"{name}: {value or 'unreachable'}")
    values = sorted(set(seen.values()))
    if len(values) == 1:
        chk.status = PASS
        chk.summary = f"all reachable providers see {values[0]}"
    else:
        chk.status = WARN
        chk.summary = f"providers disagree: {', '.join(values)}"
    return chk


def check_address_class(ip) -> Check:
    chk = Check("2. Not private / CGNAT / reserved")
    problems = []
    if ip.version == 4 and ip in CGNAT_NETWORK:
        problems.append("CGNAT range 100.64.0.0/10 (RFC 6598) - carrier-grade NAT, not a real public IP")
    if ip.is_loopback:
        problems.append("loopback address")
    if ip.is_link_local:
        problems.append("link-local address")
    if ip.is_multicast:
        problems.append("multicast address")
    if ip.is_reserved:
        problems.append("reserved address")
    if ip.is_unspecified:
        problems.append("unspecified address")
    if ip.is_private:
        problems.append("private/documentation range (RFC 1918 etc.)")
    if problems:
        chk.status = FAIL
        chk.summary = problems[0]
        for p in problems:
            chk.add(p)
    else:
        chk.status = PASS
        chk.summary = f"{ip} is in globally addressable space"
    return chk


def check_asn(ip_str: str, asn_info: Optional[AsnInfo]) -> Check:
    chk = Check("3. ASN ownership (ISP vs cloud/hosting)")
    if asn_info is None:
        chk.status = ERROR
        chk.summary = "ASN lookup failed (Team Cymru and ipinfo.io both unreachable)"
        return chk
    if asn_info.asn is None:
        chk.status = FAIL
        chk.summary = "no ASN announces this address - it is not allocated to any network"
        chk.add(f"source: {asn_info.source}")
        return chk
    chk.add(f"AS{asn_info.asn} - {asn_info.as_name}")
    if asn_info.country:
        chk.add(f"country: {asn_info.country} | registry: {asn_info.registry or 'n/a'}"
                f" | allocated: {asn_info.allocated or 'n/a'}")
    chk.add(f"source: {asn_info.source}")
    hits = classify_asn(asn_info.as_name)
    if hits:
        chk.status = FAIL
        chk.summary = f"owned by a cloud/hosting provider (matched: {', '.join(hits[:3])})"
        chk.add("this is datacenter/cloud space, not a consumer or business ISP assignment")
    else:
        chk.status = PASS
        chk.summary = f"AS{asn_info.asn} ({asn_info.as_name}) looks like a genuine ISP"
    return chk


def check_routability(ip, asn_info: Optional[AsnInfo]) -> Check:
    chk = Check("4. Routability")
    if not ip.is_global:
        chk.status = FAIL
        chk.summary = "fails the IANA global-unicast test (is_global is False)"
        return chk
    if asn_info is None:
        chk.status = WARN
        chk.summary = "IANA says global, but BGP announcement could not be verified (lookup failed)"
        return chk
    if asn_info.asn is None:
        chk.status = FAIL
        chk.summary = "no BGP announcement found - not routed on the public Internet"
        return chk
    if asn_info.prefix:
        chk.add(f"BGP prefix: {asn_info.prefix} announced by AS{asn_info.asn}")
    else:
        chk.add(f"announced by AS{asn_info.asn} (prefix data unavailable from {asn_info.source})")
    chk.status = PASS
    chk.summary = f"globally routable; announced by AS{asn_info.asn}"
    return chk


def check_reverse_dns(ip) -> Check:
    chk = Check("5. Reverse DNS (PTR)")
    ip_str = str(ip)
    try:
        ptr, _, _ = socket.gethostbyaddr(ip_str)
    except (socket.herror, socket.gaierror, OSError):
        ptr = None
    if not ptr:
        chk.status = WARN
        chk.summary = "no PTR record"
        chk.add("many residential ISPs omit PTR records - weakens the signal, but not fatal")
        return chk
    chk.add(f"PTR: {ptr}")
    confirmed = False
    try:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        infos = socket.getaddrinfo(ptr, None, family, socket.SOCK_STREAM)
        confirmed = any(info[4][0] == ip_str for info in infos)
    except (socket.gaierror, OSError):
        confirmed = False
    chk.add(f"forward-confirmed (PTR name resolves back to {ip_str}): "
            f"{'yes' if confirmed else 'no'}")
    lower = ptr.lower()
    dyn = [t for t in DYNAMIC_PTR_TOKENS if t in lower]
    sta = [t for t in STATIC_PTR_TOKENS if t in lower]
    if dyn:
        chk.add(f"pattern: residential/dynamic-looking ({', '.join(dyn[:4])}) - typical of consumer ISP space")
    elif sta:
        chk.add(f"pattern: static/server-looking ({', '.join(sta[:4])}) - typical of business or hosting space")
    if confirmed:
        chk.status = PASS
        chk.summary = f"{ptr} (forward-confirmed)"
    else:
        chk.status = WARN
        chk.summary = f"{ptr} (NOT forward-confirmed)"
    return chk


def check_consistency(echo: dict, candidate: str) -> Check:
    chk = Check("6. Consistency across providers")
    seen = {n: v for n, v in echo.items() if v}
    for name, value in echo.items():
        chk.add(f"{name}: {value or 'unreachable'}")
    if len(seen) < 2:
        chk.status = WARN
        chk.summary = "fewer than two providers reachable - consistency cannot be verified"
        return chk
    values = {v for v in seen.values()}
    if len(values) > 1:
        chk.status = FAIL
        chk.summary = (f"providers disagree ({', '.join(sorted(values))}) - "
                       "possible VPN/proxy or NAT inconsistency")
        return chk
    only = next(iter(values))
    if only == candidate:
        chk.status = PASS
        chk.summary = f"all {len(seen)} providers agree on {only}"
    else:
        chk.status = WARN
        chk.summary = (f"providers agree on {only}, which differs from the IP "
                       f"being checked ({candidate})")
    return chk


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def overall_verdict(checks: list) -> tuple:
    statuses = {c.status for c in checks}
    if FAIL in statuses:
        return FAIL, "NOT a valid ISP public IP (one or more checks failed)"
    if WARN in statuses or ERROR in statuses:
        return WARN, "INCONCLUSIVE - mostly looks like an ISP public IP, but some checks need review"
    return PASS, "VALID - this looks like a genuine ISP-assigned public IP"


def print_report(ip_str: str, checks: list, v_status: str, v_text: str) -> None:
    title = f" Public IP validation: {ip_str} "
    print("\n" + title.center(66, "="))
    for chk in checks:
        print(f"\n{SYMBOLS[chk.status]} {chk.name} -> {chk.status}")
        if chk.summary:
            print(f"    {chk.summary}")
        for line in chk.details:
            print(f"      - {line}")
    print("\n" + "=" * 66)
    print(f"{SYMBOLS[v_status]} VERDICT: {v_text}")


def to_json(ip_str: str, checks: list, v_status: str, v_text: str) -> str:
    return json.dumps({
        "ip": ip_str,
        "checks": [
            {"name": c.name, "status": c.status,
             "summary": c.summary, "details": c.details}
            for c in checks
        ],
        "verdict": {"status": v_status, "message": v_text},
    }, indent=2)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate whether an IP is a genuine ISP-assigned public IP.")
    parser.add_argument("ip", nargs="?",
                        help="public IP to check (omit to be prompted; blank = auto-detect)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    args = parser.parse_args(argv)

    socket.setdefaulttimeout(TIMEOUT)

    candidate = args.ip
    if candidate is None and sys.stdin.isatty():
        try:
            candidate = input("Public IP to check (blank = detect my own): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            print()
            return 2

    echo = fetch_public_ips()

    if candidate:
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            print(f"error: '{candidate}' is not a valid IP address", file=sys.stderr)
            return 2
    else:
        counts = {}
        for value in echo.values():
            if value:
                counts[value] = counts.get(value, 0) + 1
        if not counts:
            print("error: could not determine public IP "
                  "(all echo services unreachable)", file=sys.stderr)
            return 2
        best = max(counts, key=counts.get)
        ip_obj = ipaddress.ip_address(best)
        print(f"Auto-detected public IP: {best} "
              f"({counts[best]}/{sum(counts.values())} providers)")

    ip_str = str(ip_obj)
    asn_info = lookup_asn(ip_str)

    checks = [
        check_public_ip_seen(echo),
        check_address_class(ip_obj),
        check_asn(ip_str, asn_info),
        check_routability(ip_obj, asn_info),
        check_reverse_dns(ip_obj),
        check_consistency(echo, ip_str),
    ]
    v_status, v_text = overall_verdict(checks)

    if args.json:
        print(to_json(ip_str, checks, v_status, v_text))
    else:
        print_report(ip_str, checks, v_status, v_text)
    return 0 if v_status in (PASS, WARN) else 1


if __name__ == "__main__":
    sys.exit(main())
