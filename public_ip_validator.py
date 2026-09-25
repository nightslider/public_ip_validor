#!/usr/bin/env python3
"""
Public IP Validator
===================

Determines whether an IP address is a genuine ISP-assigned public IP.

Checks performed:
    1. When auto-detecting, what the Internet sees as your public IP (multiple echo services).
  2. Not private / CGNAT / reserved / otherwise non-public.
    3. IP geolocation in the United States or Canada.
    4. ASN ownership - a real ISP, not a cloud/hosting provider (AWS, DigitalOcean, ...).
    5. Global routability (IANA + BGP announcement).
    6. Optional reverse DNS (PTR) lookup with forward confirmation.
    7. Optional IPv4 subnet mask and default-gateway configuration.
    8. Known DNS address filtering.
    9. When auto-detecting, consistency of the observed public IP across multiple providers.

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
from functools import lru_cache
from pathlib import Path
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

PASS, WARN, FAIL, INFO, ERROR = "PASS", "WARN", "FAIL", "INFO", "ERROR"
SYMBOLS = {PASS: "✓", WARN: "⚠", FAIL: "✗", INFO: "ℹ", ERROR: "!"}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Check:
    # One validation row. The same object feeds CLI reports, GUI rows, and JSON.
    name: str
    status: str = INFO
    summary: str = ""
    details: list = field(default_factory=list)

    def add(self, line: str) -> None:
        self.details.append(line)


@dataclass
class AsnInfo:
    # Normalized ASN data from Team Cymru or the ipinfo.io fallback.
    asn: Optional[int] = None
    as_name: str = ""
    prefix: str = ""
    country: str = ""
    registry: str = ""
    allocated: str = ""
    source: str = ""


@dataclass
class ValidationResult:
    # Shared result shape returned by the core validator to every interface.
    ip: str
    checks: list
    status: str
    message: str
    echo: Optional[dict] = None


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
            # Echo services should return a bare IP literal. Anything else is ignored.
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
        # Team Cymru is the preferred source because it returns BGP prefix data.
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
        # Skip headers and malformed rows; data rows are pipe-delimited.
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
        # ipinfo.io is HTTP-friendly, but may not include prefix metadata.
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


@lru_cache(maxsize=512)
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
# Validation checks
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
    # Python's ipaddress covers most non-public ranges; CGNAT needs an explicit check.
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
        chk.summary = "; ".join(problems)
        for p in problems:
            chk.add(p)
    else:
        chk.status = PASS
        chk.summary = f"{ip} is in globally addressable space"
    return chk


def check_ip_registry(asn_info: Optional[AsnInfo]) -> Check:
    chk = Check("3. IP registry (ARIN)")
    if asn_info is None or not asn_info.registry:
        chk.status = ERROR
        chk.summary = "IP registry could not be determined from Team Cymru"
        return chk

    registry = asn_info.registry.strip().upper()
    chk.add(f"registry: {registry} (source: {asn_info.source})")
    if registry == "ARIN":
        chk.status = PASS
        chk.summary = "IP address is registered with ARIN"
    else:
        chk.status = FAIL
        chk.summary = f"IP address is registered with {registry}, not ARIN"
    return chk


def check_asn(ip_str: str, asn_info: Optional[AsnInfo]) -> Check:
    chk = Check("4. ASN ownership (ISP vs cloud/hosting)")
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
    chk = Check("5. Routability")
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
    """Look up an address's PTR record and verify forward-confirmed DNS."""
    chk = Check("6. Reverse DNS (PTR)")
    ip_str = str(ip)
    try:
        ptr, _, _ = socket.gethostbyaddr(ip_str)
    except (socket.herror, socket.gaierror, OSError):
        chk.status = WARN
        chk.summary = "no PTR record"
        chk.add("many ISP-assigned addresses do not publish a PTR record")
        return chk

    chk.add(f"PTR: {ptr}")
    try:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        infos = socket.getaddrinfo(ptr, None, family, socket.SOCK_STREAM)
        confirmed = any(info[4][0] == ip_str for info in infos)
    except (socket.gaierror, OSError):
        confirmed = False
    if confirmed:
        chk.status = PASS
        chk.summary = f"{ptr} (forward-confirmed)"
    else:
        chk.status = WARN
        chk.summary = f"{ptr} (NOT forward-confirmed)"
    return chk


def check_subnet_and_gateway(ip, subnet_mask: str, gateway: str) -> Check:
    """Validate an IPv4 address, subnet mask, and default gateway as one configuration."""
    chk = Check("7. IPv4 subnet mask and default gateway")
    problems = []
    if ip.version != 4:
        problems.append("subnet mask and default gateway validation currently supports IPv4 only")
        network = None
    else:
        try:
            network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
        except ValueError:
            network = None
            problems.append(f"invalid IPv4 subnet mask: {subnet_mask}")
    try:
        gateway_ip = ipaddress.ip_address(gateway)
    except ValueError:
        gateway_ip = None
        problems.append(f"invalid default gateway address: {gateway}")
    if gateway_ip is not None and gateway_ip.version != 4:
        problems.append("default gateway must be an IPv4 address")

    if network is not None:
        chk.add(f"subnet: {network.with_netmask}")
        # Use hosts() so network and broadcast addresses are rejected for IPv4 subnets.
        if ip not in network.hosts():
            problems.append(f"{ip} is not a usable host address in {network.with_netmask}")
        if gateway_ip is not None and gateway_ip.version == 4:
            if gateway_ip not in network:
                problems.append(f"gateway {gateway_ip} is outside {network.with_netmask}")
            elif gateway_ip not in network.hosts():
                problems.append(f"gateway {gateway_ip} is not a usable host address")
    if gateway_ip == ip:
        problems.append("default gateway must differ from the IP address being checked")

    if problems:
        chk.status = FAIL
        chk.summary = "; ".join(problems)
        return chk

    chk.status = PASS
    chk.summary = f"gateway {gateway_ip} is a usable host in the same subnet"
    return chk


@lru_cache(maxsize=1)
def load_known_dns_networks() -> tuple:
    dns_file = Path(__file__).resolve().with_name("dnsaddresses.txt")
    networks = []
    if not dns_file.exists():
        return tuple(networks)
    for line in dns_file.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if "-" in text:
            # dnsaddresses.txt may contain inclusive ranges; collapse them to CIDR blocks.
            start_text, end_text = [part.strip() for part in text.split("-", 1)]
            try:
                start = ipaddress.ip_address(start_text)
                end = ipaddress.ip_address(end_text)
                networks.extend(ipaddress.summarize_address_range(start, end))
            except ValueError:
                continue
        else:
            try:
                ip = ipaddress.ip_address(text)
                networks.append(ipaddress.ip_network(f"{ip}/32", strict=False))
            except ValueError:
                continue
    return tuple(networks)


@lru_cache(maxsize=4096)
def is_known_dns_ip(ip) -> bool:
    return any(ip in network for network in load_known_dns_networks())


def check_known_dns(ip, policy: str = "fail") -> Check:
    chk = Check("8. Known DNS address")
    if is_known_dns_ip(ip):
        msg = f"{ip} is a known DNS IP address listed in dnsaddresses.txt"
        chk.add("this address is a known DNS resolver and is not a likely consumer ISP public IP")
        if policy == "ignore":
            chk.status = PASS
            chk.summary = f"{ip} matches a known DNS entry, but DNS filtering is disabled"
            return chk
        if policy == "warn":
            chk.status = WARN
            chk.summary = msg
            return chk
        chk.status = FAIL
        chk.summary = msg
        return chk
    chk.status = PASS
    chk.summary = f"{ip} is not listed as a known DNS IP address"
    return chk


def check_consistency(echo: dict, candidate: str) -> Check:
    chk = Check("9. Consistency across providers")
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


def validate_public_ip(candidate=None, subnet_mask=None, gateway=None,
                       reverse_dns=False, dns_policy="fail") -> ValidationResult:
    """Run the shared validation flow used by the CLI, GUI, and web app."""
    # Normalize blanks from forms, prompts, and JSON into one internal shape.
    candidate = candidate.strip() if isinstance(candidate, str) else candidate
    subnet_mask = subnet_mask.strip() if isinstance(subnet_mask, str) else subnet_mask
    gateway = gateway.strip() if isinstance(gateway, str) else gateway
    candidate = candidate or None
    subnet_mask = subnet_mask or None
    gateway = gateway or None

    if dns_policy not in ("fail", "warn", "ignore"):
        raise ValueError("known DNS policy must be fail, warn, or ignore")
    if bool(subnet_mask) != bool(gateway):
        raise ValueError("subnet mask and default gateway must be provided together")

    socket.setdefaulttimeout(TIMEOUT)
    echo = None
    if candidate:
        # Explicit IP checks skip echo services because they may not match this device.
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            raise ValueError(f"'{candidate}' is not a valid IP address")
    else:
        # Blank input means auto-detect by asking several external echo services.
        echo = fetch_public_ips()
        counts = {}
        for value in echo.values():
            if value:
                counts[value] = counts.get(value, 0) + 1
        if not counts:
            raise RuntimeError("could not determine public IP (all echo services unreachable)")
        ip_obj = ipaddress.ip_address(max(counts, key=counts.get))

    ip_str = str(ip_obj)
    asn_info = lookup_asn(ip_str)
    # Keep this order aligned with the numbered README checklist and user reports.
    checks = [
        check_address_class(ip_obj),
        check_ip_registry(asn_info),
        check_asn(ip_str, asn_info),
        check_routability(ip_obj, asn_info),
        check_known_dns(ip_obj, dns_policy),
    ]
    if reverse_dns:
        checks.insert(3, check_reverse_dns(ip_obj))
    if subnet_mask:
        checks.append(check_subnet_and_gateway(ip_obj, subnet_mask, gateway))
    if echo is not None:
        # Auto-detection adds visibility and consistency checks around the core IP checks.
        checks.insert(0, check_public_ip_seen(echo))
        checks.append(check_consistency(echo, ip_str))

    status, message = overall_verdict(checks)
    return ValidationResult(ip_str, checks, status, message, echo)


def validation_result_to_dict(result: ValidationResult) -> dict:
    return {
        "ip": result.ip,
        "checks": [
            {"name": c.name, "status": c.status,
             "summary": c.summary, "details": c.details}
            for c in result.checks
        ],
        "verdict": {"status": result.status, "message": result.message},
    }


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
    return json.dumps(validation_result_to_dict(
        ValidationResult(ip_str, checks, v_status, v_text)), indent=2)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate whether an IP is a genuine ISP-assigned public IP.")
    parser.add_argument("ip", nargs="?",
                        help="public IP to check (omit to be prompted; blank = auto-detect)")
    parser.add_argument("--subnet-mask", metavar="MASK",
                        help="IPv4 subnet mask or CIDR prefix (requires --gateway)")
    parser.add_argument("--gateway", metavar="IP",
                        help="IPv4 default gateway (requires --subnet-mask)")
    parser.add_argument("--reverse-dns", action="store_true",
                        help="look up PTR and verify forward-confirmed DNS for the target IP")
    parser.add_argument("--dns-policy", choices=("fail", "warn", "ignore"), default="fail",
                        help="how to handle a known DNS IP match: fail (default), warn, or ignore")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    args = parser.parse_args(argv)

    candidate = args.ip
    if candidate is None and sys.stdin.isatty():
        # Interactive CLI mode keeps positional IP optional while still supporting scripts.
        try:
            candidate = input("Public IP to check (blank = detect my own): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            print()
            return 2

    if args.ip is None and args.subnet_mask is None and args.gateway is None and sys.stdin.isatty():
        try:
            subnet_mask = input("Subnet mask (blank to skip): ").strip()
            gateway = input("Default gateway (blank to skip): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 2
        if subnet_mask or gateway:
            if not subnet_mask or not gateway:
                print("error: subnet mask and default gateway must be provided together", file=sys.stderr)
                return 2
            args.subnet_mask = subnet_mask
            args.gateway = gateway

    try:
        result = validate_public_ip(
            candidate=candidate,
            subnet_mask=args.subnet_mask,
            gateway=args.gateway,
            reverse_dns=args.reverse_dns,
            dns_policy=args.dns_policy,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if candidate is None and result.echo is not None:
        counts = {}
        for value in result.echo.values():
            if value:
                counts[value] = counts.get(value, 0) + 1
        print(f"Auto-detected public IP: {result.ip} "
              f"({counts[result.ip]}/{sum(counts.values())} providers)")

    if args.json:
        print(to_json(result.ip, result.checks, result.status, result.message))
    else:
        print_report(result.ip, result.checks, result.status, result.message)
    return 0 if result.status in (PASS, WARN) else 1


if __name__ == "__main__":
    sys.exit(main())
