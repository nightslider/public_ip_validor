# Public IP Validator

A zero-dependency Python CLI and desktop GUI that checks whether an IP address
is a genuine, ISP-assigned **public** IP address.

## What it checks

1. **What the Internet sees** — when auto-detecting, queries several "what is
   my IP" echo services (ipify, ifconfig.me, icanhazip, ident.me, ipinfo.io,
   AWS checkip) in parallel.
2. **Not private / CGNAT** — rejects RFC 1918 private ranges, the RFC 6598
   CGNAT range (`100.64.0.0/10`), loopback, link-local, multicast, reserved
   and documentation ranges.
3. **ASN ownership** — looks up the announcing ASN via Team Cymru whois
   (ipinfo.io fallback) and fails known cloud/hosting/CDN networks
   (Amazon/AWS, DigitalOcean, Microsoft, Google, Hetzner, OVH, ...).
   Tune the list by editing `HOSTING_ASN_KEYWORDS` in the script.
4. **Routability** — must be global unicast per IANA *and* have a visible
   BGP announcement.
5. **Reverse DNS** — when requested, looks up the PTR record and confirms that
   the PTR name resolves back to the target IP.
6. **IPv4 subnet and gateway** — when supplied, checks that the subnet mask is
   valid and the public IP and default gateway are distinct usable hosts in the
   same subnet.
7. **Known DNS address** — checks the local `dnsaddresses.txt` list according
   to the selected DNS policy.
8. **Consistency** — when auto-detecting, all reachable providers must agree
   on the same public IP.

## Requirements

Python 3.8+. Standard library only — nothing to install.

## Usage

### Desktop GUI

On Windows, double-click `public_ip_validator_gui.pyw` to open the GUI directly.

```bash
python3 public_ip_validator_gui.py
```

The GUI supports automatic public-IP detection, explicit IP validation, reverse
DNS checks, subnet and gateway checks, and all three known-DNS policies. It is
implemented with Tkinter, which is included with most Python installations.
Passing checks show `✅ PASS`; failed checks show `⛔ FAIL` in red.

### Command line

```bash
# Type an IP interactively (press Enter with no input to auto-detect your own)
python3 public_ip_validator.py

# Validate a specific public IP
# This does not compare it with this device's outbound IP.
python3 public_ip_validator.py 203.0.113.7

# Check the target address's reverse DNS. A missing or non-confirming PTR warns.
python3 public_ip_validator.py 203.0.113.7 --reverse-dns

# Also validate an IPv4 subnet mask and default gateway.
# The address must be a host address and the gateway must be in the same subnet.
python3 public_ip_validator.py 134.215.239.227 \
   --subnet-mask 255.255.0.0 --gateway 134.215.0.1

# Machine-readable output
python3 public_ip_validator.py --json 203.0.113.7
```

## Exit codes

| Code | Meaning                                  |
|-----:|------------------------------------------|
| 0    | Valid, or inconclusive (warnings only)   |
| 1    | Failed — not a valid ISP public IP       |
| 2    | Usage error / bad input                  |

## Tests

```bash
python3 -m unittest -v
```

(Tests are offline; they only exercise pure logic, no network calls.)

## Limitations

- ASN lookup needs outbound TCP/43 (whois) for Team Cymru; falls back to
  ipinfo.io (rate-limited) if blocked.
- The hosting-provider keyword list is a heuristic; adjust it for your needs.
- If you are behind a VPN/proxy, the echo services report the VPN egress IP.
- Subnet and gateway validation is configuration-only; it cannot confirm that
   the supplied gateway is live or reachable. It currently supports IPv4 only.
