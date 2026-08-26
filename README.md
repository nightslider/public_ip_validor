# Public IP Validator

A zero-dependency Python CLI that checks whether an IP address is a genuine,
ISP-assigned **public** IP address.

## What it checks

1. **What the Internet sees** — queries several "what is my IP" echo services
   (ipify, ifconfig.me, icanhazip, ident.me, ipinfo.io, AWS checkip) in parallel.
2. **Not private / CGNAT** — rejects RFC 1918 private ranges, the RFC 6598
   CGNAT range (`100.64.0.0/10`), loopback, link-local, multicast, reserved
   and documentation ranges.
3. **ASN ownership** — looks up the announcing ASN via Team Cymru whois
   (ipinfo.io fallback) and fails known cloud/hosting/CDN networks
   (Amazon/AWS, DigitalOcean, Microsoft, Google, Hetzner, OVH, ...).
   Tune the list by editing `HOSTING_ASN_KEYWORDS` in the script.
4. **Routability** — must be global unicast per IANA *and* have a visible
   BGP announcement.
5. **Reverse DNS** — PTR lookup with forward confirmation (FCrDNS), plus a
   heuristic on whether the PTR looks like residential/dynamic ISP space.
6. **Consistency** — all reachable providers must agree on the same public IP;
   a mismatch with the IP you typed is flagged.

## Requirements

Python 3.8+. Standard library only — nothing to install.

## Usage

```bash
# Type an IP interactively (press Enter with no input to auto-detect your own)
python3 public_ip_validator.py

# Validate a specific public IP
python3 public_ip_validator.py 203.0.113.7

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
- A missing PTR record does **not** mean an IP isn't ISP-assigned — many
  residential ISPs don't publish PTRs (hence WARN, not FAIL).
- The hosting-provider keyword list is a heuristic; adjust it for your needs.
- If you are behind a VPN/proxy, the echo services report the VPN egress IP.
