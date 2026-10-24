# blightscan — modular OSINT / reconnaissance tool

A clean, modular reconnaissance toolkit for **authorized** security testing and
OSINT. It takes a **domain**, **IP address**, **CIDR range**, or **company
name** and gathers deep public information, producing both readable console
output and a structured JSON report.

> ## ⚠️ AUTHORIZED USE ONLY — READ THIS FIRST
> Use this tool **only** against systems you own or have **explicit written
> permission** to test. Passive modules (DNS, crt.sh, WHOIS/RDAP, HTTP
> fingerprinting, email scraping) query public records and the target's own
> public web pages. The **port scanner (`--ports`) is active**: it opens real
> TCP connections to the target and must only be pointed at hosts you are
> authorized to scan. Unauthorized scanning/recon is illegal in many
> jurisdictions. **You are solely responsible for how you use this.**

## Features / modules

| Module | File | What it does |
| --- | --- | --- |
| DNS enumeration | `blightscan/dns.py` | Resolves A, AAAA, MX, NS, TXT, CNAME, SOA via dnspython. |
| Subdomain enum | `blightscan/subdomains.py` | Certificate Transparency (crt.sh) **plus** concurrent wordlist brute-force resolution. |
| WHOIS / RDAP | `blightscan/whois_lookup.py` | RDAP (rdap.org, structured) first, then python-whois, then the system `whois` CLI. Works for domains and IPs. |
| Port scan | `blightscan/ports.py` | **Active** concurrent TCP connect scan of ~100 common ports with banner grabbing. Gated behind `--ports`. |
| Fingerprint | `blightscan/fingerprint.py` | Fetches HTTP(S) headers + HTML: server, framework/CMS hints, security headers, `<meta generator>`. |
| Emails/contacts | `blightscan/emails.py` | Scrapes homepage + common contact pages for emails; generates likely address patterns from a name. |
| Company mode | `blightscan/company.py` | Discovers likely primary domain(s) from a company name (DuckDuckGo HTML + TLD guessing), then pivots into the domain workflow. |
| IP range mode | `blightscan/iprange.py` | Expands a CIDR, reverse-DNS each host, optional port scan. |
| CLI / orchestration | `blightscan/cli.py` | Argument parsing, dispatch, console + JSON reporting. |
| Shared helpers | `blightscan/utils.py` | Target classification, validation, colored logging. |

## Install

Requires Python 3.9+. Use a virtual environment:

```bash
cd blightscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

(Optional) install as a command so `blightscan` is on your PATH:

```bash
pip install -e .
```

The system `whois` CLI is an optional fallback; on Debian/Ubuntu: `sudo apt install whois`.

## Usage

Run via the module, the launcher script, or (if installed) the `blightscan` command:

```bash
python -m blightscan <target> [options]
# or
./blightscan.py <target> [options]
# or (after pip install -e .)
blightscan <target> [options]
```

### Options

```
positional:
  target                 domain, IP, CIDR range, or company name

options:
  -t, --type {auto,domain,ip,cidr,company}   force target type (default auto)
  -o, --output FILE      write JSON report to FILE
  --json-only            suppress console output; print JSON to stdout
  -v, --verbose          verbose debug logging (stderr)
  --ports                ACTIVE TCP port scan — authorized targets only
  --no-bruteforce        skip subdomain wordlist brute force (crt.sh only)
  --person "First Last"  generate email pattern guesses for this person
  --workers N            thread pool size (default 100)
  --version              show version
```

### Examples

```bash
# Passive recon of a domain, save JSON
python -m blightscan example.com -o example-report.json

# Domain recon incl. active port scan (authorized target only)
python -m blightscan example.com --ports -o report.json

# crt.sh only, no brute force, verbose
python -m blightscan example.com --no-bruteforce -v

# Company name -> discover primary domain -> full workflow
python -m blightscan "Acme Corporation" -o acme.json

# IP range: reverse DNS across a CIDR (add --ports to scan)
python -m blightscan 192.0.2.0/24
python -m blightscan 192.0.2.0/24 --ports

# Single IP WHOIS/RDAP + reverse DNS + ports
python -m blightscan 198.51.100.10 --ports

# Email harvesting with pattern guessing
python -m blightscan example.com --person "Jane Doe"

# JSON piped to another tool
python -m blightscan example.com --json-only | jq '.subdomains.all'
```

## Output

- **Console:** sectioned, colored summary (auto-disabled when not a TTY).
- **JSON:** complete structured report via `-o FILE`, or to stdout with
  `--json-only`. Every module is resilient — a failure in one module is caught,
  recorded in the report under an `error` key, and the run continues.

## Notes & limitations

- `root_domain()` uses a small heuristic public-suffix list; exotic multi-part
  TLDs may be split imperfectly.
- Company discovery is best-effort (no paid APIs); confirm the primary domain
  before relying on the pivot.
- crt.sh and DuckDuckGo may rate-limit; rerun or lower `--workers` if so.
- The wordlist is intentionally small for speed; extend `DEFAULT_WORDLIST` in
  `blightscan/subdomains.py` for deeper brute force.

## Interactive mode (TUI)

Running `blightscan` (or `python -m blightscan`) with **no target** launches an
interactive, prompt-driven terminal UI:

```
python -m blightscan
```

It walks you through:

1. Entering a target (domain / IP / CIDR / company) and confirming the
   detected type.
2. Toggling which **passive** modules to run (all enabled by default).
3. Optional subdomain brute force and email person-name hint.
4. **Active recon gating** — port scans (`--ports`) and company-mode
   discovery hit the target/third parties directly, so they are disabled by
   default and require an explicit confirmation (you must retype the exact
   target and affirm you are authorized). Only run these against systems you
   own or are permitted to test.
5. Optionally saving a JSON report.

All existing command-line flags still work exactly as before, e.g.:

```
python -m blightscan example.com -o report.json          # passive, non-interactive
python -m blightscan example.com --modules dns,whois     # pick passive modules
python -m blightscan example.com --ports                 # active scan (authorized only)
```

Installing with `pip install -e .` provides a `blightscan` console command (defined
in `pyproject.toml`), so a one-word launch opens the TUI.
