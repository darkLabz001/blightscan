# blightscan

Modular OSINT / reconnaissance CLI and DarksecLabz synthwave TUI for targets you are authorized to test.

> ## ⚠️ AUTHORIZED USE ONLY — READ THIS FIRST
>
> Use this tool **only** against systems you own or have **explicit written permission** to test. Passive modules (DNS, crt.sh, WHOIS/RDAP, HTTP fingerprinting, email scraping) query public records and the target's own public pages.
>
> **Port scan (`--ports`) is active.** It opens real TCP connections to the target. On the CLI it runs only when you pass `--ports`, and the tool warns that the target must be authorized. In the TUI it is off by default and stays off unless you retype the target exactly and confirm written authorization (the prompt defaults to **no**).
>
> **Company mode is active.** It queries third-party discovery services, then pivots into the domain workflow. The TUI aborts company mode unless you retype the target exactly and confirm written authorization (default **no**).
>
> Unauthorized scanning or reconnaissance is illegal in many jurisdictions. **You are solely responsible for how you use this.**

## Install

Python 3.9+, from this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional WHOIS fallback on Debian/Ubuntu: `sudo apt install whois`.

## Usage

Bare `blightscan` opens the interactive DarksecLabz TUI. Pass a target to run the CLI (`python -m blightscan` and `./blightscan.py` do the same).

```bash
blightscan                              # interactive TUI
blightscan example.com -o report.json   # passive recon
blightscan example.com --ports          # ACTIVE TCP scan — authorized targets only
python -m blightscan example.com --json-only
```

```
target                  domain, IP, CIDR, or company name (omit for the TUI)
-t, --type              auto | domain | ip | cidr | company
-o, --output FILE       write a JSON report
--json-only             JSON on stdout, no console summary
--modules LIST          passive subset, e.g. dns,whois (default: all)
--no-bruteforce         crt.sh only; skip subdomain wordlist DNS
--person "First Last"   email pattern guesses
--ports                 ACTIVE TCP connect scan — authorized targets only
--workers N             concurrency (default 100)
-v, --verbose
```

## Features

- **DNS** — A, AAAA, MX, NS, TXT, CNAME, SOA
- **Subdomains** — Certificate Transparency (crt.sh) plus concurrent wordlist resolution
- **WHOIS / RDAP** — rdap.org, then python-whois, then the system `whois` binary (domains and IPs)
- **HTTP fingerprint** — server, framework/CMS hints, security headers, `<meta generator>`
- **Emails** — addresses on the homepage and common contact pages; optional name patterns
- **Company** — best-effort primary domain, then the domain workflow (active; TUI requires exact-target confirmation)
- **CIDR** — expand the range and reverse-DNS each host; port scan only with `--ports` on an authorized range
- **Ports** — concurrent TCP connect scan of ~100 common ports, with banners (**active**, `--ports` only)
- **Reports** — colored console summary plus JSON; a failed module is stored under `error` and the run continues

## Demo

No GIF or screenshot is in this repo. Run the TUI:

```bash
blightscan
```

It is a DarksecLabz synthwave terminal: hot pink prompts, cyan status, and purple borders on a dark background. A rounded panel shows **DARKSECLABZ** and the blightscan version, with the authorized-use notice directly under the banner. Passive modules are a checkbox list (toggle by number, `a` all, `n` none, Enter to continue). Before a port scan or company-mode discovery, the UI draws a warning bar, asks you to type the target exactly, and requires yes to "I am authorized to actively test this target." The default is no; a mismatch or a no skips that active step.

**Alt text** for a future GIF: "DarksecLabz synthwave TUI for blightscan: purple panel, cyan passive-module checks, and an active-scan confirmation that requires retyping the target before any TCP connections."

## Notes

- `root_domain()` uses a small public-suffix heuristic; unusual multi-part TLDs can split imperfectly.
- Company discovery uses no paid APIs. Confirm the primary domain before you trust the pivot.
- crt.sh and search endpoints may rate-limit; rerun or lower `--workers`.
- The subdomain wordlist is intentionally small. Extend `DEFAULT_WORDLIST` in `blightscan/subdomains.py` for a deeper pass.
