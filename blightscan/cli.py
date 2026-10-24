"""blightscan CLI entrypoint: orchestrates modules and emits console + JSON output."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import socket
import sys
from typing import Dict

from . import (__version__, company, dns as dns_mod, emails, fingerprint,
               iprange, ports as ports_mod, subdomains, utils, whois_lookup)

AUTH_NOTICE = (
    "AUTHORIZED USE ONLY: Run this tool only against systems you own or have\n"
    "explicit written permission to test. Unauthorized scanning or recon may\n"
    "be illegal. You are responsible for how you use it."
)


def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat()


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _enabled(name: str, args) -> bool:
    """Whether a given module should run.

    The TUI (and the optional --modules flag) can restrict the module set. When
    no restriction is set (modules is None), every passive module runs - this
    preserves the original CLI behaviour exactly.
    """
    mods = getattr(args, "modules", None)
    if mods is None:
        return True
    return name in mods


def run_domain(domain: str, args) -> Dict:
    report: Dict[str, object] = {"type": "domain", "target": domain}

    # DNS
    if _enabled("dns", args):
        try:
            dns_res = dns_mod.enumerate_dns(domain)
            report["dns"] = dns_res
            if not args.json_only:
                dns_mod.print_dns(dns_res)
        except Exception as exc:
            utils.warn(f"DNS module failed: {exc}")
            report["dns"] = {"error": str(exc)}

    # Subdomains
    if _enabled("subdomains", args):
        try:
            sub_res = subdomains.enumerate_subdomains(
                domain, do_bruteforce=not args.no_bruteforce)
            report["subdomains"] = sub_res
            if not args.json_only:
                subdomains.print_subdomains(sub_res)
        except Exception as exc:
            utils.warn(f"Subdomain module failed: {exc}")
            report["subdomains"] = {"error": str(exc)}

    # WHOIS
    if _enabled("whois", args):
        try:
            who = whois_lookup.lookup(domain, is_ip=False)
            report["whois"] = who
            if not args.json_only:
                whois_lookup.print_whois(who)
        except Exception as exc:
            utils.warn(f"WHOIS module failed: {exc}")
            report["whois"] = {"error": str(exc)}

    # Fingerprint
    if _enabled("fingerprint", args):
        try:
            fp = fingerprint.fingerprint(domain)
            report["fingerprint"] = fp
            if not args.json_only:
                fingerprint.print_fingerprint(fp)
        except Exception as exc:
            utils.warn(f"Fingerprint module failed: {exc}")
            report["fingerprint"] = {"error": str(exc)}

    # Emails
    if _enabled("emails", args):
        try:
            em = emails.harvest(domain, person_name=args.person)
            report["emails"] = em
            if not args.json_only:
                emails.print_emails(em)
        except Exception as exc:
            utils.warn(f"Email module failed: {exc}")
            report["emails"] = {"error": str(exc)}

    # Ports (active, gated behind --ports)
    if args.ports:
        ip = _resolve_ip(domain)
        if ip:
            try:
                open_ports = ports_mod.scan(ip, workers=args.workers)
                report["ports"] = {"ip": ip, "open_ports": open_ports}
                if not args.json_only:
                    ports_mod.print_ports(f"{domain} ({ip})", open_ports)
            except Exception as exc:
                utils.warn(f"Port scan failed: {exc}")
                report["ports"] = {"error": str(exc)}
        else:
            report["ports"] = {"error": "could not resolve domain to IP"}

    return report


def run_ip(ip: str, args) -> Dict:
    report: Dict[str, object] = {"type": "ip", "target": ip}
    if _enabled("whois", args):
        try:
            who = whois_lookup.lookup(ip, is_ip=True)
            report["whois"] = who
            if not args.json_only:
                whois_lookup.print_whois(who)
        except Exception as exc:
            utils.warn(f"WHOIS failed: {exc}")

    # reverse DNS
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        ptr = None
    report["reverse_dns"] = ptr
    if not args.json_only:
        utils.header("Reverse DNS")
        utils.log(f"  {ip} -> {ptr or utils.dim('(none)')}")

    if args.ports:
        try:
            open_ports = ports_mod.scan(ip, workers=args.workers)
            report["ports"] = {"open_ports": open_ports}
            if not args.json_only:
                ports_mod.print_ports(ip, open_ports)
        except Exception as exc:
            utils.warn(f"Port scan failed: {exc}")
    return report


def run_cidr(cidr: str, args) -> Dict:
    report: Dict[str, object] = {"type": "cidr", "target": cidr}
    try:
        res = iprange.scan_range(cidr, do_ports=args.ports, workers=args.workers)
        report["range"] = res
        if not args.json_only:
            iprange.print_range(res)
    except Exception as exc:
        utils.warn(f"IP range module failed: {exc}")
        report["range"] = {"error": str(exc)}
    return report


def run_company(name: str, args) -> Dict:
    report: Dict[str, object] = {"type": "company", "target": name}
    disc = company.discover_domains(name)
    report["discovery"] = disc
    if not args.json_only:
        company.print_company(disc)

    primary = disc.get("primary_domain")
    if primary:
        utils.log(utils.cyan(f"\n[*] Pivoting into domain workflow for "
                             f"{primary}\n"))
        report["domain_report"] = run_domain(primary, args)
    else:
        utils.warn("No primary domain found; skipping domain pivot.")
    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blightscan",
        description="Modular OSINT / reconnaissance tool for AUTHORIZED testing.",
        epilog=AUTH_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?",
                   help="domain, IP, CIDR range, or company name. "
                        "Omit to launch the interactive TUI.")
    p.add_argument("-t", "--type",
                   choices=["auto", "domain", "ip", "cidr", "company"],
                   default="auto", help="force target type (default: auto)")
    p.add_argument("-o", "--output", help="write JSON report to this file")
    p.add_argument("--json-only", action="store_true",
                   help="suppress pretty console output; only emit JSON")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="verbose debug logging to stderr")
    p.add_argument("--ports", action="store_true",
                   help="ACTIVE TCP port scan (authorized targets only!)")
    p.add_argument("--no-bruteforce", action="store_true",
                   help="skip subdomain wordlist brute force (crt.sh only)")
    p.add_argument("--modules",
                   help="comma-separated passive modules to run (e.g. "
                        "'dns,whois,fingerprint'). Default: all. Use 'none' "
                        "for no passive modules.")
    p.add_argument("--person", help="person name for email pattern guessing")
    p.add_argument("--workers", type=int, default=100,
                   help="thread pool size for concurrent work (default 100)")
    p.add_argument("--version", action="version",
                   version=f"blightscan {__version__}")
    return p


def _parse_modules(args) -> None:
    """Normalize args.modules (comma string) into a set or None (= all)."""
    raw = getattr(args, "modules", None)
    if raw is None:
        args.modules = None
        return
    raw = raw.strip().lower()
    if raw in ("", "all"):
        args.modules = None
    elif raw == "none":
        args.modules = set()
    else:
        args.modules = {m.strip() for m in raw.split(",") if m.strip()}


def main(argv=None) -> int:
    # No arguments at all -> launch the interactive TUI.
    if argv is None and len(sys.argv) <= 1:
        from .tui import run_tui
        return run_tui()

    parser = build_parser()
    args = parser.parse_args(argv)

    # Explicit no-target invocation (e.g. just flags) also goes to the TUI.
    if args.target is None:
        from .tui import run_tui
        return run_tui()

    utils.set_verbose(args.verbose)
    _parse_modules(args)

    target = args.target.strip()
    ttype = args.type if args.type != "auto" else utils.classify_target(target)

    if not args.json_only:
        utils.log(utils.bold(f"blightscan {__version__}"))
        utils.log(utils.dim(AUTH_NOTICE))
        utils.log(utils.dim(f"\nTarget: {target}  (type: {ttype})  "
                            f"started: {_now()}"))
    if args.ports and not args.json_only:
        utils.warn("Active port scanning enabled - authorized targets only.")

    dispatch = {
        "domain": run_domain,
        "ip": run_ip,
        "cidr": run_cidr,
        "company": run_company,
    }

    report = {
        "tool": "blightscan",
        "version": __version__,
        "target": target,
        "type": ttype,
        "started_at": _now(),
    }
    try:
        result = dispatch[ttype](target, args)
        report.update(result)
    except KeyboardInterrupt:
        utils.warn("Interrupted by user.")
        return 130
    report["finished_at"] = _now()

    # JSON output
    json_text = json.dumps(report, indent=2, default=str)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(json_text)
            if not args.json_only:
                utils.log(utils.green(f"\n[+] JSON report written to "
                                      f"{args.output}"))
        except OSError as exc:
            utils.warn(f"Could not write output file: {exc}")
    if args.json_only:
        print(json_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
