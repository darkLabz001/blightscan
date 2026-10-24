"""Subdomain enumeration.

Two sources:
  1. Certificate Transparency logs via crt.sh (passive, no traffic to target).
  2. A small built-in wordlist brute-force with concurrent DNS resolution.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set

import requests

from . import utils

# A compact, high-signal wordlist. Kept small on purpose so the default run is
# fast; extend via --wordlist if desired.
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "mx", "mx1", "mx2", "vpn", "remote", "portal", "admin", "api",
    "dev", "staging", "stage", "test", "qa", "uat", "beta", "demo",
    "app", "apps", "mobile", "m", "shop", "store", "blog", "news", "cdn",
    "static", "assets", "img", "images", "media", "docs", "help", "support",
    "status", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "dashboard", "panel", "cpanel", "secure", "login", "sso", "auth",
    "internal", "intranet", "proxy", "gateway", "gw", "fw", "router",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "backup", "monitor", "grafana", "kibana", "prometheus", "metrics",
    "cloud", "aws", "azure", "gcp", "k8s", "kube", "docker",
    "autodiscover", "owa", "exchange", "lync", "mail2", "email",
    "ns", "ns3", "server", "host", "web", "web1", "web2", "old", "new",
]


def from_crtsh(domain: str, timeout: float = 20.0) -> Set[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    found: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "blightscan/1.0"})
        resp.raise_for_status()
        data = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lstrip("*.").lower()
                if (name == domain or name.endswith("." + domain)) and utils.is_domain(name):
                    found.add(name)
        utils.vlog(f"crt.sh: {len(found)} unique name(s)")
    except requests.exceptions.JSONDecodeError:
        utils.warn("crt.sh returned non-JSON (rate limited or empty).")
    except requests.RequestException as exc:
        utils.warn(f"crt.sh query failed: {exc}")
    return found


def _resolve(host: str, timeout: float = 3.0):
    import dns.resolver

    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    ips: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            for ans in r.resolve(host, rtype):
                ips.append(ans.to_text())
        except Exception:
            continue
    return host, ips



def _detect_wildcard(domain: str, timeout: float = 3.0) -> set:
    """Return the set of IPs a guaranteed-nonexistent host resolves to.

    If non-empty, the zone has wildcard DNS and brute-force A/AAAA results that
    match these IPs are noise and should be discarded.
    """
    import uuid
    probe = f"{uuid.uuid4().hex[:16]}-nxdomain-probe.{domain}"
    _, ips = _resolve(probe, timeout)
    return set(ips)


def brute_force(domain: str, wordlist: List[str], workers: int = 50,
                timeout: float = 3.0) -> Dict[str, List[str]]:
    """Resolve <word>.<domain> concurrently; return only those that resolve."""
    resolved: Dict[str, List[str]] = {}
    wildcard_ips = _detect_wildcard(domain, timeout)
    if wildcard_ips:
        utils.warn(
            f"Wildcard DNS detected for {domain} "
            f"({', '.join(sorted(wildcard_ips))}); "
            "brute-force hits matching it are discarded as noise."
        )
    hosts = [f"{w}.{domain}" for w in wordlist]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve, h, timeout): h for h in hosts}
        for fut in as_completed(futures):
            try:
                host, ips = fut.result()
                real = sorted(set(ips) - wildcard_ips)
                if real:
                    resolved[host] = real
            except Exception as exc:  # pragma: no cover
                utils.vlog(f"resolve error: {exc}")
    utils.vlog(f"brute-force: {len(resolved)} resolved of {len(hosts)} tried")
    return resolved


def enumerate_subdomains(domain: str, wordlist: List[str] | None = None,
                         do_bruteforce: bool = True,
                         workers: int = 50) -> Dict[str, object]:
    wordlist = wordlist or DEFAULT_WORDLIST
    crt = from_crtsh(domain)
    brute: Dict[str, List[str]] = {}
    if do_bruteforce:
        brute = brute_force(domain, wordlist, workers=workers)

    all_names = sorted(crt | set(brute.keys()))
    return {
        "from_crtsh": sorted(crt),
        "from_bruteforce": brute,
        "all": all_names,
        "count": len(all_names),
    }


def print_subdomains(result: Dict[str, object]) -> None:
    utils.header("Subdomains")
    names = result.get("all", [])  # type: ignore[assignment]
    if not names:
        utils.log(utils.dim("  (none discovered)"))
        return
    brute = result.get("from_bruteforce", {})  # type: ignore[assignment]
    for name in names:
        ips = brute.get(name) if isinstance(brute, dict) else None
        if ips:
            utils.log(f"  {utils.green(name)}  -> {', '.join(ips)}")
        else:
            utils.log(f"  {utils.green(name)}")
    utils.log(utils.dim(f"  total: {result.get('count', 0)}"))
