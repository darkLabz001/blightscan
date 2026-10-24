"""Company mode: discover likely primary domains for a company name.

Uses free, keyless public sources where possible:
  * DuckDuckGo HTML endpoint (no API key) to find candidate sites.
  * A couple of common-TLD guesses derived from the slugified name, validated
    by a quick DNS resolution.

This is best-effort discovery; the operator should confirm the primary domain
before pivoting into the full domain workflow.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set
from urllib.parse import urlparse

import requests

from . import utils

_SKIP_HOSTS = {
    "wikipedia.org", "linkedin.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "youtube.com", "crunchbase.com", "bloomberg.com",
    "duckduckgo.com", "google.com", "yelp.com", "glassdoor.com",
    "indeed.com", "github.com", "medium.com", "reddit.com",
}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _resolves(domain: str, timeout: float = 3.0) -> bool:
    import dns.resolver

    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    for rtype in ("A", "AAAA"):
        try:
            if r.resolve(domain, rtype):
                return True
        except Exception:
            continue
    return False


def ddg_search(query: str, timeout: float = 12.0) -> List[str]:
    """Scrape DuckDuckGo's HTML results for candidate hostnames."""
    hosts: List[str] = []
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; blightscan/1.0)"},
        )
        resp.raise_for_status()
        # result links look like uddg=<encoded url> or direct hrefs
        for m in re.finditer(r'href="(https?://[^"]+)"', resp.text):
            url = m.group(1)
            host = urlparse(url).netloc.lower().lstrip("www.")
            if host and "duckduckgo" not in host:
                hosts.append(host)
    except requests.RequestException as exc:
        utils.vlog(f"DDG search failed: {exc}")
    # de-dup, preserve order
    seen: Set[str] = set()
    ordered = []
    for h in hosts:
        base = utils.root_domain(h)
        if base not in seen:
            seen.add(base)
            ordered.append(base)
    return ordered


def guess_tld_domains(name: str) -> List[str]:
    slug = _slug(name)
    if not slug:
        return []
    tlds = ["com", "net", "org", "io", "co", "ai", "app"]
    candidates = [f"{slug}.{t}" for t in tlds]
    resolved: List[str] = []
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        futures = {pool.submit(_resolves, c): c for c in candidates}
        for fut in as_completed(futures):
            c = futures[fut]
            try:
                if fut.result():
                    resolved.append(c)
            except Exception:
                continue
    return sorted(resolved)


def discover_domains(company: str) -> Dict:
    utils.vlog(f"company discovery for: {company}")
    ddg = ddg_search(f"{company} official site")
    filtered = [h for h in ddg if not any(h.endswith(s) for s in _SKIP_HOSTS)]
    guessed = guess_tld_domains(company)

    # rank: prefer a candidate present in both lists, else first DDG hit
    candidates = []
    for h in filtered + guessed:
        if h not in candidates:
            candidates.append(h)

    primary = None
    for g in guessed:
        if g in filtered:
            primary = g
            break
    if not primary and filtered:
        primary = filtered[0]
    if not primary and guessed:
        primary = guessed[0]

    return {
        "company": company,
        "search_results": filtered[:15],
        "guessed_domains": guessed,
        "candidates": candidates[:15],
        "primary_domain": primary,
    }


def print_company(result: Dict) -> None:
    utils.header(f"Company discovery: {result.get('company')}")
    if result.get("primary_domain"):
        utils.log(f"  Best guess primary domain: "
                  f"{utils.green(result['primary_domain'])}")
    if result.get("guessed_domains"):
        utils.log(utils.bold("  Resolved TLD guesses:"))
        for d in result["guessed_domains"]:
            utils.log(f"    {d}")
    if result.get("search_results"):
        utils.log(utils.bold("  Search-derived candidates:"))
        for d in result["search_results"]:
            utils.log(f"    {d}")
    if not result.get("primary_domain"):
        utils.log(utils.dim("  Could not determine a primary domain."))
