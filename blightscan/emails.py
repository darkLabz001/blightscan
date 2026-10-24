"""Email / contact harvesting.

Sources:
  * Scrape the target's homepage + a few common contact pages for emails.
  * Generate likely email patterns from a company/person name + domain.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set

import requests

from . import utils

COMMON_PATHS = [
    "", "contact", "contact-us", "about", "about-us", "team", "support",
    "privacy", "legal", "imprint", "company",
]


def _scrape(url: str, timeout: float = 10.0) -> Set[str]:
    emails: Set[str] = set()
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; blightscan/1.0)"},
            allow_redirects=True, verify=True,
        )
        if resp.status_code == 200 and resp.text:
            for m in utils.EMAIL_RE.findall(resp.text):
                # strip obvious junk / image filenames caught by the regex
                if not m.lower().endswith((".png", ".jpg", ".jpeg", ".gif",
                                          ".svg", ".webp")):
                    emails.add(m.lower())
    except requests.RequestException as exc:
        utils.vlog(f"email scrape failed {url}: {exc}")
    return emails


def scrape_site(domain: str, paths: List[str] | None = None,
                workers: int = 10) -> List[str]:
    paths = paths if paths is not None else COMMON_PATHS
    urls = []
    for scheme in ("https", "http"):
        for p in paths:
            urls.append(f"{scheme}://{domain}/{p}".rstrip("/"))
    found: Set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scrape, u): u for u in urls}
        for fut in as_completed(futures):
            found |= fut.result()
    # keep only emails that look related to the domain OR any email at all
    return sorted(found)


def guess_patterns(name: str, domain: str) -> List[str]:
    """Generate common corporate email formats for a person's name."""
    parts = [p for p in name.lower().replace(".", " ").split() if p]
    if not parts:
        return []
    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    fi = first[0] if first else ""
    li = last[0] if last else ""
    patterns = {first}
    if last:
        patterns.update({
            f"{first}.{last}", f"{first}{last}", f"{fi}{last}",
            f"{fi}.{last}", f"{first}_{last}", f"{first}{li}",
            f"{last}.{first}", f"{last}{fi}", last,
        })
    return [f"{p}@{domain}" for p in sorted(patterns) if p]


def harvest(domain: str, person_name: str | None = None) -> Dict:
    scraped = scrape_site(domain)
    result: Dict[str, object] = {
        "domain": domain,
        "scraped_emails": scraped,
    }
    if person_name:
        result["guessed_patterns"] = guess_patterns(person_name, domain)
    return result


def print_emails(result: Dict) -> None:
    utils.header("Emails / contacts")
    scraped = result.get("scraped_emails", [])  # type: ignore[assignment]
    if scraped:
        utils.log(utils.bold("  Scraped from site:"))
        for e in scraped:
            utils.log(f"    {utils.green(e)}")
    else:
        utils.log(utils.dim("  No emails scraped from public pages."))
    guessed = result.get("guessed_patterns")
    if guessed:
        utils.log(utils.bold("  Guessed patterns (UNVERIFIED):"))
        for e in guessed:  # type: ignore[union-attr]
            utils.log(f"    {utils.yellow(e)}")
