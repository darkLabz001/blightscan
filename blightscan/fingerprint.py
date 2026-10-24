"""HTTP(S) technology fingerprinting.

Fetches headers + HTML and infers: server, frameworks/CMS, security headers,
and generator meta tags. Passive-ish (one HTTP GET), still only touches the
target host, so run against authorized targets.
"""
from __future__ import annotations

import re
from typing import Dict, List

import requests

from . import utils

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

# Simple header/body signatures -> technology.
_HEADER_SIGS = {
    "x-powered-by": "x-powered-by",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
    "x-wix-request-id": "Wix",
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-vercel-id": "Vercel",
    "x-github-request-id": "GitHub Pages",
    "fastly-debug-digest": "Fastly",
}

_BODY_SIGS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"/sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla", re.I), "Joomla"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"data-reactroot|react", re.I), "React"),
    (re.compile(r"ng-version", re.I), "Angular"),
    (re.compile(r"__NUXT__", re.I), "Nuxt.js"),
    (re.compile(r"csrf-token", re.I), "Rails/Laravel (CSRF token)"),
]

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _fetch(url: str, timeout: float = 12.0) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; blightscan/1.0)"},
            verify=True,
        )
    except requests.exceptions.SSLError:
        utils.vlog(f"SSL error on {url}, retrying without verify")
        try:
            return requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "blightscan/1.0"}, verify=False)
        except requests.RequestException as exc:
            utils.vlog(f"fetch failed {url}: {exc}")
            return None
    except requests.RequestException as exc:
        utils.vlog(f"fetch failed {url}: {exc}")
        return None


def fingerprint_url(url: str) -> Dict:
    resp = _fetch(url)
    if resp is None:
        return {"url": url, "error": "unreachable"}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text or ""
    technologies: List[str] = []

    # header-based signatures
    for hk, label in _HEADER_SIGS.items():
        if hk in headers:
            val = headers[hk]
            technologies.append(f"{label}: {val}" if label in
                                ("x-powered-by", "generator") else label)

    # body-based signatures
    for rx, label in _BODY_SIGS:
        if rx.search(body):
            technologies.append(label)

    gen = _GENERATOR_RE.search(body)
    title = _TITLE_RE.search(body)

    present_sec = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing_sec = [h for h in SECURITY_HEADERS if h not in headers]

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "title": title.group(1).strip()[:120] if title else None,
        "generator_meta": gen.group(1).strip() if gen else None,
        "technologies": sorted(set(technologies)),
        "security_headers_present": present_sec,
        "security_headers_missing": missing_sec,
        "all_headers": dict(headers),
    }


def fingerprint(domain: str) -> Dict:
    """Try HTTPS first, then HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        result = fingerprint_url(url)
        if "error" not in result:
            return result
    return {"domain": domain, "error": "No HTTP/HTTPS response"}


def print_fingerprint(result: Dict) -> None:
    utils.header("Technology fingerprint")
    if "error" in result:
        utils.log(utils.dim(f"  {result['error']}"))
        return
    utils.log(f"  URL:        {result.get('final_url')}")
    utils.log(f"  Status:     {result.get('status_code')}")
    if result.get("title"):
        utils.log(f"  Title:      {result['title']}")
    if result.get("server"):
        utils.log(f"  Server:     {result['server']}")
    if result.get("powered_by"):
        utils.log(f"  X-Powered:  {result['powered_by']}")
    if result.get("generator_meta"):
        utils.log(f"  Generator:  {result['generator_meta']}")
    if result.get("technologies"):
        utils.log(utils.bold("  Detected tech:"))
        for t in result["technologies"]:
            utils.log(f"    - {t}")
    present = result.get("security_headers_present", {})
    missing = result.get("security_headers_missing", [])
    utils.log(utils.bold("  Security headers:"))
    for h in present:
        utils.log(f"    {utils.green('+')} {h}")
    for h in missing:
        utils.log(f"    {utils.red('-')} {h} {utils.dim('(missing)')}")
