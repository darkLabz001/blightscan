"""WHOIS / RDAP lookups for domains and IPs.

Strategy:
  * RDAP first (structured JSON, reliable) via rdap.org bootstrap.
  * Fall back to the python-whois library.
  * Fall back to the system `whois` CLI if present.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Dict, Optional

import requests

from . import utils


def rdap_lookup(target: str, is_ip: bool = False,
                timeout: float = 15.0) -> Optional[Dict]:
    """Query rdap.org, which redirects to the authoritative RDAP server."""
    kind = "ip" if is_ip else "domain"
    url = f"https://rdap.org/{kind}/{target}"
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": "blightscan/1.0",
                                     "Accept": "application/rdap+json"})
        if resp.status_code == 404:
            utils.vlog(f"RDAP: no record for {target}")
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        utils.vlog(f"RDAP lookup failed: {exc}")
        return None


def _parse_rdap(data: Dict) -> Dict:
    """Pull a few commonly useful fields out of an RDAP response."""
    out: Dict[str, object] = {}
    if not data:
        return out
    out["handle"] = data.get("handle")
    out["ldhName"] = data.get("ldhName")
    out["name"] = data.get("name")
    # events (registration, expiration, last changed)
    events = {}
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction")
        if action:
            events[action] = ev.get("eventDate")
    if events:
        out["events"] = events
    out["status"] = data.get("status")
    # registrar / entities
    entities = []
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", [])
        name = None
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    name = item[3]
                    break
        entities.append({"roles": roles, "name": name,
                         "handle": ent.get("handle")})
    if entities:
        out["entities"] = entities
    # nameservers
    ns = [n.get("ldhName") for n in data.get("nameservers", []) or []
          if n.get("ldhName")]
    if ns:
        out["nameservers"] = ns
    # IP-specific
    for k in ("startAddress", "endAddress", "country", "type", "ipVersion"):
        if k in data:
            out[k] = data[k]
    return out


def python_whois(target: str) -> Optional[Dict]:
    try:
        import whois  # python-whois
    except ImportError:
        return None
    try:
        data = whois.whois(target)
        # whois objects behave like dicts; coerce dates to strings
        result = {}
        for k, v in dict(data).items():
            if v is None:
                continue
            if isinstance(v, (list, tuple)):
                result[k] = [str(x) for x in v]
            else:
                result[k] = str(v)
        return result or None
    except Exception as exc:
        utils.vlog(f"python-whois failed: {exc}")
        return None


def cli_whois(target: str, timeout: float = 15.0) -> Optional[str]:
    if not shutil.which("whois"):
        return None
    try:
        out = subprocess.run(["whois", target], capture_output=True,
                             text=True, timeout=timeout)
        return out.stdout.strip() or None
    except Exception as exc:
        utils.vlog(f"whois CLI failed: {exc}")
        return None


def lookup(target: str, is_ip: bool = False) -> Dict:
    """Return a dict with rdap (parsed), python_whois, and raw_whois keys."""
    result: Dict[str, object] = {"target": target, "is_ip": is_ip}

    rdap_raw = rdap_lookup(target, is_ip=is_ip)
    if rdap_raw:
        result["rdap"] = _parse_rdap(rdap_raw)

    pw = python_whois(target)
    if pw:
        result["python_whois"] = pw

    if "rdap" not in result and "python_whois" not in result:
        raw = cli_whois(target)
        if raw:
            result["raw_whois"] = raw

    if len(result) == 2:  # only target + is_ip
        result["error"] = "No WHOIS/RDAP data available."
    return result


def print_whois(result: Dict) -> None:
    utils.header("WHOIS / RDAP")
    rdap = result.get("rdap")
    if isinstance(rdap, dict):
        utils.log(utils.bold("  RDAP:"))
        for k, v in rdap.items():
            utils.log(f"    {k}: {v}")
    pw = result.get("python_whois")
    if isinstance(pw, dict):
        utils.log(utils.bold("  python-whois (selected):"))
        for k in ("domain_name", "registrar", "creation_date",
                  "expiration_date", "updated_date", "name_servers",
                  "org", "country", "emails"):
            if k in pw:
                utils.log(f"    {k}: {pw[k]}")
    if "raw_whois" in result:
        utils.log(utils.bold("  whois CLI output:"))
        for line in str(result["raw_whois"]).splitlines()[:40]:
            utils.log(f"    {line}")
    if "error" in result:
        utils.log(utils.dim(f"  {result['error']}"))
