"""DNS enumeration module.

Resolves common record types for a domain using dnspython. Written with
absolute imports so `import dns.resolver` picks up the installed dnspython
package, not this sibling module.
"""
from __future__ import annotations

from typing import Dict, List

from . import utils

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolver(timeout: float = 5.0):
    import dns.resolver  # noqa: WPS433 (deferred import keeps CLI fast to load)

    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _format_rdata(rtype: str, rdata) -> str:
    try:
        if rtype == "MX":
            return f"{rdata.preference} {rdata.exchange.to_text()}"
        if rtype == "SOA":
            return (
                f"mname={rdata.mname} rname={rdata.rname} "
                f"serial={rdata.serial} refresh={rdata.refresh} "
                f"retry={rdata.retry} expire={rdata.expire} minimum={rdata.minimum}"
            )
        return rdata.to_text().strip('"')
    except Exception:  # pragma: no cover - defensive
        return str(rdata)


def enumerate_dns(domain: str, timeout: float = 5.0) -> Dict[str, List[str]]:
    """Return a dict of record type -> list of string values."""
    import dns.resolver

    results: Dict[str, List[str]] = {}
    resolver = _resolver(timeout)
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = sorted({_format_rdata(rtype, r) for r in answers})
            results[rtype] = values
            utils.vlog(f"DNS {rtype}: {len(values)} record(s)")
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            utils.warn(f"DNS: {domain} does not exist (NXDOMAIN)")
            results[rtype] = []
        except dns.resolver.NoNameservers:
            results[rtype] = []
        except Exception as exc:  # timeouts, etc.
            utils.vlog(f"DNS {rtype} error: {exc}")
            results[rtype] = []
    return results


def print_dns(results: Dict[str, List[str]]) -> None:
    utils.header("DNS records")
    for rtype in RECORD_TYPES:
        vals = results.get(rtype, [])
        if not vals:
            continue
        utils.log(utils.bold(f"  {rtype}"))
        for v in vals:
            utils.log(f"    {v}")
    if not any(results.get(t) for t in RECORD_TYPES):
        utils.log(utils.dim("  (no records found)"))
