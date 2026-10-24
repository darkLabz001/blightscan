"""IP range (CIDR) mode: expand network, reverse-DNS each host, optional scan."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from . import ports as ports_mod
from . import utils


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def expand(cidr: str, max_hosts: int = 1024) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 2 else \
        [str(net.network_address)]
    if len(hosts) > max_hosts:
        utils.warn(f"CIDR has {len(hosts)} hosts; capping at {max_hosts}.")
        hosts = hosts[:max_hosts]
    return hosts


def scan_range(cidr: str, do_ports: bool = False, workers: int = 100,
               max_hosts: int = 1024) -> Dict:
    hosts = expand(cidr, max_hosts=max_hosts)
    results: Dict[str, Dict] = {}

    # reverse DNS concurrently
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_reverse_dns, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            ptr = fut.result()
            results[ip] = {"ptr": ptr}

    if do_ports:
        for ip in hosts:
            open_ports = ports_mod.scan(ip, workers=workers)
            if open_ports:
                results[ip]["open_ports"] = open_ports

    return {
        "cidr": cidr,
        "host_count": len(hosts),
        "hosts": results,
        "port_scanned": do_ports,
    }


def print_range(result: Dict) -> None:
    utils.header(f"IP range: {result.get('cidr')}")
    hosts = result.get("hosts", {})
    live = {ip: d for ip, d in hosts.items()
            if d.get("ptr") or d.get("open_ports")}
    utils.log(utils.dim(f"  {len(hosts)} addresses expanded; "
                        f"{len(live)} with PTR or open ports"))
    for ip, d in sorted(live.items(), key=lambda kv: tuple(
            int(x) for x in kv[0].split("."))):
        line = f"  {utils.green(ip)}"
        if d.get("ptr"):
            line += f"  ({d['ptr']})"
        utils.log(line)
        for p in d.get("open_ports", []):
            utils.log(f"      {p['port']}/tcp {p['service']}")
