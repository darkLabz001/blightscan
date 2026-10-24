"""Concurrent TCP connect port scanner with light banner grabbing.

ACTIVE module: it opens real TCP connections to the target, so it is gated
behind an explicit flag in the CLI and prints an authorized-use warning.
Only scan hosts you own or are explicitly authorized to test.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from . import utils

# ~100 most common TCP service ports.
TOP_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999,
    10000, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

_COMMON_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "ms-sql",
    1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def _grab_banner(sock: socket.socket, port: int, host: str) -> str:
    """Best-effort banner. For HTTP(S) send a HEAD; otherwise read what comes."""
    try:
        sock.settimeout(2.0)
        if port in (80, 8080, 8000, 8008, 8888, 3000, 5000):
            sock.sendall(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            )
        banner = sock.recv(256)
        return banner.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _scan_port(host: str, port: int, timeout: float = 1.5) -> Dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock, port, host)
            return {
                "port": port,
                "service": _COMMON_NAMES.get(port, "unknown"),
                "banner": banner,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(host: str, ports: List[int] | None = None, workers: int = 100,
         timeout: float = 1.5) -> List[Dict]:
    ports = ports or TOP_PORTS
    open_ports: List[Dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
                utils.vlog(f"open: {host}:{res['port']} ({res['service']})")
    open_ports.sort(key=lambda d: d["port"])
    return open_ports


def print_ports(host: str, open_ports: List[Dict]) -> None:
    utils.header(f"Open ports: {host}")
    if not open_ports:
        utils.log(utils.dim("  (no open ports found in scanned range)"))
        return
    for p in open_ports:
        line = f"  {utils.green(str(p['port']))}/tcp  {p['service']}"
        if p.get("banner"):
            line += utils.dim(f"  | {p['banner'][:80]}")
        utils.log(line)
