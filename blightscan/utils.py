"""Shared helpers: logging, colors, normalization."""
from __future__ import annotations

import re
import sys

# ---- minimal ANSI color support (no external deps) -------------------------
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str:
    return _c("1", t)


def green(t: str) -> str:
    return _c("32", t)


def yellow(t: str) -> str:
    return _c("33", t)


def red(t: str) -> str:
    return _c("31", t)


def cyan(t: str) -> str:
    return _c("36", t)


def dim(t: str) -> str:
    return _c("2", t)


# ---- logging ---------------------------------------------------------------
VERBOSE = False


def set_verbose(v: bool) -> None:
    global VERBOSE
    VERBOSE = v


def log(msg: str) -> None:
    """Informational message to stderr (keeps stdout clean for --json-only)."""
    print(msg, file=sys.stderr)


def vlog(msg: str) -> None:
    if VERBOSE:
        print(dim(f"[debug] {msg}"), file=sys.stderr)


def warn(msg: str) -> None:
    print(yellow(f"[!] {msg}"), file=sys.stderr)


def header(title: str) -> None:
    bar = "=" * max(8, len(title) + 4)
    log("")
    log(cyan(bar))
    log(cyan(f"  {title}"))
    log(cyan(bar))


# ---- validation / normalization -------------------------------------------
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def is_domain(s: str) -> bool:
    return bool(_DOMAIN_RE.match(s.strip().rstrip(".")))


def is_ip(s: str) -> bool:
    if not _IPV4_RE.match(s.strip()):
        return False
    return all(0 <= int(o) <= 255 for o in s.strip().split("."))


def is_cidr(s: str) -> bool:
    if not _CIDR_RE.match(s.strip()):
        return False
    ip, bits = s.strip().split("/")
    return is_ip(ip) and 0 <= int(bits) <= 32


def classify_target(s: str) -> str:
    """Return one of: 'cidr', 'ip', 'domain', 'company'."""
    s = s.strip()
    if is_cidr(s):
        return "cidr"
    if is_ip(s):
        return "ip"
    if is_domain(s):
        return "domain"
    return "company"


def root_domain(host: str) -> str:
    """Very small heuristic for the registrable domain (last two labels).

    Good enough for the common single-suffix TLDs we deal with here; multi-part
    public suffixes (co.uk, com.au...) are only partially handled.
    """
    host = host.strip().rstrip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # crude multi-part suffix handling
    two = ".".join(parts[-2:])
    multi_suffixes = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.nz",
                      "co.jp", "com.br", "co.in", "co.za"}
    if two in multi_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return two


# ---- DarksecLabz synthwave truecolor theme (24-bit ANSI, stdlib only) -------
# Palette: hot pink, neon cyan, purple, muted void-grey.
THEME = {
    "pink":   (255, 46, 154),   # #ff2e9a  hot pink  (accent / selection)
    "cyan":   (0, 245, 255),    # #00f5ff  neon cyan (enabled / info)
    "purple": (157, 78, 221),   # #9d4edd  purple    (borders / frame)
    "muted":  (118, 118, 150),  # void-grey disabled / hints
    "text":   (224, 224, 240),  # near-white body text
    "warn":   (255, 196, 61),   # amber warnings
    "danger": (255, 64, 96),    # red active-recon warnings
}


def _rgb(rgb, text: str, bold: bool = False) -> str:
    if not _USE_COLOR:
        return text
    r, g, b = rgb
    pre = "1;" if bold else ""
    return f"\033[{pre}38;2;{r};{g};{b}m{text}\033[0m"


def pink(t: str, bold: bool = False) -> str:
    return _rgb(THEME["pink"], t, bold)


def neon(t: str, bold: bool = False) -> str:
    return _rgb(THEME["cyan"], t, bold)


def violet(t: str, bold: bool = False) -> str:
    return _rgb(THEME["purple"], t, bold)


def muted(t: str, bold: bool = False) -> str:
    return _rgb(THEME["muted"], t, bold)


def body(t: str, bold: bool = False) -> str:
    return _rgb(THEME["text"], t, bold)


def amber(t: str, bold: bool = False) -> str:
    return _rgb(THEME["warn"], t, bold)


def danger(t: str, bold: bool = False) -> str:
    return _rgb(THEME["danger"], t, bold)


def supports_color() -> bool:
    return _USE_COLOR
