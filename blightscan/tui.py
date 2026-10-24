"""Interactive terminal UI for the blightscan toolkit.

Dependency-light (stdlib only, no curses / no external deps) prompt-driven menu
so it works across terminals and even when input is piped for testing.

Styled with the DarksecLabz synthwave theme (hot pink / neon cyan / purple on a
void background) using 24-bit ANSI truecolor + box-drawing. Launched when
`blightscan` / `python -m blightscan` runs with no target. Gathers a target, lets the user
pick passive modules (with explicit confirmation after every action), gates
ACTIVE recon behind a strict authorization confirmation, then hands off to the
normal CLI pipeline so all output + JSON logic is reused.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from . import __version__, utils

AUTH_NOTICE = (
    "AUTHORIZED USE ONLY: run only against systems you own or have explicit\n"
    "written permission to test. Unauthorized scanning may be illegal. You are\n"
    "responsible for how you use this tool."
)

# Passive modules available per target type. Order matters for display.
PASSIVE_MODULES = {
    "domain": [
        ("dns", "DNS records (A/AAAA/MX/NS/TXT/...)"),
        ("subdomains", "Subdomain enum (crt.sh + optional brute force)"),
        ("whois", "WHOIS / RDAP registration data"),
        ("fingerprint", "HTTP(S) server fingerprint"),
        ("emails", "Email address harvest"),
    ],
    "ip": [
        ("whois", "WHOIS / RDAP (IP allocation)"),
        # reverse DNS is always done for IPs
    ],
    "cidr": [
        ("range", "CIDR expansion + reverse DNS sweep"),
    ],
    "company": [],  # company mode discovers a domain then pivots
}

# --------------------------------------------------------------------------- #
# presentation helpers (truecolor + box drawing, visible-width aware)
# --------------------------------------------------------------------------- #
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_WIDTH = 66  # outer panel width


def _vis(s: str) -> int:
    """Visible length of a string, ignoring ANSI escape codes."""
    return len(_ANSI_RE.sub("", s))


def _clear() -> None:
    """Clear the screen for an in-place redraw (TTY only; no-op when piped)."""
    if utils.supports_color():
        print("\033[2J\033[3J\033[H", end="")


def _pad(s: str, width: int) -> str:
    return s + " " * max(0, width - _vis(s))


def _panel(lines: List[str], title: str = "", width: int = _WIDTH) -> None:
    """Draw a rounded, purple-bordered panel around pre-colored content lines."""
    inner = width - 4  # space between "│ " and " │"
    b = utils.violet
    print("  " + b("\u256d" + "\u2500" * (width - 2) + "\u256e"))
    if title:
        t = utils.pink(title, bold=True)
        print("  " + b("\u2502 ") + _pad(t, inner) + b(" \u2502"))
        print("  " + b("\u251c" + "\u2500" * (width - 2) + "\u2524"))
    for ln in lines:
        print("  " + b("\u2502 ") + _pad(ln, inner) + b(" \u2502"))
    print("  " + b("\u2570" + "\u2500" * (width - 2) + "\u256f"))


def _banner() -> None:
    _clear()
    logo = [
        utils.pink("\u2593\u2592\u2591 ", bold=True) + utils.neon("D A R K S E C L A B Z", bold=True)
        + utils.pink(" \u2591\u2592\u2593", bold=True),
        utils.body(f"blightscan  ") + utils.violet("v" + __version__)
        + utils.muted("   \u00b7 interactive mode"),
    ]
    _panel(logo)
    for line in AUTH_NOTICE.split("\n"):
        print("   " + utils.muted(line))
    print()


# --------------------------------------------------------------------------- #
# small input helpers (EOF-safe so piped input / headless testing works)
# --------------------------------------------------------------------------- #
def _prompt(label: str) -> str:
    return utils.pink("  \u276f ", bold=True) + utils.body(label)


def _ask(prompt: str, default: Optional[str] = None) -> Optional[str]:
    try:
        raw = input(prompt).strip()
    except EOFError:
        return default
    if not raw and default is not None:
        return default
    return raw


def _ask_yn(prompt: str, default: bool = False) -> bool:
    hint = utils.neon("Y") + utils.muted("/n") if default else utils.muted("y/") + utils.neon("N")
    try:
        raw = input(_prompt(prompt) + utils.muted(" [") + hint + utils.muted("]: ")).strip().lower()
    except EOFError:
        return default
    if not raw:
        return default
    return raw in ("y", "yes")


# --------------------------------------------------------------------------- #
# target + type
# --------------------------------------------------------------------------- #
def _choose_target() -> Optional[str]:
    target = _ask(_prompt("Target ") + utils.muted("(domain / IP / CIDR / company): "))
    if not target:
        print(utils.amber("  No target entered."))
        return None
    return target


def _choose_type(target: str) -> Optional[str]:
    detected = utils.classify_target(target)
    print("  " + utils.violet("detected type: ") + utils.neon(detected, bold=True))
    if _ask_yn("Override the detected type?", default=False):
        print("    " + utils.pink("1") + utils.muted(") domain   ")
              + utils.pink("2") + utils.muted(") ip   ")
              + utils.pink("3") + utils.muted(") cidr   ")
              + utils.pink("4") + utils.muted(") company"))
        choice = _ask(_prompt("Pick 1-4: "))
        mapping = {"1": "domain", "2": "ip", "3": "cidr", "4": "company"}
        return mapping.get(choice or "", detected)
    return detected


# --------------------------------------------------------------------------- #
# passive module selection
# --------------------------------------------------------------------------- #
def _enabled_summary(modules: List[Tuple[str, str]], enabled: set) -> str:
    names = [k for k, _ in modules if k in enabled]
    if len(names) == len(modules):
        return utils.neon("all", bold=True)
    if not names:
        return utils.muted("none")
    return utils.neon(", ".join(names))


def _select_modules(ttype: str, target: str) -> Optional[List[str]]:
    """Return the list of enabled passive module keys, or None for 'all'."""
    modules = PASSIVE_MODULES.get(ttype, [])
    if not modules:
        return None  # nothing to toggle (e.g. company / ip minimal)

    enabled = {key for key, _ in modules}  # all on by default (passive)
    status = utils.muted("All modules enabled by default.")

    while True:
        _clear()
        print("  " + utils.pink("\u2593 ", bold=True)
              + utils.neon("DARKSECLABZ blightscan", bold=True)
              + utils.muted("  \u00b7  target: ") + utils.body(target)
              + utils.muted("  \u00b7  ") + utils.violet(ttype))
        print()
        lines = []
        for i, (key, desc) in enumerate(modules, 1):
            on = key in enabled
            box = utils.neon("[\u2713]", bold=True) if on else utils.muted("[ ]")
            label = utils.body(desc) if on else utils.muted(desc)
            num = utils.pink(str(i), bold=True)
            lines.append(f"{num} {box} {label}")
        _panel(lines, title="PASSIVE MODULES")
        print("  " + utils.violet("Enabled: ") + _enabled_summary(modules, enabled))
        print("  " + status)
        print("  " + utils.muted("keys:  ")
              + utils.pink("#") + utils.muted(" toggle (e.g. '2 4')   ")
              + utils.pink("a") + utils.muted(" all   ")
              + utils.pink("n") + utils.muted(" none   ")
              + utils.pink("\u21b5") + utils.muted(" continue"))

        raw = _ask(_prompt(""), default="")
        if raw == "":
            break
        low = raw.strip().lower()

        if low in ("a", "all"):
            enabled = {key for key, _ in modules}
            status = utils.neon("\u2713 Enabled ALL modules.", bold=True)
            continue
        if low in ("n", "none"):
            enabled = set()
            status = utils.amber("\u2717 Disabled ALL modules.")
            continue

        toggled: List[str] = []
        invalid: List[str] = []
        for tok in low.replace(",", " ").split():
            if tok.isdigit() and 1 <= int(tok) <= len(modules):
                key = modules[int(tok) - 1][0]
                if key in enabled:
                    enabled.discard(key)
                    toggled.append(f"{key} OFF")
                else:
                    enabled.add(key)
                    toggled.append(f"{key} ON")
            else:
                invalid.append(tok)

        parts = []
        if toggled:
            parts.append(utils.neon("Toggled " + ", ".join(toggled)))
        if invalid:
            parts.append(utils.amber("ignored: " + ", ".join(invalid)))
        status = utils.muted("  \u00b7  ").join(parts) if parts else utils.muted("No change.")

    result = [key for key, _ in modules if key in enabled]
    print("  " + utils.violet("Final selection: ") + _enabled_summary(modules, enabled))
    return result


# --------------------------------------------------------------------------- #
# active-recon gating (STRICT - unchanged behavior)
# --------------------------------------------------------------------------- #
def _confirm_active(label: str, target: str) -> bool:
    """Loud, explicit confirmation required before any ACTIVE recon."""
    bar = "\u2501" * (_WIDTH - 2)
    print("  " + utils.danger(bar, bold=True))
    print("  " + utils.danger("\u26a0 ACTIVE RECON WARNING: ", bold=True) + utils.danger(label))
    for line in (
        "This sends traffic directly to the target and is intrusive.",
        "Only do this against systems you OWN or are EXPLICITLY AUTHORIZED",
        "(in writing) to test. Unauthorized scanning may be illegal.",
    ):
        print("  " + utils.amber(line))
    print("  " + utils.danger(bar, bold=True))
    print("  " + utils.muted("To proceed, type the target exactly: ") + utils.body(target))
    typed = _ask(_prompt("Confirm target: "))
    if typed != target:
        print("  " + utils.amber("Confirmation did not match \u2014 skipping active step."))
        return False
    return _ask_yn("I am authorized to actively test this target. Proceed?",
                   default=False)


# --------------------------------------------------------------------------- #
# main interactive flow
# --------------------------------------------------------------------------- #
def run_tui() -> int:
    from .cli import main as cli_main  # lazy import to avoid circular import

    _banner()

    target = _choose_target()
    if not target:
        return 1

    ttype = _choose_type(target)
    modules = _select_modules(ttype, target)

    argv: List[str] = [target, "-t", ttype]
    if modules is not None:
        argv += ["--modules", ",".join(modules) if modules else "none"]

    # --- subdomain brute force (passive-ish, but can be noisy DNS) ---------- #
    if ttype == "domain" and (modules is None or "subdomains" in modules):
        if not _ask_yn("\n  Include subdomain wordlist brute force?", default=True):
            argv.append("--no-bruteforce")

    # --- email person hint ------------------------------------------------- #
    if ttype == "domain" and (modules is None or "emails" in modules):
        person = _ask(_prompt("Person name for email guessing ")
                      + utils.muted("(optional, Enter to skip): "), default="")
        if person:
            argv += ["--person", person]

    # --- ACTIVE: port scan (gated) ----------------------------------------- #
    if ttype in ("domain", "ip", "cidr"):
        if _ask_yn("\n  Run ACTIVE TCP port scan? (authorized targets only)",
                   default=False):
            if _confirm_active("TCP port scan (--ports)", target):
                argv.append("--ports")
            else:
                print("  " + utils.muted("Port scan disabled; continuing passive-only."))

    # --- ACTIVE: company mode hits third-party hosts ----------------------- #
    if ttype == "company":
        print("  " + utils.amber(
            "Company mode queries third-party search/discovery services and then"))
        print("  " + utils.amber("pivots into a full domain workflow."))
        if not _confirm_active("company-mode discovery + pivot", target):
            print("  " + utils.amber("Company mode not confirmed \u2014 aborting."))
            return 1

    # --- output ------------------------------------------------------------ #
    out = _ask(_prompt("Save JSON report to file ")
               + utils.muted("(path, Enter to skip): "), default="")
    if out:
        argv += ["-o", out]

    # --- summary + go ------------------------------------------------------ #
    import textwrap
    print()
    cmd = "blightscan " + " ".join(argv)
    wrapped = textwrap.wrap(cmd, width=_WIDTH - 6) or [cmd]
    _panel([utils.body(w) for w in wrapped], title="ABOUT TO RUN")
    if not _ask_yn("\n  Proceed?", default=True):
        print("  " + utils.amber("Cancelled."))
        return 1

    print("  " + utils.violet("\u2500" * (_WIDTH - 2)))
    return cli_main(argv)
