#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Small shared helpers used across the BinTopsy scripts.

Keep this file dependency-free (stdlib only) so it never breaks an import
chain. If a helper requires an external package, add it locally to the
script that needs it instead.
"""

import os
import sys

# --- ANSI colors ---
# Set BINTOPSY_NO_COLOR=1 to strip them (useful for piping to files).
if os.environ.get("BINTOPSY_NO_COLOR") or not sys.stderr.isatty():
    RED = GREEN = YELLOW = CYAN = MAGENTA = BOLD = RESET = ""
else:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def log(msg):
    """Info log to stderr — never pollutes stdout (which carries data)."""
    sys.stderr.write(f"{GREEN}[+]{RESET} {msg}\n")


def warn(msg):
    sys.stderr.write(f"{YELLOW}[!]{RESET} {msg}\n")


def error(msg):
    sys.stderr.write(f"{RED}[-]{RESET} {msg}\n")


def die(msg, code=1):
    error(msg)
    sys.exit(code)


def parse_int(text):
    """
    Accepts decimal, hex (0x...), octal (0o...) or binary (0b...).
    Used by argparse type= for offset/base parameters.
    """
    return int(text, 0)


def open_r2(path, *, deep=True, quiet=True):
    """
    Centralised r2pipe.open with the flags every BinTopsy script wants:
      -2: silence r2's own logs to stderr
      aaa: deep analysis (skip with deep=False if speed matters)

    Imported lazily so non-r2 scripts don't pull r2pipe at import time.
    """
    import r2pipe  # noqa: WPS433  (lazy import on purpose)

    flags = ['-2'] if quiet else []
    r2 = r2pipe.open(path, flags=flags)
    if deep:
        r2.cmd("aaa")
    return r2
