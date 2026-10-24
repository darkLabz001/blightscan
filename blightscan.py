#!/usr/bin/env python3
"""Convenience launcher so you can run `./blightscan.py <target>` directly."""
import sys
from blightscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
