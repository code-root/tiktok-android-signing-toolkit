#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.mitm_raw``."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.mitm_raw"
    runpy.run_module("ttk.mitm_raw", run_name="__main__")
