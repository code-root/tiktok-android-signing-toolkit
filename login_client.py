#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.login_client`` (run from this directory)."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.login_client"
    runpy.run_module("ttk.login_client", run_name="__main__")
