#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.flow``."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.flow"
    runpy.run_module("ttk.flow", run_name="__main__")
