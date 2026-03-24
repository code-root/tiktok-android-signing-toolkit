#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.device_register``."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.device_register"
    runpy.run_module("ttk.device_register", run_name="__main__")
