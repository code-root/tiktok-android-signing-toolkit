#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.fake_login_probe``."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.fake_login_probe"
    runpy.run_module("ttk.fake_login_probe", run_name="__main__")
