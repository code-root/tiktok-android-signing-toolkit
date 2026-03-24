#!/usr/bin/env python3
"""Shim — equivalent to ``python3 -m ttk.feed_api_client``."""
import runpy
import sys

if __name__ == "__main__":
    sys.argv[0] = "ttk.feed_api_client"
    runpy.run_module("ttk.feed_api_client", run_name="__main__")
