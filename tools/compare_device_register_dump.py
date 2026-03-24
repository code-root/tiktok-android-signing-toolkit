#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compare two golden JSON files produced by ``device_register.py --dump-golden`` or
``--golden-only`` (or hand-edited MITM exports with the same ``request`` shape).

Usage:
  python3 tools/compare_device_register_dump.py golden_mitm.json golden_python.json
"""

from __future__ import annotations

import argparse
import json
import sys


def _load(p: str) -> dict:
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _hdr_keys(body_json: str) -> set:
    try:
        o = json.loads(body_json)
        h = o.get("header") or {}
        return set(h.keys()) if isinstance(h, dict) else set()
    except Exception:
        return set()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file_a", help="MITM capture or reference")
    ap.add_argument("file_b", help="Python golden")
    args = ap.parse_args()

    a = _load(args.file_a)
    b = _load(args.file_b)
    ra = a.get("request") or a
    rb = b.get("request") or b

    print("=== profile_hint ===")
    print("A:", json.dumps(a.get("profile_hint"), ensure_ascii=False))
    print("B:", json.dumps(b.get("profile_hint"), ensure_ascii=False))

    print("\n=== query param keys (diff) ===")
    pa, pb = ra.get("params") or {}, rb.get("params") or {}
    if isinstance(pa, str):
        print("Note: A has string params — normalize to dict for full diff")
    if isinstance(pb, str):
        print("Note: B has string params")
    if isinstance(pa, dict) and isinstance(pb, dict):
        sa, sb = set(pa.keys()), set(pb.keys())
        print("only A:", sorted(sa - sb))
        print("only B:", sorted(sb - sa))
        for k in sorted(sa & sb):
            if pa.get(k) != pb.get(k):
                print(f"  {k!r}: A={pa.get(k)!r} B={pb.get(k)!r}")

    print("\n=== body hashes ===")
    for label, r in ("A", ra), ("B", rb):
        print(
            label,
            "body_utf8_sha256",
            r.get("body_utf8_sha256"),
            "gzip_sha256",
            r.get("gzip_sha256"),
            "sign_mode",
            r.get("sign_mode"),
        )

    print("\n=== header JSON keys (ss_app_log.header) ===")
    ba, bb = ra.get("body_json") or "", rb.get("body_json") or ""
    ka, kb = _hdr_keys(ba), _hdr_keys(bb)
    print("only A:", sorted(ka - kb))
    print("only B:", sorted(kb - ka))

    print("\n=== X-Gorgon prefix ===")
    print("A", ra.get("xgorgon_prefix"))
    print("B", rb.get("xgorgon_prefix"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
