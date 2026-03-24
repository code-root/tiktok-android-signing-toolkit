#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extract TikTok ``sig_hash`` from an APK — same as JADX C938760aXG.LIZLLL + C0VNP.LIZLLL:
MD5(first signing block bytes) → lowercase hex (32 chars).

Use the **same** APK build as in ``fixtures/device_v44_3_1.json`` / your User-Agent version.

Usage:
  python3 tools/apk_sig_hash.py /path/to/base.apk
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import zipfile


def _first_meta_inf_signature(apk_path: str) -> bytes | None:
    """First META-INF/*.RSA / *.DSA / *.EC (v1 JAR signature block)."""
    with zipfile.ZipFile(apk_path, "r") as z:
        names = [n for n in z.namelist() if n.startswith("META-INF/")]
        for ext in (".RSA", ".DSA", ".EC"):
            for n in sorted(names):
                if n.endswith(ext) and not n.endswith("MANIFEST.MF"):
                    return z.read(n)
    return None


def sig_hash_from_apk(apk_path: str) -> str | None:
    raw = _first_meta_inf_signature(apk_path)
    if not raw:
        return None
    return hashlib.md5(raw).hexdigest()


def _openssl_cert_fingerprints(pkcs7_der: bytes) -> tuple[str | None, str | None]:
    """
    SHA-1 / SHA-256 of the **leaf** cert in the PKCS#7 block (same idea as APKMirror
    "APK certificate fingerprints"). Requires ``openssl`` on PATH.
    """
    with tempfile.NamedTemporaryFile(suffix=".p7b", delete=False) as f:
        f.write(pkcs7_der)
        p7 = f.name
    try:
        r = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-in", p7, "-print_certs", "-out", "/dev/stdout"],
            capture_output=True,
            timeout=30,
        )
        if r.returncode != 0 or not r.stdout:
            return None, None
        pem = r.stdout.decode("utf-8", errors="replace")
        # First PEM block = signing cert (matches typical APKMirror single-cert display)
        m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.DOTALL)
        if not m:
            return None, None
        one = m.group(0).encode("ascii")
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
            cf.write(one)
            cpath = cf.name
        try:
            out: list[str | None] = []
            for alg in ("sha1", "sha256"):
                p = subprocess.run(
                    ["openssl", "x509", "-in", cpath, "-noout", "-fingerprint", "-" + alg],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                line = (p.stdout or "") + (p.stderr or "")
                mm = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", line)
                out.append(mm.group(1).replace(":", "").lower() if mm else None)
            return out[0], out[1]
        finally:
            try:
                os.unlink(cpath)
            except OSError:
                pass
    finally:
        try:
            os.unlink(p7)
        except OSError:
            pass


def try_aapt_version(apk_path: str) -> str | None:
    """Optional: ``aapt dump badging`` versionName for UA alignment."""
    for cmd in (("aapt", "dump", "badging", apk_path), ("aapt2", "dump", "badging", apk_path)):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if p.returncode != 0 or not p.stdout:
                continue
            for line in p.stdout.splitlines():
                if line.startswith("versionName="):
                    return line.split("'", 2)[1] if "'" in line else line
            return p.stdout[:200]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Compute TikTok sig_hash from APK (MD5 of v1 signature block)")
    ap.add_argument("apk", help="Path to .apk (use **base.apk** from an APK bundle)")
    ap.add_argument("--show-version", action="store_true", help="Try aapt badging for versionName (align UA)")
    ap.add_argument(
        "--cert-fingerprints",
        action="store_true",
        help="Print cert SHA-1/SHA-256 (APKMirror-style) via openssl; compare with store listing",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        print("File not found:", args.apk, file=sys.stderr)
        return 1

    raw_sig = _first_meta_inf_signature(args.apk)
    if not raw_sig:
        print("No META-INF/*.RSA/*.DSA/*.EC found — APK may use signing scheme v2+ only; use a full APK.", file=sys.stderr)
        return 2

    h = hashlib.md5(raw_sig).hexdigest()
    print("sig_hash:", h)
    print("Paste under device_register.sig_hash or device.sig_hash in your base JSON.")

    if args.cert_fingerprints:
        s1, s256 = _openssl_cert_fingerprints(raw_sig)
        if s1 and s256:
            print("cert_sha1:", s1)
            print("cert_sha256:", s256)
            print(
                "Compare with APKMirror \"APK certificate fingerprints\" (same hex, ignore colons/case).",
            )
        else:
            print("Could not compute cert fingerprints (need openssl and a valid PKCS#7 block).", file=sys.stderr)

    if args.show_version:
        v = try_aapt_version(args.apk)
        if v:
            print("aapt version hint:", v)
        else:
            print("aapt not found — align meta.version / user_agent manually with this build.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
