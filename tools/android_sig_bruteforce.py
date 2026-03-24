#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
android_sig_bruteforce.py — مسح «قوة إجبارية» لملفات أندرويد المفككة + تحليل توقيع APK

يجمع:
  • استخراج sig_hash وبصمات الشهادة من APK (مثل apk_sig_hash.py)
  • مسح متكرر لمجلد JADX/APKTool: كلمات التوقيع، سلاسل hex طويلة، مصفوفات bytes
  • بحث عن تسلسلات hex معروفة (ثوابت signing_engine) في كل الملفات النصية
  • تقرير JSON اختياري

الاستخدام:
  python3 android_sig_bruteforce.py --apk /path/app.apk --out report.json
  python3 android_sig_bruteforce.py --jadx /path/jadx_out --apk /path/app.apk
  python3 android_sig_bruteforce.py --jadx /path/jadx_out --hex-brute "ac 1a da ae"
  python3 android_sig_bruteforce.py --jadx /path/jadx_out --full
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ── امتدادات الملفات المرشحة للتحليل النصي ─────────────────────────────────
TEXT_EXTENSIONS = frozenset({
    ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".txt",
    ".pro", ".gradle", ".kts", ".aidl",
})

# كلمات/رؤوس التوقيع (مسح سريع)
SIGNATURE_TERMS: list[tuple[str, list[str]]] = [
    ("headers", ["X-Gorgon", "X-Argus", "X-Ladon", "X-Khronos", "X-SS-STUB", "x-gorgon"]),
    ("names", ["gorgon", "argus", "ladon", "khronos", "metasec", "sscronet", "ss_stub"]),
    ("crypto", ["SIMON", "SM3", "MessageDigest", "Cipher", "AES", "RC4", "JNI_OnLoad"]),
]

# ثوابت معروفة من signing_engine (بداية التسلسل) للمطابقة السريعة
KNOWN_HEX_PREFIXES: list[tuple[str, str]] = [
    ("argus_key_16", "ac1adaae95a7af94a5114ab3b3a97dd8"),
    ("gorgon_hexstr", "1e40e0d9934500b4"),
    ("ladon_license", "601e6f64"),  # 1611921764 LE
]


def _read_text_safe(path: Path, max_bytes: int) -> str:
    try:
        raw = path.read_bytes()[:max_bytes]
    except OSError:
        return ""
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""


def _iter_files(root: Path, exts: frozenset[str] | None, max_file_mb: float) -> Iterator[Path]:
    max_b = int(max_file_mb * 1024 * 1024)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if exts is not None and p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > max_b:
                continue
        except OSError:
            continue
        yield p


# ══════════════════════════════════════════════════════════════════════════════
# APK: توقيع v1 + sig_hash + بصمات (openssl اختياري)
# ══════════════════════════════════════════════════════════════════════════════

def first_meta_inf_signature_block(apk_path: Path) -> tuple[str | None, bytes | None]:
    """أول ملف META-INF/*.RSA|DSA|EC ومحتواه."""
    with zipfile.ZipFile(apk_path, "r") as z:
        names = [n for n in z.namelist() if n.startswith("META-INF/")]
        for ext in (".RSA", ".DSA", ".EC"):
            for n in sorted(names):
                if n.endswith(ext) and not n.endswith("MANIFEST.MF"):
                    return n, z.read(n)
    return None, None


def meta_inf_listing(apk_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for n in sorted(z.namelist()):
            if not n.startswith("META-INF/"):
                continue
            info = z.getinfo(n)
            out.append({
                "name": n,
                "size": info.file_size,
                "compress": info.compress_type,
            })
    return out


def sig_hash_md5_of_v1_block(raw_pkcs7: bytes) -> str:
    return hashlib.md5(raw_pkcs7).hexdigest()


def openssl_cert_fingerprints(pkcs7_der: bytes) -> tuple[str | None, str | None]:
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


def analyze_apk(apk_path: Path, with_cert: bool) -> dict[str, Any]:
    listing = meta_inf_listing(apk_path)
    report: dict[str, Any] = {
        "path": str(apk_path),
        "meta_inf_files": len(listing),
        "meta_inf_detail": listing[:80],
    }
    if len(listing) > 80:
        report["meta_inf_truncated"] = True

    name, raw = first_meta_inf_signature_block(apk_path)
    if not raw:
        report["sig_hash"] = None
        report["error"] = "No META-INF *.RSA/*.DSA/*.EC — قد يكون التوقيع v2 فقط أو APK غير كامل"
        return report

    report["first_signature_entry"] = name
    report["first_signature_size"] = len(raw)
    report["sig_hash"] = sig_hash_md5_of_v1_block(raw)

    if with_cert:
        s1, s256 = openssl_cert_fingerprints(raw)
        report["cert_sha1"] = s1
        report["cert_sha256"] = s256

    report["note"] = "sig_hash يطابق منطق TikTok (MD5 أول كتلة PKCS#7 في META-INF)."

    return report


# ══════════════════════════════════════════════════════════════════════════════
# مسح مجلد المصدر (JADX / smali / إلخ)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanStats:
    files_scanned: int = 0
    bytes_read: int = 0
    term_hits: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    hex_long_strings: list[dict[str, Any]] = field(default_factory=list)
    known_prefix_hits: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))


# سلاسل hex طويلة (مفاتيح/توقيعات محتملة)
_RE_HEX_RUN = re.compile(r"[0-9a-fA-F]{32,}")


def scan_tree(
    root: Path,
    max_file_mb: float,
    max_hex_samples: int,
    read_cap_per_file: int,
) -> ScanStats:
    stats = ScanStats()
    hex_count = 0

    for path in _iter_files(root, TEXT_EXTENSIONS, max_file_mb):
        stats.files_scanned += 1
        text = _read_text_safe(path, read_cap_per_file)
        stats.bytes_read += len(text.encode("utf-8", errors="replace"))
        lower = text.lower()

        for cat, terms in SIGNATURE_TERMS:
            for t in terms:
                if t.lower() in lower:
                    # عدّ التكرارات بrough
                    c = lower.count(t.lower())
                    if c and len(stats.term_hits[f"{cat}:{t}"]) < 200:
                        line_no = text[: text.lower().find(t.lower())].count("\n") + 1 if t.lower() in lower else 0
                        stats.term_hits[f"{cat}:{t}"].append({
                            "file": str(path.relative_to(root)),
                            "line": line_no,
                            "count": c,
                        })

        for m in _RE_HEX_RUN.finditer(text):
            if hex_count >= max_hex_samples:
                break
            s = m.group(0)
            if len(s) % 2 == 0 and len(s) >= 32:
                ln = text[: m.start()].count("\n") + 1
                stats.hex_long_strings.append({
                    "file": str(path.relative_to(root)),
                    "line": ln,
                    "len": len(s),
                    "preview": s[:64] + ("..." if len(s) > 64 else ""),
                })
                hex_count += 1

        flat = text.replace(" ", "").replace("\n", "")
        for label, hx in KNOWN_HEX_PREFIXES:
            if hx.lower() in flat.lower():
                stats.known_prefix_hits[label].append({
                    "file": str(path.relative_to(root)),
                    "matched_prefix": hx,
                })

    return stats


def brute_hex_in_tree(root: Path, hex_seq: str, max_file_mb: float, read_cap: int) -> list[dict[str, Any]]:
    """بحث خام عن تسلسل hex في الملفات النصية."""
    hex_seq = hex_seq.replace(" ", "").replace(",", "")
    if len(hex_seq) % 2 != 0:
        return []
    hits: list[dict[str, Any]] = []
    needle = hex_seq.lower()
    for path in _iter_files(root, TEXT_EXTENSIONS, max_file_mb):
        text = _read_text_safe(path, read_cap)
        if needle in text.lower():
            pos = text.lower().find(needle)
            ln = text[:pos].count("\n") + 1
            line = text.splitlines()[ln - 1] if ln <= len(text.splitlines()) else ""
            hits.append({
                "file": str(path.relative_to(root)),
                "line": ln,
                "snippet": line.strip()[:200],
            })
    return hits


def stats_to_dict(s: ScanStats) -> dict[str, Any]:
    return {
        "files_scanned": s.files_scanned,
        "bytes_read_approx": s.bytes_read,
        "term_hits": {k: v[:50] for k, v in s.term_hits.items()},
        "term_hits_total_keys": len(s.term_hits),
        "hex_long_strings_sample": s.hex_long_strings[:200],
        "known_constant_hits": {k: v for k, v in s.known_prefix_hits.items()},
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(
        description="مسح ملفات أندرويد المفككة + تحليل توقيع APK (تقرير موحّد)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--jadx", type=Path, help="مجلد مخرجات JADX أو apktool (مصادر/smali)")
    ap.add_argument("--apk", type=Path, help="مسار ملف .apk لاستخراج sig_hash والـ META-INF")
    ap.add_argument("--full", action="store_true", help="مسح أوسع (زيادة عيّنات hex)")
    ap.add_argument("--cert-fingerprints", action="store_true", help="SHA-1/SHA-256 للشهادة عبر openssl")
    ap.add_argument("--hex-brute", metavar="HEX", help="بحث عن تسلسل hex في شجرة --jadx")
    ap.add_argument("--max-file-mb", type=float, default=8.0, help="تخطّى الملفات الأكبر (ميجابايت)")
    ap.add_argument("--out", type=Path, help="حفظ JSON")
    args = ap.parse_args()

    if not args.jadx and not args.apk:
        ap.print_help()
        print("\n[!] حدّد على الأقل --jadx أو --apk\n", file=sys.stderr)
        return 1

    report: dict[str, Any] = {"summary": {}}

    if args.apk:
        if not args.apk.is_file():
            print("[!] APK غير موجود:", args.apk, file=sys.stderr)
            return 2
        report["apk"] = analyze_apk(args.apk, with_cert=args.cert_fingerprints)

    if args.jadx:
        if not args.jadx.is_dir():
            print("[!] مجلد JADX غير موجود:", args.jadx, file=sys.stderr)
            return 2
        max_hex = 800 if args.full else 200
        read_cap = 2_000_000 if args.full else 600_000
        stats = scan_tree(args.jadx, args.max_file_mb, max_hex, read_cap)
        report["source_scan"] = stats_to_dict(stats)
        report["summary"]["files_scanned"] = stats.files_scanned

        if args.hex_brute:
            report["hex_brute"] = brute_hex_in_tree(
                args.jadx, args.hex_brute, args.max_file_mb, read_cap,
            )

    # طباعة مختصرة
    if args.apk and report.get("apk"):
        a = report["apk"]
        print("=== APK ===")
        print("  path:", a.get("path"))
        print("  sig_hash:", a.get("sig_hash", a.get("error")))
        if a.get("cert_sha256"):
            print("  cert_sha256:", a["cert_sha256"])
        print()

    if args.jadx and report.get("source_scan"):
        s = report["source_scan"]
        print("=== مسح المصدر ===")
        print("  ملفات:", s.get("files_scanned"))
        print("  مفاتيح term_hits:", s.get("term_hits_total_keys"))
        print("  عيّنات hex طويلة:", len(s.get("hex_long_strings_sample") or []))
        kh = s.get("known_constant_hits") or {}
        if kh:
            print("  ثوابت معروفة:")
            for k, v in kh.items():
                print(f"    • {k}: {len(v)} ملف(ات)")
        print()

    if args.hex_brute and report.get("hex_brute") is not None:
        hb = report["hex_brute"]
        print("=== hex-brute ===")
        print("  نتائج:", len(hb))
        for h in hb[:30]:
            print(f"  {h['file']}:{h['line']}  {h['snippet'][:80]}...")
        if len(hb) > 30:
            print(f"  ... و {len(hb) - 30} أخرى")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print("[+] JSON:", args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
