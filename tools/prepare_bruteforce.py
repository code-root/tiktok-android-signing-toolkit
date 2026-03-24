#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prepare_bruteforce.py — يحضّر المدخلات الصحيحة لـ gorgon_bruteforce

خطوات:
  1. التقط X-Gorgon حقيقي من Charles/Fiddler
  2. خذ الـ URL الكامل + body + cookie + timestamp
  3. شغّل هذا السكريبت ليحسب الـ hashes الصحيحة
  4. انسخ الأمر الناتج وشغّله في start.sh

استخدام:
  python3 prepare_bruteforce.py \
      --url "https://log-va.tiktokv.com/service/2/device_register/?device_id=0&aid=1233&ts=1711111111..." \
      --body '{"magic_tag":"ss_app_log",...}' \
      --cookie "store-idc=useast5; tt-target-idc=useast5" \
      --captured-gorgon "8404000000001a2b3c..." \
      --threads 8
"""

import argparse
import hashlib
import re
import sys
from urllib.parse import urlparse

# ── الدوال نفسها من signing_engine.py ──────────────────

def compute_url_md5(url: str) -> str:
    qs = urlparse(url).query
    return hashlib.md5(qs.encode("utf-8")).hexdigest()

def compute_stub(body: str | bytes) -> str:
    if not body:
        return ""
    raw = body.encode("utf-8") if isinstance(body, str) else body
    return hashlib.md5(raw).hexdigest().upper()

def compute_cookie_md5(cookie: str) -> str:
    if not cookie:
        return ""
    return hashlib.md5(cookie.encode("utf-8")).hexdigest()

def extract_ts_from_url(url: str) -> int | None:
    m = re.search(r"[?&]ts=(\d+)", url)
    return int(m.group(1)) if m else None

def extract_ts_from_gorgon(gorgon: str) -> int | None:
    """آخر 8 chars من X-Gorgon = timestamp hex"""
    if len(gorgon) >= 52:
        ts_hex = gorgon[-8:]
        try:
            return int(ts_hex, 16)
        except ValueError:
            return None
    return None

def parse_fixed_from_gorgon(gorgon: str) -> str:
    """
    يستخرج الـ fixed bytes المعروفة من X-Gorgon header.
    X-Gorgon structure:
      [0:4]   version = "8404" أو "0404"
      [4:6]   hex_str[7]
      [6:8]   hex_str[3]
      [8:10]  hex_str[1]
      [10:12] hex_str[6]
      [12:52] sig (20 bytes)
    """
    if len(gorgon) < 12:
        return "xx,xx,xx,xx,xx,xx,xx,xx"
    b7 = int(gorgon[4:6],  16)
    b3 = int(gorgon[6:8],  16)
    b1 = int(gorgon[8:10], 16)
    b6 = int(gorgon[10:12], 16)
    # fixed[0], fixed[1]=b1, fixed[2], fixed[3]=b3,
    # fixed[4], fixed[5], fixed[6]=b6, fixed[7]=b7
    fixed = ["xx"] * 8
    fixed[1] = str(b1)
    fixed[3] = str(b3)
    fixed[6] = str(b6)
    fixed[7] = str(b7)
    return ",".join(fixed)

def build_command(args, url_md5, stub, cookie_md5, ts, fixed_str):
    parts = [
        "./gorgon_bf",
        f"--url-md5 {url_md5}",
        f"--ts {ts}",
        f'--target "{args.captured_gorgon}"',
        f'--fixed "{fixed_str}"',
        f"--threads {args.threads}",
    ]
    if stub:
        parts.append(f"--stub {stub}")
    if cookie_md5:
        parts.append(f"--cookie-md5 {cookie_md5}")
    return " \\\n    ".join(parts)


def main():
    p = argparse.ArgumentParser(description="تحضير مدخلات gorgon_bruteforce")
    p.add_argument("--url",              required=True, help="الـ URL الكامل")
    p.add_argument("--body",             default="",    help="الـ body النصي")
    p.add_argument("--cookie",           default="",    help="الـ Cookie header")
    p.add_argument("--captured-gorgon",  required=True, help="قيمة X-Gorgon المُلتقطة")
    p.add_argument("--threads",          type=int, default=8)
    args = p.parse_args()

    gorgon = args.captured_gorgon.strip()
    if len(gorgon) < 52:
        print(f"[!] X-Gorgon قصير جداً: {len(gorgon)} حرف (المطلوب 52+)", file=sys.stderr)
        sys.exit(1)

    url_md5    = compute_url_md5(args.url)
    stub       = compute_stub(args.body) if args.body else ""
    cookie_md5 = compute_cookie_md5(args.cookie) if args.cookie else ""

    # timestamp: من URL أو من X-Gorgon
    ts = extract_ts_from_url(args.url)
    if ts is None:
        ts = extract_ts_from_gorgon(gorgon)
        print(f"[~] timestamp من X-Khronos: {ts}")
    else:
        print(f"[~] timestamp من URL: {ts}")

    if ts is None:
        print("[!] لم أجد timestamp. أضفه يدوياً في --url مثل: &ts=1711111111")
        sys.exit(1)

    fixed_str = parse_fixed_from_gorgon(gorgon)
    version   = gorgon[:4]

    print(f"\n{'='*60}")
    print(f"  المدخلات المحسوبة")
    print(f"{'='*60}")
    print(f"  version       = {version}")
    print(f"  url_md5       = {url_md5}")
    print(f"  stub          = {stub or '(GET - فارغ)'}")
    print(f"  cookie_md5    = {cookie_md5 or '(فارغ)'}")
    print(f"  ts            = {ts}  (hex: {ts:08x})")
    print(f"  fixed_str     = {fixed_str}")
    print(f"  target_sig    = {gorgon[12:52]}")
    print(f"\n  bytes معروفة من X-Gorgon header:")
    b1 = int(gorgon[8:10], 16)
    b3 = int(gorgon[6:8], 16)
    b6 = int(gorgon[10:12], 16)
    b7 = int(gorgon[4:6], 16)
    print(f"    hex_str[1]={b1}  hex_str[3]={b3}  hex_str[6]={b6}  hex_str[7]={b7}")
    print(f"  → bytes مجهولة: hex_str[0], [2], [4], [5]")
    print(f"  → فضاء البحث: 256^4 = {256**4:,} محاولة ≈ 4.29 مليار\n")

    cmd = build_command(args, url_md5, stub, cookie_md5, ts, fixed_str)

    print(f"{'='*60}")
    print(f"  الأمر الجاهز للتشغيل:")
    print(f"{'='*60}")
    print(f"\n{cmd}\n")

    # كتابة start.sh جاهز
    with open("start_ready.sh", "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("cd \"$(dirname \"$0\")\"\n\n")
        f.write("# تجميع\n")
        f.write("[ ! -f ./gorgon_bf ] && gcc -O3 -march=native -o gorgon_bf gorgon_bruteforce.c -lpthread\n\n")
        f.write("# تشغيل في الخلفية\n")
        f.write(f"nohup \\\n    {cmd} \\\n    > output.log 2>&1 &\n")
        f.write("echo \"PID: $!\"\n")
        f.write("echo \"tail -f output.log\"\n")
    print(f"[+] تم حفظ: start_ready.sh")

    # كتابة start.bat
    with open("start_ready.bat", "w") as f:
        f.write("@echo off\n")
        f.write("if not exist gorgon_bf.exe gcc -O3 -o gorgon_bf.exe gorgon_bruteforce.c -lpthread\n")
        win_cmd = cmd.replace("./gorgon_bf", "gorgon_bf.exe").replace("\\\n    ", "^\n    ")
        f.write(f"start /B {win_cmd} > output.log 2>&1\n")
        f.write("echo يعمل في الخلفية - type output.log\n")
    print(f"[+] تم حفظ: start_ready.bat")


if __name__ == "__main__":
    main()
