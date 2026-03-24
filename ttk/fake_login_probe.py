#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fake_login_probe.py — اختبار «لوجن وهمي» ضد خوادم TikTok

لا يُرسل كلمة مرور حقيقية. يهدف إلى:
  • التحقق من أن التوقيعات والهيدرز تُبنى بشكل كامل (X-Argus / Gorgon / Ladon / STUB / guard)
  • قياس استجابة الخادم على check_login_name_registered + pre_check باسم مستخدم عشوائي

error_code 31: غالباً رفض risk / بصمة غير متسقة (جهاز، guard، جلسة غير مسجّلة).
  - جرّب: --device device_emulator_mitm_44315.json (محاكي يطابق MITM)
  - سجّل الجهاز عبر device_register.py ثم انسخ device_id + guard_keys من الاستجابة

Usage:
    python3 fake_login_probe.py
    python3 fake_login_probe.py --proxy-file proxsy.txt
    python3 fake_login_probe.py --device device_emulator_mitm_44315.json --verbose
    python3 fake_login_probe.py --mitm-folder ../api-proxy/Raw_03-23-2026-14-39-43.folder --mitm-only

إن وُجد ``proxsy.txt`` في ``tiktok_final/`` يُحمّل أول سطر بروكسي تلقائياً ما لم تمرّر ``--no-proxy``.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time

from .paths import PROJECT_ROOT, WORKSPACE_ROOT
from .login_client import TikTokLoginClient, encode_password, _proxy_line_to_url
from .mitm_raw import scan_folder_summary


def _dry_sign_only(client: TikTokLoginClient, user: str) -> None:
    ts = int(time.time())
    rt = ts * 1000
    params = client._base_params(ts, rticket=rt, include_device_redirect=True)
    url = client._build_url(client._HOST_LOGIN, "/passport/user/login/", params)
    body = (
        f"password={encode_password('dummy')}"
        f"&account_sdk_source=app&multi_login=1&mix_mode=1"
        f"&username={encode_password(user)}"
    )
    hdrs = client._sign_and_build_headers(
        url, "POST", body, cookie=client._cookie_for_passport_request()
    )
    print("[probe] --only-sign (offline):", flush=True)
    for k in ("X-SS-STUB", "X-Khronos", "X-Gorgon", "X-Ladon", "X-Argus"):
        v = hdrs.get(k, "")
        print(f"  {k}: {v}", flush=True)
    gd = hdrs.get("tt-device-guard-client-data", "")
    print(f"  tt-device-guard-client-data ({len(gd)} b64 chars)", flush=True)


def _dummy_username() -> str:
    return f"probe_{secrets.token_hex(6)}_user"


def _mitm_folder_candidates(path: str) -> list[str]:
    """مسارات مطلقة نجرّبها بالترتيب."""
    if not path:
        return []
    raw = os.path.expanduser(path.strip())
    repo = WORKSPACE_ROOT
    parent = os.path.dirname(repo)
    home = os.path.expanduser("~")
    bn = os.path.basename(os.path.normpath(raw))

    candidates: list[str] = []
    seen: set[str] = set()

    def add(p: str) -> None:
        ap = os.path.abspath(os.path.normpath(p))
        if ap not in seen:
            seen.add(ap)
            candidates.append(ap)

    # مسار كامل من البيئة (الأولوية)
    env_p = (os.environ.get("TIKTOK_MITM_FOLDER") or "").strip()
    if env_p:
        add(env_p)

    add(raw)
    for base in (os.getcwd(), PROJECT_ROOT, repo, parent):
        add(os.path.join(base, raw))

    # api-proxy داخل المشروع / المستندات / المجلد الأب
    for base in (repo, parent, os.getcwd(), PROJECT_ROOT):
        add(os.path.join(base, "api-proxy", bn))

    # المجلد بجانب المستخدم (Desktop / Downloads / …) — غالباً يضع api-proxy هناك
    home_bases = [
        home,
        os.path.join(home, "Desktop"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Documents"),
    ]
    for base in home_bases:
        if not base or not os.path.isdir(base):
            continue
        add(os.path.join(base, "api-proxy", bn))
        add(os.path.join(base, bn))

    return candidates


def _discover_raw_folders_in_repo(max_items: int = 16) -> list[str]:
    """مجلدات ``Raw_*.folder`` الموجودة فعلياً تحت جذر المستودع (مثل ``tik-api-1``)."""
    repo = WORKSPACE_ROOT
    out: list[str] = []
    seen: set[str] = set()
    for sub in ("tik-api-1", "api-proxy", "tiktok_final"):
        root = os.path.join(repo, sub)
        if not os.path.isdir(root):
            continue
        try:
            for name in sorted(os.listdir(root)):
                if not name.startswith("Raw_") or not name.endswith(".folder"):
                    continue
                p = os.path.join(root, name)
                if os.path.isdir(p):
                    ap = os.path.abspath(p)
                    if ap not in seen:
                        seen.add(ap)
                        out.append(ap)
        except OSError:
            pass
        if len(out) >= max_items:
            break
    return out[:max_items]


def _resolve_mitm_folder(path: str) -> str | None:
    """
    ``../api-proxy/Raw_....folder`` من ``tiktok_final`` → ``normpath`` من جذر المستودع
    يعطي غالباً ``.../Documents/api-proxy/...`` إن كان ``api-proxy`` بجانب المشروع.
    """
    for cand in _mitm_folder_candidates(path):
        if os.path.isdir(cand):
            return cand
    return None


def _default_proxy_file_path() -> str | None:
    p = os.path.join(PROJECT_ROOT, "proxsy.txt")
    return p if os.path.isfile(p) else None


def main() -> int:
    p = argparse.ArgumentParser(description="TikTok fake login / header probe (no real password)")
    p.add_argument("--device", default=os.path.join(PROJECT_ROOT, "device_emulator_mitm_44315.json"),
                   help="Device JSON (default: emulator MITM-aligned profile)")
    p.add_argument("--username", default="", help="Fixed username to check (default: random probe_*)")
    p.add_argument("--proxy", default=None, help="HTTP proxy URL (overrides --proxy-file)")
    p.add_argument("--proxy-file", default=None,
                   help="host:port:user:pass lines (Geonode user may contain ':'). Default: tiktok_final/proxsy.txt if present")
    p.add_argument("--no-proxy", action="store_true", help="Do not load proxsy.txt / proxy-file")
    p.add_argument("--mitm-folder", default=None,
                   help="Raw_....folder or basename only; also set TIKTOK_MITM_FOLDER=/abs/path "
                        "if المجلد خارج المسارات التلقائية")
    p.add_argument("--mitm-only", action="store_true", help="Only print --mitm-folder summary, then exit")
    p.add_argument("--mitm-list-repo", action="store_true",
                   help="List Raw_*.folder found under repo (tik-api-1, …) and exit")
    p.add_argument("--verbose", action="store_true", help="Print full headers / bodies")
    p.add_argument("--skip-region", action="store_true", help="Skip get_nonce + app/region chain")
    p.add_argument("--only-sign", action="store_true",
                   help="No HTTP — only build signing headers for a dummy login POST (offline)")
    p.add_argument("--step1-only", action="store_true", help="Stop after check_login_name_registered")
    args = p.parse_args()

    if args.mitm_list_repo:
        found = _discover_raw_folders_in_repo()
        print("[probe] Raw_*.folder under repo:", flush=True)
        if not found:
            print("  (none — add captures under tik-api-1/ or api-proxy/)", flush=True)
            return 1
        for pth in found:
            print(f"  {pth}", flush=True)
        print("\nExample:", flush=True)
        print(
            f'  python3 fake_login_probe.py --no-proxy --mitm-folder "{found[0]}" --mitm-only',
            flush=True,
        )
        return 0

    proxy_url = None if args.no_proxy else args.proxy
    if not proxy_url and not args.no_proxy:
        pf = args.proxy_file
        if pf is None:
            pf = _default_proxy_file_path()
        if pf:
            pabs = pf if os.path.isabs(pf) else os.path.join(PROJECT_ROOT, pf)
            if os.path.isfile(pabs):
                with open(pabs, encoding="utf-8", errors="ignore") as fp:
                    for line in fp:
                        proxy_url = _proxy_line_to_url(line)
                        if proxy_url:
                            print(f"[probe] proxy from {pabs} (first valid line)", flush=True)
                            break

    mitm_arg = (args.mitm_folder or os.environ.get("TIKTOK_MITM_FOLDER") or "").strip()
    mitm = _resolve_mitm_folder(mitm_arg)
    if args.mitm_folder or os.environ.get("TIKTOK_MITM_FOLDER"):
        if not mitm:
            print(f"[probe] [!] mitm-folder not found: {mitm_arg!r}", flush=True)
            print(
                "[probe]     hint: export TIKTOK_MITM_FOLDER=\"/full/path/to/Raw_....folder\"",
                flush=True,
            )
            tried = _mitm_folder_candidates(mitm_arg)
            if tried:
                print("[probe]     tried:", flush=True)
                for t in tried[:24]:
                    print(f"       - {t}", flush=True)
                if len(tried) > 24:
                    print(f"       ... +{len(tried) - 24} more", flush=True)
            alt = _discover_raw_folders_in_repo()
            if alt:
                print(
                    "[probe]     المجلد المطلوب غير موجود. هذه اعتراضات موجودة في المشروع:",
                    flush=True,
                )
                for ap in alt[:8]:
                    print(f"       ✓ {ap}", flush=True)
                print(
                    f'[probe]     جرّب: python3 fake_login_probe.py --no-proxy --mitm-folder "{alt[0]}" --mitm-only',
                    flush=True,
                )
        else:
            print(f"[probe] mitm-folder={mitm}", flush=True)
            print(json.dumps(scan_folder_summary(mitm), indent=2, ensure_ascii=False), flush=True)
        if args.mitm_only:
            return 0 if mitm else 1

    user = (args.username or "").strip() or _dummy_username()
    print(f"[probe] device={args.device}", flush=True)
    print(f"[probe] username={user!r}", flush=True)
    if proxy_url:
        print(f"[probe] proxy={proxy_url.split('@')[-1]}", flush=True)

    client = TikTokLoginClient(
        device_path=args.device,
        proxy=proxy_url,
        verbose=args.verbose,
    )

    if args.only_sign:
        _dry_sign_only(client, user)
        return 0

    # ── Warm-up steps (same order as login()) ─────────────────────────────
    if not args.skip_region:
        print("[probe] get_nonce ...", flush=True)
        try:
            r0 = client.step_get_nonce()
            d0 = r0.get("data") or {}
            print(
                f"  → message={r0.get('message')} error_code={d0.get('error_code')} "
                f"keys={list(d0.keys())}",
                flush=True,
            )
        except Exception as e:
            print(f"  [!] {e}", flush=True)

        print("[probe] app/region chain (useast5 → canonical) ...", flush=True)
        try:
            r_reg = client.step_app_region_chain(region_id_source=None)
            fin = r_reg.get("final") or {}
            d = fin.get("data") or {}
            dom = d.get("domain")
            print(f"  → domain={dom or '?'} captcha_domain={d.get('captcha_domain', '?')}", flush=True)
            if not dom:
                print(f"  [raw final] {json.dumps(fin, ensure_ascii=False)[:600]}", flush=True)
        except Exception as e:
            print(f"  [!] {e}", flush=True)

    # ── Step 1: check_login_name_registered ───────────────────────────────
    print("[probe] GET check_login_name_registered ...", flush=True)
    try:
        r1 = client.step1_check_username(user)
    except Exception as e:
        print(f"  [!] HTTP/request error: {e}", flush=True)
        return 2

    d1 = r1.get("data") or {}
    ec1 = d1.get("error_code")
    print(f"  → message={r1.get('message')} error_code={ec1} is_registered={d1.get('is_registered')}", flush=True)
    if ec1 == 31:
        print(
            "\n  [hint] error_code 31: منطق الخادم يرفض الطلب (غالباً بصمة/جلسة).\n"
            "         • استخدم device_emulator_mitm_44315.json أو جهاز مسجّل فعلياً.\n"
            "         • نفّذ device_register.py ثم حدّث device_id + guard_keys في JSON.\n"
            "         • تأكد أن channel في الملف يطابق بناء التطبيق (beta / googleplay / …).\n",
            flush=True,
        )

    if args.step1_only:
        print("[probe] --step1-only: skipping pre_check", flush=True)
        return 0 if ec1 != 31 else 1

    # ── Step 2: pre_check (no password) ─────────────────────────────────────
    print("[probe] POST login/pre_check ...", flush=True)
    try:
        r2 = client.step2_pre_check(user)
    except Exception as e:
        print(f"  [!] {e}", flush=True)
        return 2

    d2 = r2.get("data") or {}
    ec2 = d2.get("error_code", 0)
    print(f"  → message={r2.get('message')} error_code={ec2}", flush=True)

    # ── Dry login body signing only (no send) ─────────────────────────────
    ts = int(time.time())
    rt = ts * 1000
    params = client._base_params(ts, rticket=rt, include_device_redirect=True)
    url = client._build_url(client._HOST_LOGIN, "/passport/user/login/", params)
    body = (
        f"password={encode_password('dummy_not_used')}"
        f"&account_sdk_source=app&multi_login=1&mix_mode=1"
        f"&username={encode_password(user)}"
    )
    hdrs = client._sign_and_build_headers(url, "POST", body, cookie=client._cookie_for_passport_request())
    print("[probe] dry-sign POST /passport/user/login/ (not sent):", flush=True)
    for k in ("X-SS-STUB", "X-Khronos", "X-Gorgon", "X-Ladon", "X-Argus"):
        v = hdrs.get(k, "")
        print(f"  {k}: {len(v)} chars  prefix={str(v)[:24]}...", flush=True)
    g = hdrs.get("tt-device-guard-client-data") or hdrs.get("tt-ticket-guard-client-data") or ""
    print(f"  tt-*-guard-client-data: {len(g)} chars", flush=True)

    out = {
        "username": user,
        "check_login": r1,
        "pre_check": r2,
        "dry_sign_lengths": {k: len(hdrs.get(k, "")) for k in ("X-Argus", "X-Gorgon", "X-Ladon", "X-SS-STUB")},
    }
    print("\n[probe] summary JSON:", flush=True)
    print(json.dumps(out, indent=2, ensure_ascii=False)[:2500], flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
