#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flow.py — TikTok v44.3.15 End-to-End Flow

Chains device registration + warm-up + login in one command:
  1. Register new device (new device_id + install_id)
  2. Warm-up: fetch initial cookies (msToken, store-country-sign) via domain resolution
  3. Save device profile to JSON
  4. Login with new device (full 15-step flow — captcha + IDV handled)

Usage:
    python3 flow.py --username myuser --password "MyPass123"
    python3 flow.py --username myuser --password-hex 5a4b61...
    python3 flow.py --username myuser --password "MyPass123" --skip-register
    python3 flow.py --username myuser --password "MyPass123" --device existing.json
    python3 flow.py --username myuser --password "MyPass123" --verbose --proxy http://127.0.0.1:8888
    python3 flow.py --username myuser --password "MyPass123" --proxy-file proxsy.txt
    python3 flow.py ... --allow-local-fallback   # only if TikTok returns 0 and you accept local IDs
"""

import argparse
import gzip
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error

from .paths import FIXTURES_DIR, PROJECT_ROOT
from .device_register import TikTokDeviceRegister, _build_common_params_v2
from .signing_engine import sign as _sign
from .login_client import TikTokLoginClient, encode_password, _proxy_line_to_url


def warmup_device(profile_path: str, proxy: str = None, verbose: bool = False) -> dict:
    """
    Post-registration warm-up: makes initial API calls to acquire session cookies
    (msToken, store-country-sign) that TikTok expects in subsequent requests.

    This simulates the real app's first-launch behavior:
      1. GET /get_domains/v5/ — domain resolution (triggers msToken set-cookie)
      2. Updates the profile JSON with new cookies

    Returns the updated profile dict.
    """
    with open(profile_path, encoding="utf-8") as f:
        profile = json.load(f)

    ts = int(time.time())
    rticket = ts * 1000
    d = profile["device"]
    m = profile["meta"]
    a = profile["app"]
    loc = profile["locale"]

    # Build domain resolution URL (first request the app makes after registration)
    query = {
        "os": "android",
        "_rticket": str(rticket),
        "device_id": d["device_id"],
        "iid": d["iid"],
        "aid": a["aid"],
        "app_name": a["app_name"],
        "version_code": m["version_code"],
        "version_name": m["version"],
        "manifest_version_code": m["manifest_version_code"],
        "update_version_code": m["update_version_code"],
        "device_platform": "android",
        "device_type": d["device_type"],
        "device_brand": d["device_brand"],
        "os_version": d["os_version"],
        "os_api": d["os_api"],
        "resolution": d["resolution"],
        "dpi": d["dpi"],
        "language": loc.get("language", "en"),
        "ts": str(ts),
    }

    url = "https://api16-core-useast5.tiktokv.us/get_domains/v5/?" + urllib.parse.urlencode(query)

    cookie = profile["session"]["cookie"]
    sig = _sign(url=url, method="GET", body=b"", cookie=cookie, ts=ts)

    region = loc.get("region", loc.get("sys_region", "US"))
    headers = {
        "User-Agent": profile["user_agent"],
        "Accept-Encoding": "gzip, deflate, br",
        "Cookie": cookie,
        "X-Argus": sig["X-Argus"],
        "X-Gorgon": sig["X-Gorgon"],
        "X-Khronos": str(sig["X-Khronos"]),
        "X-Ladon": sig["X-Ladon"],
        "x-tt-pba-enable": "1",
        "x-tt-dm-status": "login=0;ct=1;rt=6",
        "X-SS-REQ-TICKET": str(rticket),
        "sdk-version": "2",
        "passport-sdk-version": "1",
        "oec-cs-sdk-version": "v10.02.02.01-bugfix-ov-android_V31",
        "x-vc-bdturing-sdk-version": "2.4.1.i18n",
        "x-tt-store-region": region.lower(),
        "x-tt-store-region-src": "did",
        "x-tt-ttnet-origin-host": "api16-core-useast5.tiktokv.us",
        "x-ss-dp": a["aid"],
        "x-common-params-v2": _build_common_params_v2(profile),
        "x-tt-trace-id": f"00-{format(ts, '08x')}1069b5d83f35b0060ea904d1-{format(ts, '08x')}1069b5d8-01",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        _open = opener.open
    else:
        _open = lambda *a, **kw: urllib.request.urlopen(*a, context=ctx, **kw)

    req = urllib.request.Request(url, headers=headers, method="GET")
    new_cookies = {}
    try:
        resp = _open(req, timeout=15)
        # Extract Set-Cookie headers
        for hdr in resp.headers.get_all("Set-Cookie") or []:
            parts = hdr.split(";")[0].strip()
            if "=" in parts:
                k, v = parts.split("=", 1)
                new_cookies[k.strip()] = v.strip()

        body = resp.read()
        if body[:2] == b"\x1f\x8b":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        if verbose:
            print(f"[warmup] GET /get_domains/v5/ → {resp.status}")
            print(f"[warmup] New cookies: {list(new_cookies.keys())}")
    except Exception as e:
        print(f"[warmup] Domain resolution request failed: {e}")
        return profile

    # Merge new cookies into profile
    if new_cookies:
        existing = profile["session"]["cookie"]
        existing_dict = {}
        for part in existing.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                existing_dict[k.strip()] = v.strip()
        existing_dict.update(new_cookies)
        profile["session"]["cookie"] = "; ".join(f"{k}={v}" for k, v in existing_dict.items())

        # Save updated profile
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False)
        if verbose:
            print(f"[warmup] Updated profile cookies → {profile_path}")

    return profile


import urllib.parse


def run_flow(
    username: str,
    password_hex: str,
    device_path: str = None,
    skip_register: bool = False,
    proxy: str = None,
    verbose: bool = False,
    save_device: str = None,
    allow_local_fallback: bool = False,
    region_id_source: str | None = None,
) -> dict:
    """
    Full end-to-end flow:
      1. Register new device (unless --skip-register or --device given)
      2. Login (3 steps)

    Returns:
        dict with keys: device_profile, login_result, success
    """

    # ── Step A: Device ────────────────────────────────────────────────────────
    if device_path:
        print(f"[flow] Using existing device: {device_path}")
        profile_path = device_path
    elif skip_register:
        print("[flow] Using default device (skip-register)")
        profile_path = os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
    else:
        print("[flow] Registering new device ...")
        dr = TikTokDeviceRegister(
            proxy=proxy,
            verbose=verbose,
            allow_local_fallback=allow_local_fallback,
        )
        try:
            reg = dr.register()
        except RuntimeError as e:
            print(f"[flow] Device registration failed: {e}", file=sys.stderr)
            sys.exit(1)
        ts      = int(time.time())
        out     = save_device or os.path.join(PROJECT_ROOT, f"device_{ts}.json")
        profile = dr.build_profile(reg, out)
        profile_path = out
        print(f"[flow] New device → {out}")
        print(f"       device_id  : {reg['device_id']}")
        print(f"       install_id : {reg['install_id']}")
        if reg.get("server_resp"):
            print("       ids source : TikTok server (non-zero device_id)")
        else:
            print("       ids source : local only (--allow-local-fallback; not server-registered)")

        # ── Step A.2: Warm-up (fetch initial cookies) ─────────────────────────
        print("\n[flow] Warming up device (fetching session cookies) ...")
        warmup_device(profile_path, proxy=proxy, verbose=verbose)

    # ── Step B: Login ─────────────────────────────────────────────────────────
    print(f"\n[flow] Logging in as '{username}' ...")
    client = TikTokLoginClient(device_path=profile_path, proxy=proxy, verbose=verbose)

    def _cli_captcha_solver(captcha_data):
        """Interactive captcha prompt — user must solve manually or pass --captcha-edata."""
        print("\n[!] CAPTCHA REQUIRED (error_code 1105)")
        print(f"    captcha_data keys: {list(captcha_data.keys())}")
        print("    Pass solved edata via idv_code_provider or handle programmatically.")
        return None  # Signal failure; caller should provide captcha_solver callback

    def _cli_idv_code_provider(verify_ticket, pseudo_id, extra_info):
        """Interactive IDV prompt — reads verification code from stdin."""
        print(f"\n[!] IDV/2FA REQUIRED (error_code 2135)")
        print(f"    pseudo_id     : {pseudo_id}")
        print(f"    verify_ticket : {str(verify_ticket)[:40]}...")
        print(f"    Check email/phone for verification code.")
        try:
            code = input("    Enter verification code: ").strip()
            return code if code else None
        except (EOFError, KeyboardInterrupt):
            return None

    result = client.login(
        username, password_hex,
        region_id_source=region_id_source,
        captcha_solver=_cli_captcha_solver,
        idv_code_provider=_cli_idv_code_provider,
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    if result["success"]:
        data = result.get("step3", {}).get("data", {})
        print("LOGIN SUCCESS")
        print(f"  uid        : {result.get('uid') or data.get('uid', '?')}")
        print(f"  session_key: {str(result.get('session_key') or data.get('session_key', '?'))[:40]}...")
        print(f"  cookie     : {client._cookie[:100]}...")
    else:
        err = result.get("error", "?")
        step3 = result.get("step3", {})
        ec    = step3.get("data", {}).get("error_code") if step3 else "?"
        desc  = step3.get("data", {}).get("description", step3.get("message", "?")) if step3 else "?"
        print("LOGIN FAILED")
        print(f"  error      : {err}")
        if ec and ec != "?":
            print(f"  error_code : {ec}")
            print(f"  description: {desc}")
        if result.get("passport_ticket"):
            print(f"  Captcha/IDV info saved in result dict — use programmatic API to handle")

    return {
        "device_path":   profile_path,
        "login_result":  result,
        "success":       result["success"],
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TikTok v44.3.15 — Full Flow (register device + login, captcha+IDV handled)"
    )
    parser.add_argument("--username",       required=True,
                        help="TikTok username")
    parser.add_argument("--password",       default="",
                        help="Plain text password (will be hex-encoded)")
    parser.add_argument("--password-hex",   default="",
                        help="Pre-encoded hex password")
    parser.add_argument("--device",         default=None,
                        help="Use existing device JSON (skips registration)")
    parser.add_argument("--skip-register",  action="store_true",
                        help="Use default device_v44_3_1.json (skip registration)")
    parser.add_argument("--save-device",    default=None,
                        help="Path to save new device JSON (default: device_<ts>.json)")
    parser.add_argument("--proxy",          default=None,
                        help="HTTP proxy e.g. http://user:pass@host:port")
    parser.add_argument("--proxy-file",   default=None,
                        help="First host:port:user:pass line → --proxy (register + login)")
    parser.add_argument("--verbose",        action="store_true",
                        help="Print full request/response")
    parser.add_argument("--region-email",   default="",
                        help="Email for /passport/app/region/ hashed_id; else device_id")
    parser.add_argument(
        "--allow-local-fallback",
        action="store_true",
        help="If TikTok returns only 0 for device_id, continue with random local IDs (not server-registered)",
    )
    args = parser.parse_args()

    proxy_url = args.proxy
    if args.proxy_file:
        ppath = args.proxy_file if os.path.isabs(args.proxy_file) else os.path.join(PROJECT_ROOT, args.proxy_file)
        with open(ppath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                proxy_url = _proxy_line_to_url(line)
                if proxy_url:
                    break
        if not proxy_url:
            parser.error(f"No valid proxy line in {ppath}")

    if args.password:
        pw_hex = encode_password(args.password)
        print(f"[flow] Password encoded: {pw_hex}")
    elif getattr(args, "password_hex", ""):
        pw_hex = args.password_hex
    else:
        parser.error("Provide --password or --password-hex")

    reg_src = (getattr(args, "region_email", "") or "").strip() or None
    run_flow(
        username=args.username,
        password_hex=pw_hex,
        device_path=args.device,
        skip_register=args.skip_register,
        proxy=proxy_url,
        verbose=args.verbose,
        save_device=args.save_device,
        allow_local_fallback=args.allow_local_fallback,
        region_id_source=reg_src,
    )
