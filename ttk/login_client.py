#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
login_client.py — TikTok v44.3.15 Login Client

Implements the complete 15-step login flow captured from real device traffic (2026-03-23):

  Step 1  (GET):  /passport/user/check_login_name_registered  → username exists?
  Step 2  (POST): /passport/user/login/pre_check              → pre-login validation
  Step 3  (POST): /passport/user/login                        → first attempt (→ 1105 captcha)
  Step 4  (GET):  /captcha/get                                → fetch captcha challenge
  Step 5  (POST): /captcha/verify                             → submit captcha solution
  Step 6  (POST): /passport/user/login                        → second attempt (→ 2135 IDV)
  Step 7  (POST): /passport/aaas/authenticate/ action=3       → request email code
  Step 8  (POST): /passport/aaas/authenticate/ action=4       → submit email code
  Step 9  (POST): /passport/user/login                        → final attempt (SUCCESS)
  Step 10 (POST): /passport/app/auth_broadcast/               → notify login success

Error codes: 1105 = captcha required, 2135 = IDV/2FA required, 0 = success.
Body field encoding (username/password/OTP): XOR 0x05 per char → hex (v44.3.15); xor_key=0x17 for older builds.

All request parameters, headers, and signing are 100% based on captured traffic.
Uses signing_engine.py (same directory) — no other dependencies.

Usage:
    python3 login_client.py --username myuser --password-hex 4576716a...
    python3 login_client.py --username myuser --step1          # check username only
    python3 login_client.py --username myuser --step2          # pre_check only
    python3 login_client.py --username u --step1 --devices-batch devices_001.json
    python3 login_client.py --username u --step1 --sign-backend rapidapi --rapidapi-key "$RAPIDAPI_KEY"
    # أو: export TIKTOK_SIGN_BACKEND=rapidapi && export RAPIDAPI_KEY=...
    python3 login_client.py --username u --step1 --no-proxy   # تجاهل proxsy.txt ومتغيرات البروكسي
    # 10 أجهزة + بروكسي مختلف لكل صف + ملف مراجعة JSON:
    python3 login_client.py --username u --step1 --devices-batch devices_001.json \\
        --batch-limit 10 --proxy-rotate-file proxsy.txt --batch-summary-out batch_step1.json
"""

import argparse
import base64
import copy
import json
import os
import re
import secrets
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error

try:
    import requests as _requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .paths import FIXTURES_DIR, PROJECT_ROOT, resolve_data_path
from .signing_engine import sign as _sign_engine

try:
    from .rapidapi_signer import dev_info_from_profile as _rapidapi_dev_info_from_profile
    from .rapidapi_signer import sign_via_rapidapi as _sign_via_rapidapi
    _HAS_RAPIDAPI_SIGNER = True
except ImportError:
    _rapidapi_dev_info_from_profile = None  # type: ignore
    _sign_via_rapidapi = None  # type: ignore
    _HAS_RAPIDAPI_SIGNER = False

try:
    from .device_guard import _HAS_CRYPTO as _GUARD_HAS_CRYPTO
    from .device_guard import build_guard_headers as _build_guard_headers
    _HAS_GUARD = True
except ImportError:
    _HAS_GUARD = False
    _GUARD_HAS_CRYPTO = False
    _build_guard_headers = None  # type: ignore

try:
    from .device_guard import get_public_key_header as _get_public_key_header
except ImportError:
    _get_public_key_header = None


# ── Load device profile ───────────────────────────────────────────────────────

def _load_device(path: str = None) -> dict:
    if path is None:
        path = os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def merge_devices_batch_record_into_profile(base: dict, record: dict) -> dict:
    """
    Build a login ``device`` profile from ``device_v44_3_1``-style JSON + one
    ``devices_001.json`` entry (``.devices[].record``).

    Patches ``device_id``, ``iid``, ``openudid``, ``session.last_install_time``,
    and ``install_id`` inside ``session.cookie`` when present.

    Note: ``guard_keys`` stay from ``base`` unless you registered those devices
    with the same EC key; mismatch → risk errors (e.g. 31).
    """
    prof = copy.deepcopy(base)
    rr = record.get("register_response") or {}
    did = str(record.get("device_id_str") or rr.get("device_id_str") or "").strip()
    iid = str(record.get("install_id_str") or rr.get("install_id_str") or "").strip()
    inp = record.get("input") or {}
    ou = str(inp.get("openudid") or "").strip()
    d = prof.setdefault("device", {})
    if did:
        d["device_id"] = did
    if iid:
        d["iid"] = iid
    if ou:
        d["openudid"] = ou
    st = record.get("server_time")
    if st is None:
        st = rr.get("server_time")
    if st is not None:
        prof.setdefault("session", {})["last_install_time"] = str(int(st))
    ck = prof.get("session", {}).get("cookie", "")
    if iid and ck:
        if re.search(r"install_id=\d+", ck):
            ck = re.sub(r"install_id=\d+", f"install_id={iid}", ck, count=1)
        elif "install_id=" not in ck:
            ck = ck.rstrip().rstrip(";") + f"; install_id={iid}"
        prof["session"]["cookie"] = ck
    return prof


def _x_tt_trace_id() -> str:
    """Per-request trace id (same shape as TikTok Android)."""
    h = secrets.token_hex(24)
    return f"00-{h[:32]}-{h[32:48]}-01"


def _proxy_line_to_url(line: str):
    """
    host:port:user:pass → http://user:pass@host:port (user/pass URL-encoded).

    Geonode-style users contain ':' (e.g. ...-session-abc:uuid) — only the last
    segment after the *third* colon is the password.
    """
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 4:
        return None
    host, port = parts[0], parts[1]
    password = parts[-1]
    user = ":".join(parts[2:-1])
    u = urllib.parse.quote(user, safe="")
    p = urllib.parse.quote(password, safe="")
    return f"http://{u}:{p}@{host}:{port}"


def _first_proxy_url_from_file(path: str) -> str | None:
    """First non-empty, non-comment ``host:port:user:pass`` line → ``http://...`` URL."""
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = _proxy_line_to_url(line)
            if u:
                return u
    return None


def _all_proxy_urls_from_file(path: str) -> list[str]:
    """Every valid ``host:port:user:pass`` line → ``http://...`` URL (order preserved)."""
    if not path or not os.path.isfile(path):
        return []
    out: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = _proxy_line_to_url(line)
            if u:
                out.append(u)
    return out


def _batch_is_transport_failure(exc: BaseException) -> bool:
    """Proxy tunnel / timeout / connection errors — batch should continue, not abort."""
    if _HAS_REQUESTS and isinstance(
        exc,
        (
            _requests.exceptions.ProxyError,
            _requests.exceptions.ConnectTimeout,
            _requests.exceptions.ReadTimeout,
            _requests.exceptions.ConnectionError,
        ),
    ):
        return True
    if isinstance(exc, RuntimeError):
        s = str(exc).lower()
        if "proxyerror" in s.replace(" ", "") or "tunnel" in s or "562" in s:
            return True
        if "proxy" in s and ("tiktok" in s or "max retries" in s or "connection" in s):
            return True
    if isinstance(exc, OSError):
        s = str(exc).lower()
        if "tunnel" in s or "proxy" in s:
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# TikTokLoginClient
# ══════════════════════════════════════════════════════════════════════════════

class TikTokLoginClient:
    """
    TikTok v44.3.15 Login Client.

    Replicates the complete 15-step login flow observed in captured traffic.
    Automatically handles captcha (1105) and IDV/2FA (2135) via optional callbacks.
    Merges Set-Cookie headers after every response to keep self._cookie current.

    Parameters:
        device_path  : path to device profile JSON (default: device_v44_3_1.json)
        proxy        : optional proxy URL e.g. "http://127.0.0.1:8888"
        verbose      : print request/response details
    """

    # Hosts used in login flow (from captures)
    _HOST_LOGIN    = "api16-normal-c-alisg.tiktokv.com"
    _HOST_CHECK    = "aggr16-normal.tiktokv.us"

    # Query key order for /captcha/get and /captcha/verify (Raw_03-16 captcha_get)
    _CAPTCHA_QUERY_KEYS = (
        "lang", "app_name", "h5_sdk_version", "h5_sdk_use_type", "sdk_version",
        "iid", "did", "device_id", "ch", "aid", "os_type", "mode", "tmp",
        "platform", "webdriver", "enable_image", "verify_host", "locale", "channel",
        "app_key", "vc", "app_version", "session_id", "region", "userMode",
        "use_native_report", "use_jsb_request", "orientation", "resolution",
        "os_version", "device_brand", "device_model", "os_name", "version_code",
        "device_type", "device_platform", "store_region", "imagex_domain", "subtype",
        "challenge_code", "verify_id", "triggered_region", "cookie_enabled",
        "screen_width", "screen_height", "browser_language", "browser_platform",
        "browser_name", "browser_version", "mobile_container",
    )

    def __init__(
        self,
        device_path: str = None,
        proxy: str = None,
        verbose: bool = False,
        sign_backend: str | None = None,
        rapidapi_key: str | None = None,
    ):
        if device_path is not None:
            dp = resolve_data_path(device_path)
        else:
            dp = os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
        self._device_path = os.path.abspath(dp)
        self.dev                  = _load_device(dp)
        self.proxy                = proxy
        self.verbose              = verbose
        self._cookie              = self.dev["session"]["cookie"]
        self._device_redirect_info = ""   # populated by step_app_region()
        self._captcha_domain       = ""   # host only, from app/region or overrides
        self._captcha_last        = {}    # tmp_ms + merged hints for verify after get

        sb = (sign_backend or os.environ.get("TIKTOK_SIGN_BACKEND") or "local").strip().lower()
        if sb not in ("local", "rapidapi"):
            sb = "local"
        self._sign_backend = sb
        self._rapidapi_key = (rapidapi_key or "").strip() or None
        self._rapidapi_dev_info: dict = {}
        if self._sign_backend == "rapidapi":
            if not _HAS_RAPIDAPI_SIGNER or not _sign_via_rapidapi or not _rapidapi_dev_info_from_profile:
                raise RuntimeError("RapidAPI signing requested but rapidapi_signer.py is missing")
            self._rapidapi_dev_info = _rapidapi_dev_info_from_profile(self.dev)
            if self.verbose:
                print("[*] Signing via RapidAPI /android/get_sign (live x-argus/x-gorgon/…)", flush=True)

        self._validate_guard_public_key_parity()

    def _validate_guard_public_key_parity(self) -> None:
        """
        ``tt_ticket_guard_public_key`` must equal the X962-uncompressed base64 of
        ``guard_keys.public_pem`` (same bytes the server associates with device_register).
        """
        if not _get_public_key_header:
            return
        gk = self.dev.get("guard_keys") or {}
        pub_pem = (gk.get("public_pem") or "").strip()
        stored = (gk.get("tt_ticket_guard_public_key") or "").strip()
        if not pub_pem or not stored:
            return
        try:
            derived = _get_public_key_header(pub_pem)
        except Exception:
            return
        if derived and stored != derived:
            msg = (
                "guard_keys.tt_ticket_guard_public_key does not match public_pem "
                f"(derived prefix {derived[:20]}… vs stored {stored[:20]}…). "
                "Fix the profile so the header matches the registered EC key."
            )
            print(f"[login_client] WARNING: {msg}", file=sys.stderr, flush=True)
            if self.verbose:
                print(f"  [!] {msg}", flush=True)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _ttnet_origin_host(self, url: str) -> str:
        """
        Map request host → x-tt-ttnet-origin-host (MITM: aggr16 varies by tt-target-idc).

        Raw [841] useast8 → api16-normal-useast8; Raw [193] useast5 cookie → useast5.
        """
        host = urllib.parse.urlparse(url).netloc
        if "alisg" in host:
            return "api16-normal-c-alisg.tiktokv.com"
        idc = ""
        for seg in (self._cookie or "").split(";"):
            seg = seg.strip()
            if seg.startswith("tt-target-idc="):
                idc = seg.split("=", 1)[1].strip().lower()
                break
        if "useast5" in host and "aggr16" not in host:
            return "api16-normal-useast5.tiktokv.us"
        if "aggr16" in host or "useast8" in host:
            if idc == "useast5":
                return "api16-normal-useast5.tiktokv.us"
            return "api16-normal-useast8.tiktokv.us"
        return host

    def _cookie_passport_minimal(self) -> str:
        """Match capture [2820]: only store-idc + tt-target-idc (no msToken) for POST."""
        out = []
        for seg in (self._cookie or "").split(";"):
            seg = seg.strip()
            if seg.startswith("store-idc=") or seg.startswith("tt-target-idc="):
                out.append(seg)
        if len(out) >= 2:
            return "; ".join(out)
        return "store-idc=useast5; tt-target-idc=useast5"

    def _cookie_for_passport_request(self) -> str:
        """
        Passport POSTs after pre_check / 2135: store-idc + tt-target-idc + msToken + d_ticket
        when present (matches v44.3.15 MITM captures — X-SS-STUB / Gorgon use this Cookie).
        """
        want_order = ("store-idc", "tt-target-idc", "msToken", "d_ticket")
        found: dict[str, str] = {}
        for seg in (self._cookie or "").split(";"):
            seg = seg.strip()
            if "=" not in seg:
                continue
            k, v = seg.split("=", 1)
            k = k.strip()
            if k in want_order:
                found[k] = v.strip()
        parts = [f"{k}={found[k]}" for k in want_order if k in found]
        if "store-idc" in found and "tt-target-idc" in found:
            return "; ".join(parts)
        return self._cookie_passport_minimal()

    def _base_params(self, ts: int, rticket: int = None,
                     include_device_redirect: bool = False,
                     rticket_extra: int = 0) -> dict:
        """
        Build the common query parameters used in every login request.
        Matches capture [849]/[965]/[1534]: complete param set in exact order.
        rticket is the millisecond timestamp at request start (defaults to ts*1000).
        """
        d   = self.dev["device"]
        a   = self.dev["app"]
        n   = self.dev["network"]
        loc = self.dev["locale"]
        m   = self.dev["meta"]
        if rticket is None:
            rticket = ts * 1000 + int(rticket_extra or 0)
        params = {
            "passport-sdk-version":   "1",
            "device_platform":        "android",
            "os":                     "android",
            "ssmix":                  a["ssmix"],
            "_rticket":               str(rticket),
        }
        if d.get("cdid"):
            params["cdid"] = d["cdid"]
        if d.get("openudid"):
            params["openudid"] = d["openudid"]
        params.update({
            "channel":                a["channel"],
            "aid":                    a["aid"],
            "app_name":               a["app_name"],
            "version_code":           m["version_code"],
            "version_name":           m["version"],
            "manifest_version_code":  m["manifest_version_code"],
            "update_version_code":    m["update_version_code"],
            "ab_version":             m["version"],
            "resolution":             d["resolution"],
            "dpi":                    d["dpi"],
            "device_type":            d["device_type"],
            "device_brand":           d["device_brand"],
            "language":               loc["language"],
            "os_api":                 d["os_api"],
            "os_version":             d["os_version"],
            "ac":                     n["ac"],
            "is_pad":                 d["is_pad"],
            "current_region":         loc.get("region", loc["sys_region"]),
            "app_type":               a["app_type"],
            "sys_region":             loc["sys_region"],
            "last_install_time":      self.dev["session"]["last_install_time"],
            "mcc_mnc":                n["mcc_mnc"],
            "timezone_name":          loc["timezone_name"].replace("/", "%2F"),
            "carrier_region_v2":      n["carrier_region_v2"],
            "residence":              loc.get("region", loc["sys_region"]),
            "app_language":           loc["app_language"],
            "carrier_region":         n["carrier_region"],
            "timezone_offset":        loc["timezone_offset"],
            "host_abi":               d["host_abi"],
            "locale":                 loc["locale"],
            "ac2":                    n["ac2"],
            "uoo":                    loc["uoo"],
            "op_region":              loc["op_region"],
            "build_number":           m["version"],
            "region":                 loc.get("region", loc["sys_region"]),
            "ts":                     str(ts),
            "iid":                    d["iid"],
            "device_id":              d["device_id"],
            "support_webview":        a["support_webview"],
        })
        if include_device_redirect:
            # Use server-issued device_redirect_info if available (from step_app_region)
            params["device_redirect_info"] = (
                self._device_redirect_info or secrets.token_urlsafe(64)
            )
        return params

    def _build_url(self, host: str, path: str, params: dict) -> str:
        """Build full URL — timezone_name is already percent-encoded, don't double-encode."""
        parts = []
        for k, v in params.items():
            if k == "timezone_name":
                parts.append(f"{k}={v}")
            else:
                parts.append(f"{k}={urllib.parse.quote(str(v), safe='*@')}")
        qs = "&".join(parts)
        return f"https://{host}{path}?{qs}"

    def _sign_and_build_headers(
        self,
        url: str,
        method: str,
        body: str | bytes = "",
        cookie: str = None,
        login_state: int = 0,
        content_type: str | None = None,
    ) -> dict:
        """
        Generate complete header set matching real TikTok traffic (capture 2026-03-23).

        - ``x-tt-bypass-dp``: only on non-GET (Raw [841] check_login GET omits it; [849]/[965] POST include it).
        - ``x-common-params-v2``: same compact param blob as feed/device_register (Raw e.g. [147]).
        login_state: 0 = pre-login, 1 = post-login (changes x-tt-dm-status).
        """
        ck = cookie if cookie is not None else self._cookie
        if getattr(self, "_sign_backend", "local") == "rapidapi":
            sig = _sign_via_rapidapi(
                url=url,
                method=method,
                body=body,
                cookie=ck,
                dev_info=self._rapidapi_dev_info,
                api_key=self._rapidapi_key,
            )
        else:
            sig = _sign_engine(url=url, method=method, body=body, cookie=ck)
        method_u = (method or "GET").upper()

        # Extract _rticket from URL for X-SS-REQ-TICKET (matches capture exactly)
        qs = urllib.parse.urlparse(url).query
        rticket_val = urllib.parse.parse_qs(qs).get("_rticket", [None])[0]

        dm_status = f"login={login_state};ct=1;rt=6"
        ph = self.dev.get("passport_headers") or {}
        if login_state == 0 and ph.get("x-tt-dm-status"):
            dm_status = ph["x-tt-dm-status"]

        headers = {
            # Standard
            "User-Agent":      self.dev["user_agent"],
            "Cookie":          ck,
            "Connection":      "keep-alive",
            "Accept-Encoding": "gzip, deflate, br",

            # Signing
            "X-Argus":  sig["X-Argus"],
            "X-Gorgon": sig["X-Gorgon"],
            "X-Khronos": str(sig["X-Khronos"]),
            "X-Ladon":  sig["X-Ladon"],

            # Required TikTok headers (from capture [849]/[965])
            "x-tt-pba-enable":            "1",
            "x-tt-dm-status":             dm_status,
            "sdk-version":                "2",
            "passport-sdk-settings":      "x-tt-token",
            "passport-sdk-sign":          "x-tt-token",
            "passport-sdk-version":       "1",
            "oec-cs-si-a":                "2",
            "oec-cs-sdk-version":         "v10.02.02.01-bugfix-ov-android_V31",
            "x-vc-bdturing-sdk-version":  "2.4.1.i18n",
            "oec-vc-sdk-version":         "3.2.1.i18n",
            "rpc-persist-pns-region-1":   "US|6252001",
            "rpc-persist-pns-region-2":   "US|6252001",
            "rpc-persist-pns-region-3":   "US|6252001",
            "x-tt-request-tag":           "n=0;nr=0;bg=0;s=-1;p=0",
            "x-tt-trace-id":              _x_tt_trace_id(),

            # Routing headers (from capture [841] — required by aggr16/useast hosts)
            "X-SS-DP":                    self.dev["app"]["aid"],
            "x-tt-store-region":          self.dev["locale"].get("region", "US").lower(),
            "x-tt-store-region-src":      "did",
            "rpc-persist-pyxis-policy-state-law-is-ca": "0",
            "rpc-persist-pyxis-policy-v-tnc": "1",
            "x-tt-ttnet-origin-host":     self._ttnet_origin_host(url),
        }

        if method_u != "GET":
            headers["x-tt-bypass-dp"] = "1"

        try:
            from device_register import _build_common_params_v2

            headers["x-common-params-v2"] = _build_common_params_v2(self.dev)
        except Exception as e:
            if self.verbose:
                print(f"  [!] x-common-params-v2 omitted: {e}", flush=True)

        if rticket_val:
            headers["X-SS-REQ-TICKET"] = rticket_val

        if sig.get("X-SS-STUB"):
            headers["X-SS-STUB"] = sig["X-SS-STUB"]

        if method_u != "GET":
            if content_type:
                headers["Content-Type"] = content_type
            elif isinstance(body, (bytes, bytearray)):
                headers["Content-Type"] = "application/octet-stream"
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        # Guard headers — dynamic ECDSA signing if private key is in profile
        guard_keys = self.dev.get("guard_keys") or {}
        private_pem = guard_keys.get("private_pem", "")
        public_key_b64 = guard_keys.get("tt_ticket_guard_public_key", "") or \
                         (self.dev.get("guard_headers") or {}).get("tt-ticket-guard-public-key", "")

        if (
            _HAS_GUARD
            and _build_guard_headers
            and _GUARD_HAS_CRYPTO
            and private_pem
            and public_key_b64
        ):
            # Compute guard headers dynamically per-request (needs cryptography)
            path = urllib.parse.urlparse(url).path
            guard_hdrs = _build_guard_headers(
                profile=self.dev,
                path=path,
                private_pem=private_pem,
                public_key_b64=public_key_b64,
                login_state=login_state,
                ts=int(qs_ts) if (qs_ts := urllib.parse.parse_qs(
                    urllib.parse.urlparse(url).query
                ).get("ts", [None])[0]) else None,
            )
            headers.update(guard_hdrs)
        else:
            # Fallback: static values from profile (old behavior)
            guard_static = self.dev.get("guard_headers") or {}
            for k, v in guard_static.items():
                if v and k not in (
                    "sdk-version", "passport-sdk-settings", "passport-sdk-sign",
                    "passport-sdk-version", "x-tt-bypass-dp", "x-vc-bdturing-sdk-version"
                ):
                    headers[k] = v

        # Post-login: add X-Tt-Token, x-bd-kmsv, change dm-status
        if login_state == 1:
            tt_token = self.dev.get("session", {}).get("x_tt_token", "")
            if tt_token:
                headers["X-Tt-Token"] = tt_token
            headers["x-bd-kmsv"] = "0"

        return headers

    def _http(
        self,
        url: str,
        method: str,
        body: str | bytes = "",
        cookie: str = None,
        login_state: int = 0,
        extra_headers: dict = None,
        content_type: str | None = None,
        parse_json: bool = True,
    ) -> dict:
        """
        Execute the HTTP request, merge Set-Cookie headers into self._cookie,
        and return parsed JSON (or ``{_raw_b64,_raw_len}`` when parse_json=False).
        """
        headers = self._sign_and_build_headers(
            url, method, body,
            cookie=cookie,
            login_state=login_state,
            content_type=content_type,
        )
        if extra_headers:
            headers.update(extra_headers)

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"{method} {url}")
            for k, v in headers.items():
                print(f"  {k}: {v[:80]}{'...' if len(v) > 80 else ''}")
            if body:
                if isinstance(body, (bytes, bytearray)):
                    print(f"  Body: <{len(body)} bytes binary>")
                else:
                    print(f"  Body: {body}")

        method_u = (method or "GET").upper()
        if method_u == "GET":
            body_bytes = None
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        else:
            body_bytes = (body or "").encode("utf-8")
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        d_ticket_hdr = None
        set_cookies = []

        if _HAS_REQUESTS:
            # Use requests — handles proxy auth, auto-decompresses gzip/deflate
            try:
                resp = _requests.request(
                    method, url,
                    headers=headers,
                    data=body_bytes,
                    proxies=proxies,
                    verify=False,
                    timeout=45,
                    allow_redirects=True,
                )
            except _requests.exceptions.ProxyError as e:
                extra = ""
                if self.proxy:
                    extra = (
                        " TikTok requests use this HTTP proxy; RapidAPI signing does not. "
                        "Retry with --no-proxy or fix/replace the proxy line (e.g. tunnel 562)."
                    )
                raise RuntimeError(f"{e!s}.{extra}") from e
            # Raw Set-Cookie headers (multiple values preserved)
            raw_hdrs = resp.raw.headers
            set_cookies = raw_hdrs.getlist("Set-Cookie") if hasattr(raw_hdrs, "getlist") else []
            d_ticket_hdr = resp.headers.get("D-Ticket") or resp.headers.get("d-ticket")
            # Capture X-Tt-Token
            tt_token = resp.headers.get("X-Tt-Token") or resp.headers.get("x-tt-token") or ""
            if tt_token:
                self.dev.setdefault("session", {})["x_tt_token"] = tt_token
                if self.verbose:
                    print(f"  X-Tt-Token captured: {tt_token[:40]}...")
            raw = resp.content  # already decompressed by requests
        else:
            # Fallback: urllib (no proxy auth support for geonode-style proxies)
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method=method)
            for k, v in headers.items():
                req.add_header(k, v)
            if proxies:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler(proxies),
                    urllib.request.HTTPSHandler(context=ctx),
                )
                _open = opener.open
            else:
                _open = lambda *a, **kw: urllib.request.urlopen(*a, context=ctx, **kw)
            resp_h = None
            try:
                resp_raw = _open(req, data=body_bytes, timeout=45)
                resp_h = resp_raw
                raw = resp_raw.read()
                set_cookies = resp_raw.headers.get_all("Set-Cookie") if hasattr(resp_raw.headers, "get_all") else []
                tt_token = resp_raw.headers.get("X-Tt-Token") or ""
                if tt_token:
                    self.dev.setdefault("session", {})["x_tt_token"] = tt_token
            except urllib.error.HTTPError as e:
                resp_h = e
                raw = e.read()
                set_cookies = e.headers.get_all("Set-Cookie") if e.headers and hasattr(e.headers, "get_all") else []
            if resp_h is not None:
                h = resp_h.headers
                d_ticket_hdr = h.get("D-Ticket") or h.get("d-ticket")
            # Decompress manually for urllib
            if raw[:2] == b'\x1f\x8b':
                import gzip
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass

        # Merge Set-Cookie into self._cookie
        if set_cookies:
            self._merge_set_cookies({"Set-Cookie": set_cookies})
        if d_ticket_hdr:
            self._merge_cookie_pair("d_ticket", d_ticket_hdr.strip())

        if not parse_json:
            result = {
                "_raw_b64": base64.b64encode(raw).decode("ascii"),
                "_raw_len": len(raw),
            }
        else:
            try:
                result = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                result = {"_raw": raw.decode("utf-8", errors="replace")}

        if self.verbose:
            print(f"  Response: {json.dumps(result, indent=2, ensure_ascii=False)[:400]}")
            if set_cookies:
                print(f"  Cookies updated: {len(set_cookies)} Set-Cookie header(s)")

        return result

    # ── Step 1: Check Username ────────────────────────────────────────────────

    def step1_check_username(self, username: str) -> dict:
        """
        GET /passport/user/check_login_name_registered/
        Checks whether the username exists before login.

        Signing is **not** inlined here: ``_http()`` calls ``_sign_and_build_headers()``
        which adds X-Argus, X-Gorgon, X-Khronos, X-Ladon, x-common-params-v2, guard
        headers (tt-device-guard-*, tt-ticket-guard-*), etc. — same path as all passport
        requests (cf. MITM aggr16 e.g. Raw [193] / [841]).

        Returns:
            {"data": {"is_registered": true/false, ...}, "message": "success"}
        """
        ts = int(time.time())
        params = self._base_params(ts)

        # Extra params for this endpoint (from capture [2817])
        extra_params = {
            "login_name":           username,
            "scene":                "3",
            "multi_login":          "1",
            "account_sdk_source":   "app",
        }
        # Prepend extra params before base params (matching capture order)
        all_params = {**extra_params, **params}

        url = self._build_url(self._HOST_CHECK,
                              "/passport/user/check_login_name_registered/",
                              all_params)
        return self._http(url, "GET")

    # ── Step 2: Pre-check ────────────────────────────────────────────────────

    def step2_pre_check(self, username: str) -> dict:
        """
        POST /passport/user/login/pre_check/
        Pre-login validation. Returns {"data": {"login_page": "pwd"}} on success.
        Also sets msToken via Set-Cookie — caller should update self._cookie.
        Body: account_sdk_source=app&multi_login=1&mix_mode=1&username=<hex>
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket, include_device_redirect=True)
        url = self._build_url(self._HOST_LOGIN, "/passport/user/login/pre_check/", params)
        user_hex = encode_password(username)
        body = f"account_sdk_source=app&multi_login=1&mix_mode=1&username={user_hex}"
        return self._http(url, "POST", body, cookie=self._cookie_for_passport_request())

    # ── Step 3: Login attempt ─────────────────────────────────────────────────

    def step3_login(self, username: str, password_hex: str,
                    cookie: str = None) -> dict:
        """
        POST /passport/user/login/
        Authenticate. Returns error_code 0 (success), 1105 (captcha), or 2135 (IDV).
        Body: password=<hex>&account_sdk_source=app&multi_login=1&mix_mode=1&username=<hex>
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket, include_device_redirect=True)
        url = self._build_url(self._HOST_LOGIN, "/passport/user/login/", params)
        user_hex = encode_password(username)
        body = (
            f"password={password_hex}"
            f"&account_sdk_source=app"
            f"&multi_login=1"
            f"&mix_mode=1"
            f"&username={user_hex}"
        )
        ck = cookie if cookie is not None else self._cookie_for_passport_request()
        return self._http(url, "POST", body, cookie=ck)

    # ── Captcha helpers ───────────────────────────────────────────────────────

    def _cookie_with_mstoken(self, ms_token: str) -> str:
        """Build passport cookie with msToken appended."""
        base = self._cookie_passport_minimal()
        if ms_token:
            return base + f"; msToken={ms_token}"
        return base

    @staticmethod
    def _normalize_captcha_host(raw: str) -> str:
        if not raw:
            return ""
        h = str(raw).strip()
        for p in ("https://", "http://"):
            if h.startswith(p):
                h = h[len(p):]
        return h.split("/")[0].strip()

    def _captcha_hints_from_login_error(self, captcha_data: dict | None) -> dict[str, str]:
        """Fields from error_code=1105 JSON used to build captcha/get|verify URLs."""
        hints: dict[str, str] = {}
        cd = captcha_data or {}
        for key in (
            "verify_id", "verify_host", "challenge_code", "mode", "subtype",
            "region", "userMode", "triggered_region",
        ):
            v = cd.get(key)
            if v is not None and str(v) != "":
                hints[key] = str(v)
        desc = cd.get("verify_center_decision_conf") or cd.get("description")
        if isinstance(desc, str) and desc.strip().startswith("{"):
            try:
                j = json.loads(desc)
                if isinstance(j, dict):
                    for key in ("verify_id", "challenge_code"):
                        if j.get(key):
                            hints[key] = str(j[key])
                    for ex in j.get("extra") or []:
                        if isinstance(ex, dict) and ex.get("verify_id"):
                            hints["verify_id"] = str(ex["verify_id"])
            except Exception:
                pass
        return hints

    def _resolve_captcha_host(self, captcha_data: dict | None) -> str:
        if self._captcha_domain:
            return self._captcha_domain
        forced = (self.dev.get("captcha") or {}).get("host", "")
        if forced:
            return self._normalize_captcha_host(str(forced))
        hints = self._captcha_hints_from_login_error(captcha_data)
        if hints.get("verify_host"):
            return self._normalize_captcha_host(hints["verify_host"])
        return "rc-verification-sg.tiktokv.com"

    def _build_captcha_query_params(self, captcha_data: dict | None, tmp_ms: int) -> dict:
        hints = self._captcha_hints_from_login_error(captcha_data)
        co = (self.dev.get("captcha") or {}).get("query_overrides")
        if isinstance(co, dict):
            for k, v in co.items():
                if v is not None:
                    hints[str(k)] = str(v)

        d, a, m = self.dev["device"], self.dev["app"], self.dev["meta"]
        loc, n = self.dev["locale"], self.dev["network"]
        res = d.get("resolution", "1080*2340")
        rp = res.replace("*", "x").split("x")
        rw, rh = (rp + ["1080", "2340"])[:2]
        cap_cfg = self.dev.get("captcha") or {}
        sw = str(cap_cfg.get("screen_width", "412"))
        sh = str(cap_cfg.get("screen_height", "892"))
        host = self._resolve_captcha_host(captcha_data)
        verify_host = hints.get("verify_host") or f"https://{host}/"
        if not verify_host.endswith("/"):
            verify_host += "/"

        values: dict[str, str] = {
            "lang": loc.get("language", "en"),
            "app_name": a["app_name"],
            "h5_sdk_version": str(cap_cfg.get("h5_sdk_version", "2.34.12")),
            "h5_sdk_use_type": str(cap_cfg.get("h5_sdk_use_type", "goofy")),
            "sdk_version": str(cap_cfg.get("sdk_version", "2.4.1.i18n")),
            "iid": d["iid"],
            "did": d["device_id"],
            "device_id": d["device_id"],
            "ch": a["channel"],
            "aid": a["aid"],
            "os_type": "0",
            "mode": hints.get("mode", "slide"),
            "tmp": str(tmp_ms),
            "platform": "app",
            "webdriver": "false",
            "enable_image": "1",
            "verify_host": verify_host,
            "locale": loc.get("locale", "en"),
            "channel": a["channel"],
            "app_key": str(cap_cfg.get("app_key", "")),
            "vc": m["version"],
            "app_version": m["version"],
            "session_id": str(cap_cfg.get("session_id", "")),
            "region": hints.get("region", "ttp"),
            "userMode": hints.get("userMode", "258"),
            "use_native_report": "1",
            "use_jsb_request": "1",
            "orientation": str(cap_cfg.get("orientation", "2")),
            "resolution": f"{rw}*{rh}",
            "os_version": d["os_version"],
            "device_brand": d["device_brand"],
            "device_model": d["device_type"],
            "os_name": "Android",
            "version_code": m["version_code"],
            "device_type": d["device_type"],
            "device_platform": "Android",
            "store_region": loc.get("region", loc["sys_region"]).lower(),
            "imagex_domain": str(cap_cfg.get("imagex_domain", "")),
            "subtype": hints.get("subtype", "slide"),
            "challenge_code": hints.get("challenge_code", "99999"),
            "verify_id": hints.get("verify_id", ""),
            "triggered_region": hints.get("triggered_region", hints.get("region", "ttp")),
            "cookie_enabled": "true",
            "screen_width": sw,
            "screen_height": sh,
            "browser_language": loc.get("language", "en"),
            "browser_platform": str(cap_cfg.get("browser_platform", "Linux aarch64")),
            "browser_name": str(cap_cfg.get("browser_name", "Mozilla")),
            "browser_version": self.dev["user_agent"],
            "mobile_container": str(cap_cfg.get("mobile_container", "spark")),
        }
        return {k: values[k] for k in self._CAPTCHA_QUERY_KEYS if k in values}

    def step_captcha_get(self, captcha_data: dict | None = None) -> dict:
        """GET /captcha/get on captcha_domain (capture Step 7)."""
        tmp_ms = int(time.time() * 1000)
        self._captcha_last = {"tmp_ms": tmp_ms, "raw_captcha_data": dict(captcha_data or {})}
        params = self._build_captcha_query_params(captcha_data, tmp_ms)
        host = self._resolve_captcha_host(captcha_data)
        url = self._build_url(host, "/captcha/get", params)
        cap_ex = {
            "Accept": "application/json, text/plain, */*",
            "x-tt-request-tag": "n=1;nr=111;bg=0;t=0;s=-1;p=0",
        }
        return self._http(url, "GET", "", cookie=self._cookie, extra_headers=cap_ex)

    def step_captcha_verify(self, edata: str, captcha_data: dict | None = None) -> dict:
        """POST /captcha/verify with JSON ``{\"edata\": ...}`` (capture Step 8)."""
        st = self._captcha_last or {}
        tmp_ms = st.get("tmp_ms") or int(time.time() * 1000)
        base_cd = dict(st.get("raw_captcha_data") or {})
        if captcha_data:
            base_cd.update(captcha_data)
        params = self._build_captcha_query_params(base_cd, tmp_ms)
        host = self._resolve_captcha_host(base_cd)
        url = self._build_url(host, "/captcha/verify", params)
        body = json.dumps({"edata": edata}, separators=(",", ":"))
        cap_ex = {
            "Accept": "application/json, text/plain, */*",
            "x-tt-request-tag": "n=1;nr=111;bg=0;t=0;s=-1;p=0",
        }
        return self._http(
            url, "POST", body, cookie=self._cookie,
            content_type="application/json; charset=utf-8",
            extra_headers=cap_ex,
        )

    # ── AAAS authenticate (email/phone IDV) ───────────────────────────────────

    def step_aaas_request_code(self, passport_ticket: str, pseudo_id: str,
                                cookie: str = None) -> dict:
        """
        POST /passport/aaas/authenticate/ action=3
        Requests email/phone verification code.
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket, include_device_redirect=True)
        params["request_tag_from"] = "h5"
        params["challenge_type"] = "2"
        params["fixed_mix_mode"] = "0"
        params["skip_handler"] = "error_handler"
        params["pseudo_id"] = pseudo_id
        params["mix_mode"] = "0"
        params["passport_ticket"] = passport_ticket
        params["action"] = "3"
        url = self._build_url(self._HOST_LOGIN, "/passport/aaas/authenticate/", params)
        body = (
            f"mix_mode=0&pseudo_id={pseudo_id}&challenge_type=2&action=3"
            f"&passport_ticket={passport_ticket}&skip_handler=error_handler&fixed_mix_mode=0"
        )
        ck = cookie if cookie is not None else self._cookie
        aaas_headers = {
            "Accept": "application/json, text/plain, */*",
            "x-tt-referer": "https://inapp.tiktokv.com/ucenter_web/idv_core/verification",
        }
        return self._http(url, "POST", body, cookie=ck, extra_headers=aaas_headers)

    def step_aaas_submit_code(self, passport_ticket: str, pseudo_id: str,
                               code: str, cookie: str = None) -> dict:
        """
        POST /passport/aaas/authenticate/ action=4
        Submits email/phone verification code.
        code: plain text (will be hex-encoded with mix_mode=1).
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket, include_device_redirect=True)
        params["request_tag_from"] = "h5"
        params["challenge_type"] = "2"
        params["fixed_mix_mode"] = "1"
        params["skip_handler"] = "error_handler"
        params["pseudo_id"] = pseudo_id
        params["mix_mode"] = "1"
        params["passport_ticket"] = passport_ticket
        params["action"] = "4"
        url = self._build_url(self._HOST_LOGIN, "/passport/aaas/authenticate/", params)
        code_hex = encode_password(code)
        body = (
            f"mix_mode=1&code={code_hex}&pseudo_id={pseudo_id}&challenge_type=2&action=4"
            f"&passport_ticket={passport_ticket}&skip_handler=error_handler&fixed_mix_mode=1"
        )
        ck = cookie if cookie is not None else self._cookie
        aaas_headers = {
            "Accept": "application/json, text/plain, */*",
            "x-tt-referer": "https://inapp.tiktokv.com/ucenter_web/idv_core/verification",
        }
        return self._http(url, "POST", body, cookie=ck, extra_headers=aaas_headers)

    # ── Pre-login: get_nonce ──────────────────────────────────────────────────

    def step_get_nonce(self) -> dict:
        """
        POST /passport/auth/get_nonce/
        First step of real flow. Returns encryption nonce used for password.
        Body: platform=google  (captured from aggr16-normal.tiktokv.us [164])
        Sets msToken via Set-Cookie.
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket)
        url = self._build_url(self._HOST_CHECK, "/passport/auth/get_nonce/", params)
        return self._http(url, "POST", "platform=google", cookie=self._cookie)

    def step_sdi_get_token(self) -> dict:
        """
        POST /sdi/get_token — MSSDK token step (capture Step 2, before app/region).

        Body is **binary** (application/octet-stream). Provide it via device profile::

            "sdi": {
              "request_body_b64": "<base64>",
              "request_body_path": "optional/path.bin",
              "skip_if_no_body": true,
              "host": "aggr16-normal.tiktokv.us",
              "origin_host": "mssdk16-normal-useast8.tiktokv.us"
            }

        When ``skip_if_no_body`` is true (default) and no body is configured, the
        step is skipped so local login tests still run.
        """
        sdi = self.dev.get("sdi") or {}
        if sdi.get("disabled"):
            return {"skipped": True, "reason": "disabled"}

        body_b = b""
        if sdi.get("request_body_b64"):
            try:
                body_b = base64.b64decode(sdi["request_body_b64"])
            except Exception as e:
                return {"skipped": True, "reason": "invalid_request_body_b64", "error": str(e)}
        elif sdi.get("request_body_path"):
            rel = sdi["request_body_path"]
            p = rel if os.path.isabs(rel) else os.path.join(os.path.dirname(self._device_path), rel)
            if not os.path.isfile(p):
                return {"skipped": True, "reason": "request_body_path_missing", "path": p}
            with open(p, "rb") as f:
                body_b = f.read()
        elif sdi.get("skip_if_no_body", True):
            return {"skipped": True, "reason": "no_sdi_body_configure_sdi.request_body_b64"}

        d, a, m = self.dev["device"], self.dev["app"], self.dev["meta"]
        host = sdi.get("host", "aggr16-normal.tiktokv.us")
        origin = sdi.get("origin_host", "mssdk16-normal-useast8.tiktokv.us")
        ordered = [
            ("lc_id", sdi.get("lc_id", "2142840551")),
            ("platform", "android"),
            ("device_platform", "android"),
            ("sdk_ver", sdi.get("sdk_ver", "v05.02.05-alpha.5-ov-android")),
            ("sdk_ver_code", sdi.get("sdk_ver_code", "84018464")),
            ("app_ver", sdi.get("app_ver", m["version"])),
            ("version_code", sdi.get("version_code", m["manifest_version_code"])),
            ("aid", a["aid"]),
            ("sdkid", sdi.get("sdkid", "")),
            ("subaid", sdi.get("subaid", "")),
            ("iid", d["iid"]),
            ("did", d["device_id"]),
            ("bd_did", sdi.get("bd_did", "")),
            ("client_type", sdi.get("client_type", "inhouse")),
            ("region_type", sdi.get("region_type", "ov")),
            ("mode", sdi.get("mode", "2")),
        ]
        params = dict(ordered)
        url = self._build_url(host, "/sdi/get_token", params)
        extra = {
            "Accept": "*/*",
            "x-tt-ttnet-origin-host": origin,
            "x-tt-request-tag": "n=0;nr=111;bg=0;rs=100;t=0;s=-1;p=0",
        }
        return self._http(
            url, "POST", body_b, cookie=self._cookie,
            extra_headers=extra, parse_json=False,
        )

    # ── Pre-login: app/region ─────────────────────────────────────────────────

    def _region_hashed_id(self, region_id_source: str | None) -> str:
        """
        Body hashed_id for /passport/app/region/: SHA-256 of identifier.
        • Email login (type=3): hash of normalized email (strip + lower).
        • Otherwise: hash of device_id (guest / device-scoped region probe).
        """
        import hashlib
        if region_id_source and str(region_id_source).strip():
            raw = str(region_id_source).strip()
            if "@" in raw:
                raw = raw.lower()
            to_hash = raw
        else:
            to_hash = str(self.dev["device"]["device_id"])
        return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()

    def step_app_region(self, region_id_source: str | None = None) -> dict:
        """
        POST /passport/app/region/
        Returns login domain + device_redirect_info + captcha_domain.
        Body: hashed_id=<sha256(email|device_id)>&type=3
        Updates self._device_redirect_info and self._HOST_LOGIN if domain returned.
        """
        d = self.dev["device"]
        a = self.dev["app"]
        m = self.dev["meta"]
        loc = self.dev["locale"]
        n = self.dev["network"]
        params = {
            "device_platform": "android",
            "channel":         a["channel"],
            "aid":             a["aid"],
            "app_name":        a["app_name"],
            "version_code":    m["version_code"],
            "version_name":    m["version"],
            "sys_region":      loc["sys_region"],
            "carrier_region":  n["carrier_region"],
            "iid":             d["iid"],
            "device_id":       d["device_id"],
            "support_webview": a["support_webview"],
            "reg_store_region": loc.get("region", "us").lower(),
        }
        url = self._build_url(self._HOST_LOGIN, "/passport/app/region/", params)
        hashed_id = self._region_hashed_id(region_id_source)
        body = f"hashed_id={hashed_id}&type=3"
        # Minimal cookie for app/region (from capture: only tt-target-idc)
        minimal_ck = ""
        for seg in self._cookie.split(";"):
            seg = seg.strip()
            if seg.startswith("tt-target-idc="):
                minimal_ck = seg
                break
        result = self._http(url, "POST", body, cookie=minimal_ck or self._cookie)

        # Update HOST_LOGIN and device_redirect_info from server response
        data = result.get("data", {})
        if data.get("domain"):
            self._HOST_LOGIN = data["domain"]
        if data.get("device_redirect_info"):
            self._device_redirect_info = data["device_redirect_info"]
        if data.get("captcha_domain"):
            self._captcha_domain = self._normalize_captcha_host(data["captcha_domain"])
        return result

    def step_app_region_chain(self, region_id_source: str | None = None) -> dict:
        """
        [1] POST /passport/app/region/ on api16-normal-useast5.tiktokv.us
        [2] POST again on canonical domain (e.g. api16-normal-c-alisg.tiktokv.com)
        Refreshes store routing + device_redirect_info (same as real app).
        """
        saved_host = self._HOST_LOGIN
        self._HOST_LOGIN = "api16-normal-useast5.tiktokv.us"
        r1 = self.step_app_region(region_id_source=region_id_source)
        r2 = None
        dom = (r1.get("data") or {}).get("domain")
        if dom and dom != "api16-normal-useast5.tiktokv.us":
            self._HOST_LOGIN = dom
            r2 = self.step_app_region(region_id_source=region_id_source)
        out = {"useast5": r1, "alisg": r2, "final": r2 if r2 is not None else r1}
        if not dom:
            self._HOST_LOGIN = saved_host
        return out

    # ── Post-login: basic_info ─────────────────────────────────────────────────

    def step_basic_info(self, username: str, target_region: str = "") -> dict:
        """
        POST /passport/user/basic_info/
        Step 15. Returns avatar_url, avatar_uri, expires.
        Requires full post-login session cookie + X-Tt-Token.
        Body: type=1&username=<username>  (capture [1552])
        target_region: country code e.g. "eg", "us" (from store-country-code cookie)
        """
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        params = self._base_params(ts, rticket=rticket, include_device_redirect=True)
        if target_region:
            # Prepend target_region (it appears first in URL from capture)
            params = {"target_region": target_region, **params}
        url = self._build_url(self._HOST_LOGIN, "/passport/user/basic_info/", params)
        body = f"type=1&username={urllib.parse.quote(username)}"
        return self._http(url, "POST", body, cookie=self._cookie, login_state=1)

    # ── Post-login: device_register ────────────────────────────────────────────

    def step_device_register_post_login(self) -> dict:
        """
        POST /service/2/device_register/ (post-login)
        Step 14. Re-registers device with full session context after login.
        Host: log16-normal-alisg.tiktokv.com  (capture [1541])
        Extra URL params: req_id + cdid + openudid
        Body: full JSON with guest_mode=0, sdk_flavor, apk_first_install_time
        Uses login_state=1 (X-Tt-Token + login=1 dm-status).
        """
        import uuid
        import json as _json

        _HOST_LOG = "log16-normal-alisg.tiktokv.com"
        req_id = str(uuid.uuid4())

        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        d  = self.dev["device"]
        a  = self.dev["app"]
        m  = self.dev["meta"]
        loc = self.dev["locale"]
        n  = self.dev["network"]

        params = self._base_params(ts, rticket=rticket)
        params["req_id"]   = req_id
        params["cdid"]     = d.get("cdid", "")
        params["openudid"] = d.get("openudid", "")

        url = self._build_url(_HOST_LOG, "/service/2/device_register/", params)

        res = d.get("resolution", "1080*2340")
        w, h = (res.replace("*", "x").split("x") + ["1080", "2340"])[:2]
        resolution_v2 = f"{h}x{w}"

        body_dict = {
            "header": {
                "os": "Android",
                "os_version": d["os_version"],
                "os_api": int(d["os_api"]),
                "device_model": d["device_type"],
                "device_brand": d["device_brand"],
                "device_manufacturer": d["device_brand"].capitalize(),
                "cpu_abi": d["host_abi"],
                "density_dpi": int(d["dpi"]),
                "display_density": "mdpi",
                "resolution": f"{h}x{w}",
                "display_density_v2": "xxhdpi",
                "resolution_v2": resolution_v2,
                "access": n["ac"],
                "rom": m.get("rom", "13894323"),
                "rom_version": m.get("rom_version", f"{d['device_type']}-userdebug {d['os_version']}"),
                "language": loc["language"],
                "timezone": int(int(loc["timezone_offset"]) // 3600),
                "tz_name": loc["timezone_name"],
                "tz_offset": int(loc["timezone_offset"]),
                "sim_region": n.get("sim_region", n["carrier_region"].lower()),
                "carrier": n.get("carrier", "T-Mobile"),
                "mcc_mnc": n["mcc_mnc"],
                "clientudid": d.get("clientudid", ""),
                "openudid": d.get("openudid", ""),
                "channel": a["channel"],
                "not_request_sender": 1,
                "aid": int(a["aid"]),
                "release_build": m.get("release_build", ""),
                "ab_version": m["version"],
                "google_aid": d.get("google_aid", ""),
                "gaid_limited": 0,
                "custom": {
                    "is_foldable": 0,
                    "screen_height_dp": 851,
                    "priority_region": loc.get("region", "US"),
                    "user_period": 0,
                    "is_kids_mode": 0,
                    "user_mode": -1,
                    "ram_size": m.get("ram_size", "4GB"),
                    "screen_inches": 6.1,
                    "dark_mode_setting_value": 1,
                    "is_flip": 0,
                    "filter_warn": 0,
                    "web_ua": m.get("web_ua", (
                        f"Mozilla/5.0 (Linux; Android {d['os_version']}; "
                        f"{d['device_type']} Build/{m.get('build_id','BE2A.250530.026.F3')}; wv) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Version/4.0 Chrome/133.0.6943.137 Mobile Safari/537.36"
                    )),
                    "screen_width_dp": 393,
                },
                "package": "com.zhiliaoapp.musically",
                "app_version": m["version"],
                "app_version_minor": "",
                "version_code": int(m["version_code"]),
                "update_version_code": int(m["update_version_code"]),
                "manifest_version_code": int(m["manifest_version_code"]),
                "app_name": a["app_name"],
                "tweaked_channel": a["channel"],
                "display_name": "TikTok",
                "install_id": d["iid"],
                "device_id": d["device_id"],
                "sig_hash": m.get("sig_hash", "194326e82c84a639a52e5c023116f12a"),
                "cdid": d.get("cdid", ""),
                "device_platform": "android",
                "git_hash": m.get("git_hash", "5ae517f"),
                "sdk_version_code": int(m.get("sdk_version_code", 205140390)),
                "sdk_target_version": 30,
                "req_id": req_id,
                "sdk_version": m.get("sdk_version", "2.5.14.3"),
                # Post-login specific fields
                "guest_mode": 0,
                "sdk_flavor": "i18nInner",
                "apk_first_install_time": int(self.dev["session"]["last_install_time"]) * 1000,
                "is_system_app": 0,
            },
            "magic_tag": "ss_app_log",
            "_gen_time": rticket,
        }

        body = _json.dumps(body_dict, separators=(",", ":"), ensure_ascii=False)
        return self._http(url, "POST", body, cookie=self._cookie, login_state=1,
                          extra_headers={"Content-Type": "application/json; charset=utf-8"})

    # ── Auth broadcast (post-login) ───────────────────────────────────────────

    def step_auth_broadcast(self, sec_uid: str, screen_name: str,
                             final_domain: str, cookie: str = None) -> dict:
        """
        POST /passport/app/auth_broadcast/
        Notifies all regions of successful login. Triggers odin_tt + msToken refresh.
        """
        import hashlib
        rticket = int(time.time() * 1000)
        ts = rticket // 1000
        # Reduced params for auth_broadcast (from capture [1536])
        d = self.dev["device"]
        a = self.dev["app"]
        loc = self.dev["locale"]
        m = self.dev["meta"]
        params = {
            "device_platform": "android",
            "channel":         a["channel"],
            "aid":             a["aid"],
            "app_name":        a["app_name"],
            "version_code":    m["version_code"],
            "version_name":    m["version"],
            "sys_region":      loc["sys_region"],
            "carrier_region":  self.dev["network"]["carrier_region"],
            "iid":             d["iid"],
            "device_id":       d["device_id"],
            "support_webview": a["support_webview"],
        }
        url = self._build_url(self._HOST_LOGIN, "/passport/app/auth_broadcast/", params)
        hashed_id = hashlib.sha256(
            (sec_uid or screen_name or "").encode()
        ).hexdigest()
        body = (
            f"sec_uid={urllib.parse.quote(sec_uid)}"
            f"&screen_name={urllib.parse.quote(screen_name)}"
            f"&final_domain={urllib.parse.quote(final_domain)}"
            f"&hashed_id={hashed_id}&type=3"
        )
        ck = cookie if cookie is not None else self._cookie
        # auth_broadcast uses post-login state (login=1, X-Tt-Token, x-bd-kmsv=0)
        return self._http(url, "POST", body, cookie=ck, login_state=1)

    # ── Update cookies from response headers ──────────────────────────────────

    def _merge_set_cookies(self, resp_headers: dict) -> None:
        """
        Merge Set-Cookie values from response into self._cookie.
        Updates self.dev["session"]["cookie"] too.
        """
        if not resp_headers:
            return
        set_cookies = resp_headers.get("Set-Cookie") or resp_headers.get("set-cookie")
        if not set_cookies:
            return
        if isinstance(set_cookies, str):
            set_cookies = [set_cookies]

        existing = {}
        for part in self._cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                existing[k.strip()] = v.strip()

        for sc in set_cookies:
            name_val = sc.split(";")[0].strip()
            if "=" in name_val:
                k, v = name_val.split("=", 1)
                existing[k.strip()] = v.strip()

        self._cookie = "; ".join(f"{k}={v}" for k, v in existing.items())
        self.dev["session"]["cookie"] = self._cookie

    def _merge_cookie_pair(self, name: str, value: str) -> None:
        """Set or replace one name=value in self._cookie (e.g. D-Ticket → d_ticket)."""
        if not name or not value:
            return
        existing: dict[str, str] = {}
        for part in (self._cookie or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                existing[k.strip()] = v.strip()
        existing[name.strip()] = value.strip()
        self._cookie = "; ".join(f"{k}={v}" for k, v in existing.items())
        self.dev.setdefault("session", {})["cookie"] = self._cookie

    # ── Full login flow (handles captcha=1105, IDV/2135 automatically) ────────

    def login(self, username: str, password_hex: str,
              skip_check: bool = False,
              region_id_source: str | None = None,
              captcha_solver=None,
              idv_code_provider=None) -> dict:
        """
        Execute the full login flow with automatic captcha + IDV handling.

        Args:
            username          : TikTok username (plain text)
            password_hex      : Password in TikTok hex format (use encode_password())
            skip_check        : Skip step1 username check
            region_id_source  : Optional email/phone for /passport/app/region/ hashed_id
                                (SHA-256); if None, uses device_id
            captcha_solver    : Optional callable(captcha_data) → solved_edata string
                                If None, returns success=False and captcha_data on 1105
            idv_code_provider : Optional callable(verify_ticket, pseudo_id, extra_info)
                                → verification code string
                                If None, raises IDVRequired on error_code 2135

        Returns:
            dict with keys: step1, step2, step3, success, session_key, x_tt_token,
                            cookies, uid, username
        """
        results = {}

        # ── Step 0a: get_nonce (real flow step 1) ───────────────────────────
        print("[login] Step 0a — get_nonce...", flush=True)
        try:
            r_nonce = self.step_get_nonce()
            results["get_nonce"] = r_nonce
            nonce = r_nonce.get("data", {}).get("nonce", "")
            print(f"  → nonce={'present' if nonce else 'missing'}", flush=True)
        except Exception as _e:
            print(f"  [!] get_nonce failed (non-fatal): {_e}", flush=True)

        # ── Step 0a-sdi: MSSDK /sdi/get_token (real flow step 2) ───────────────
        print("[login] Step 0a-sdi — sdi/get_token...", flush=True)
        try:
            r_sdi = self.step_sdi_get_token()
            results["sdi_get_token"] = r_sdi
            if r_sdi.get("skipped"):
                print(f"  → skipped: {r_sdi.get('reason')}", flush=True)
            else:
                print(f"  → response raw_len={r_sdi.get('_raw_len', '?')}", flush=True)
        except Exception as _e:
            print(f"  [!] sdi/get_token failed (non-fatal): {_e}", flush=True)

        # ── Step 0b: app/region useast5 → alisg (real flow [1]+[2]) ───────────
        print("[login] Step 0b — app/region (useast5 → canonical)...", flush=True)
        try:
            r_region = self.step_app_region_chain(region_id_source=region_id_source)
            results["app_region_chain"] = r_region
            final = r_region.get("final") or {}
            region_domain = (final.get("data") or {}).get("domain", "")
            print(f"  → domain={region_domain or '?'}", flush=True)
        except Exception as _e:
            print(f"  [!] app/region failed (non-fatal): {_e}", flush=True)

        # ── Step 1: Check username ───────────────────────────────────────────
        if not skip_check:
            print(f"[login] Step 1 — checking username '{username}'...", flush=True)
            r1 = self.step1_check_username(username)
            results["step1"] = r1
            ec1 = r1.get("data", {}).get("is_registered")
            print(f"  → registered={ec1}", flush=True)

        # ── Step 2: Pre-check ────────────────────────────────────────────────
        print(f"[login] Step 2 — pre_check...", flush=True)
        r2 = self.step2_pre_check(username)
        results["step2"] = r2
        print(f"  → {r2.get('message', '?')}", flush=True)
        # Note: _http() auto-merges Set-Cookie (msToken) into self._cookie after pre_check

        # ── Step 3: Login (retry loop for captcha + IDV) ─────────────────────
        # Cookie for signing: include msToken / d_ticket when present (v44.3.15 captures)
        cookie = self._cookie_for_passport_request()

        max_login_attempts = 3
        for attempt in range(max_login_attempts):
            print(f"[login] Step 3 — login attempt {attempt + 1}...", flush=True)
            r3 = self.step3_login(username, password_hex, cookie=cookie)
            results["step3"] = r3

            data = r3.get("data", r3)
            ec = data.get("error_code") or r3.get("error_code") or 0
            msg = r3.get("message", "")
            print(f"  → message={msg} error_code={ec}", flush=True)

            # SUCCESS
            if msg == "success" and (not ec or ec == 0):
                session_key = data.get("session_key", "")
                uid          = data.get("user_id_str", data.get("uid", ""))
                uname        = data.get("username", "")
                sec_uid      = data.get("sec_user_id", "")
                x_tt_token   = self.dev.get("session", {}).get("x_tt_token", "")
                print(f"  ✓ Login success — uid={uid} username={uname}", flush=True)

                # ── auth_broadcast (step 10) ────────────────────────────────
                # Determines final_domain from store-idc cookie (migrates post-login)
                idc_val = ""
                for part in self._cookie.split(";"):
                    part = part.strip()
                    if part.startswith("store-idc="):
                        idc_val = part.split("=", 1)[1].strip()
                        break
                final_domain = f"api16-normal-c-{idc_val}.tiktokv.com" if idc_val else self._HOST_LOGIN
                print(f"[login] auth_broadcast → {final_domain}...", flush=True)
                try:
                    self.step_auth_broadcast(
                        sec_uid=sec_uid,
                        screen_name=uname,
                        final_domain=final_domain,
                        cookie=self._cookie,
                    )
                    print(f"  → auth_broadcast OK", flush=True)
                except Exception as _e:
                    print(f"  [!] auth_broadcast failed (non-fatal): {_e}", flush=True)

                # ── Step 14: device_register post-login ─────────────────────
                print("[login] Step 14 — device_register post-login...", flush=True)
                try:
                    r_dreg = self.step_device_register_post_login()
                    results["device_register_post_login"] = r_dreg
                    print(f"  → {r_dreg.get('message', '?')}", flush=True)
                except Exception as _e:
                    print(f"  [!] device_register post-login failed (non-fatal): {_e}", flush=True)

                # ── Step 15: basic_info ─────────────────────────────────────
                print("[login] Step 15 — basic_info...", flush=True)
                try:
                    # Extract target_region from store-country-code cookie
                    target_region = ""
                    for part in self._cookie.split(";"):
                        part = part.strip()
                        if part.startswith("store-country-code="):
                            target_region = part.split("=", 1)[1].strip()
                            break
                    r_info = self.step_basic_info(uname, target_region=target_region)
                    results["basic_info"] = r_info
                    avatar = r_info.get("data", {}).get("avatar_uri", "")
                    print(f"  → avatar={'present' if avatar else 'missing'}", flush=True)
                except Exception as _e:
                    print(f"  [!] basic_info failed (non-fatal): {_e}", flush=True)

                results["success"]     = True
                results["session_key"] = session_key
                results["uid"]         = uid
                results["sec_uid"]     = sec_uid
                results["username"]    = uname
                results["x_tt_token"]  = x_tt_token
                results["cookies"]     = self._cookie
                return results

            # CAPTCHA REQUIRED (error_code 1105)
            elif ec == 1105:
                print(f"  [!] Captcha required (1105)", flush=True)
                enriched = dict(data)
                use_http = self.dev.get("captcha_http") is not False
                host_ok = bool(self._resolve_captcha_host(enriched))
                if use_http and host_ok:
                    try:
                        cg = self.step_captcha_get(enriched)
                        results.setdefault("captcha_get", []).append(cg)
                        enriched["captcha_get_response"] = cg
                    except Exception as _e:
                        print(f"  [!] captcha/get failed (non-fatal): {_e}", flush=True)
                if captcha_solver is None:
                    results["success"] = False
                    results["error"] = "captcha_required"
                    results["captcha_data"] = enriched
                    return results
                edata = captcha_solver(enriched)
                if not edata:
                    results["success"] = False
                    results["error"] = "captcha_solver_failed"
                    return results
                if use_http and host_ok:
                    try:
                        cv = self.step_captcha_verify(edata, enriched)
                        results.setdefault("captcha_verify", []).append(cv)
                    except Exception as _e:
                        print(f"  [!] captcha/verify failed (non-fatal): {_e}", flush=True)
                cookie = self._cookie_for_passport_request()
                continue

            # IDV / 2FA REQUIRED (error_code 2135)
            elif ec == 2135:
                print(f"  [!] IDV required (2135)", flush=True)
                cookie = self._cookie_for_passport_request()
                passport_ticket = data.get("passport_ticket", "")
                verify_ticket = data.get("verify_ticket", "")
                # Extract pseudo_id from verify_center_decision_conf
                try:
                    conf = json.loads(data.get("verify_center_decision_conf", "{}"))
                    pseudo_id = conf.get("extra", [{}])[0].get("pseudo_id", "")
                    extra_info = conf.get("extra", [])
                except Exception:
                    pseudo_id = ""
                    extra_info = []

                # Extract d_ticket from response (if Set-Cookie present)
                d_ticket = data.get("d_ticket", "")
                if d_ticket:
                    parts = dict(p.split("=", 1) for p in cookie.split(";") if "=" in p.strip())
                    parts["d_ticket"] = d_ticket
                    cookie = "; ".join(f"{k.strip()}={v.strip()}" for k, v in parts.items())

                if idv_code_provider is None:
                    results["success"] = False
                    results["error"] = "idv_required"
                    results["passport_ticket"] = passport_ticket
                    results["verify_ticket"] = verify_ticket
                    results["pseudo_id"] = pseudo_id
                    results["extra_info"] = extra_info
                    results["step3"] = r3
                    return results

                # Request code
                print(f"  [*] Requesting IDV code...", flush=True)
                self.step_aaas_request_code(passport_ticket, pseudo_id, cookie=cookie)
                time.sleep(2)

                # Get code from provider
                code = idv_code_provider(verify_ticket, pseudo_id, extra_info)
                if not code:
                    results["success"] = False
                    results["error"] = "idv_code_not_provided"
                    return results

                # Submit code
                print(f"  [*] Submitting IDV code...", flush=True)
                r_aaas = self.step_aaas_submit_code(
                    passport_ticket, pseudo_id, code, cookie=cookie
                )
                if r_aaas.get("message") != "success":
                    results["success"] = False
                    results["error"] = "aaas_failed"
                    results["aaas_response"] = r_aaas
                    return results

                # [7] Renew device_redirect_info after successful OTP (same as app)
                print("[login] Step 0b′ — app/region after AAAS...", flush=True)
                try:
                    r_ar2 = self.step_app_region(region_id_source=region_id_source)
                    results["app_region_after_aaas"] = r_ar2
                except Exception as _e:
                    print(f"  [!] app/region after AAAS (non-fatal): {_e}", flush=True)

                cookie = self._cookie_for_passport_request()
                continue

            else:
                results["success"] = False
                results["error"] = f"unknown_error_code_{ec}"
                return results

        results["success"] = False
        results["error"] = "max_login_attempts_reached"
        return results


# ── Password encoding utility ─────────────────────────────────────────────────

# XOR key for mix_mode=1 username/password/OTP body fields (v44.3.15 MITM verified).
LOGIN_BODY_XOR_KEY = 0x05


def encode_password(plain: str, xor_key: int | None = None) -> str:
    """
    Encode plain text to TikTok login body hex (per character code point; BMP matches the app).
    Each unit: hex(ord(c) ^ xor_key), zero-padded to 2 hex digits.

    v44.3.15 captures use xor_key=0x05 (e.g. ``storegs2`` → ``76716a7760627637``).
    Older builds (e.g. 44.3.1 notes) used 0x17 — pass ``xor_key=0x17`` if needed.
    """
    k = LOGIN_BODY_XOR_KEY if xor_key is None else xor_key
    return "".join(f"{ord(c) ^ k:02x}" for c in plain)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TikTok v44.3.15 Login Client — full 15-step flow with captcha+IDV handling"
    )
    parser.add_argument("--username",     required=True,      help="TikTok username")
    parser.add_argument("--password",     default="",         help="Plain text password (will be hex-encoded)")
    parser.add_argument("--password-hex", default="",         help="Pre-encoded hex password")
    parser.add_argument("--device",       default=None,       help="Path to device JSON (default: fixtures/device_v44_3_1.json)")
    parser.add_argument("--proxy",        default=None,       help="HTTP proxy e.g. http://user:pass@host:port")
    parser.add_argument(
        "--proxy-file",
        default=None,
        help="Read first host:port:user:pass line → --proxy (else try TIKTOK_PROXY_FILE, proxsy.txt, proxy.txt)",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Direct connection only: skip --proxy, --proxy-file, proxsy.txt, TIKTOK_PROXY*, HTTP(S)_PROXY",
    )
    parser.add_argument("--step1",        action="store_true",help="Run step 1 (check username) only")
    parser.add_argument("--step2",        action="store_true",help="Run step 2 (pre_check) only")
    parser.add_argument("--skip-check",   action="store_true",help="Skip username check (step 1)")
    parser.add_argument("--region-email", default="",
                        help="Email for /passport/app/region/ hashed_id (SHA-256); else device_id")
    parser.add_argument(
        "--devices-batch",
        default=None,
        metavar="JSON",
        help="devices_001.json style (.devices[].record): merge each into --device base and run step1|step2|login",
    )
    parser.add_argument("--batch-limit", type=int, default=0,
                        help="With --devices-batch: max entries (0 = all after offset)")
    parser.add_argument("--batch-offset", type=int, default=0,
                        help="With --devices-batch: skip first N entries in .devices[]")
    parser.add_argument(
        "--proxy-rotate-file",
        default=None,
        metavar="FILE",
        help="With --devices-batch: proxy for row i = line (i mod N) from FILE (host:port:user:pass per line)",
    )
    parser.add_argument(
        "--batch-summary-out",
        default=None,
        metavar="FILE.json",
        help="After batch: write JSON array of per-device results (for step1/step2/login batch)",
    )
    parser.add_argument("--verbose",      action="store_true",help="Print full request/response")
    parser.add_argument(
        "--sign-backend",
        choices=("local", "rapidapi"),
        default=None,
        help="local=signing_engine (default); rapidapi=live headers from RapidAPI get_sign (needs RAPIDAPI_KEY)",
    )
    parser.add_argument(
        "--rapidapi-key",
        default=None,
        help="RapidAPI key (else env RAPIDAPI_KEY / X_RAPIDAPI_KEY)",
    )
    args = parser.parse_args()

    def _cli_sign_backend() -> str:
        if args.sign_backend:
            return args.sign_backend
        env = (os.environ.get("TIKTOK_SIGN_BACKEND") or "local").strip().lower()
        return env if env in ("local", "rapidapi") else "local"

    _sign_be = _cli_sign_backend()
    if _sign_be == "rapidapi" and not (
        (args.rapidapi_key or "").strip()
        or os.environ.get("RAPIDAPI_KEY")
        or os.environ.get("X_RAPIDAPI_KEY")
    ):
        parser.error("--sign-backend rapidapi requires --rapidapi-key or RAPIDAPI_KEY in the environment")

    if args.no_proxy:
        if args.proxy or args.proxy_file:
            parser.error("Do not combine --no-proxy with --proxy or --proxy-file")
        proxy_url = None
        print("[*] Direct connection (--no-proxy): TikTok requests without HTTP proxy", flush=True)
    else:
        proxy_url = args.proxy
        if args.proxy_file:
            ppath = args.proxy_file if os.path.isabs(args.proxy_file) else os.path.join(PROJECT_ROOT, args.proxy_file)
            proxy_url = _first_proxy_url_from_file(ppath)
            if not proxy_url:
                parser.error(f"No valid proxy line in {ppath}")
        if not proxy_url:
            pf = (os.environ.get("TIKTOK_PROXY_FILE") or "").strip()
            if pf:
                ppath = pf if os.path.isabs(pf) else os.path.join(PROJECT_ROOT, pf)
                proxy_url = _first_proxy_url_from_file(ppath)
                if proxy_url:
                    print("[*] HTTP proxy from TIKTOK_PROXY_FILE", flush=True)
        if not proxy_url:
            for name in ("proxsy.txt", "proxy.txt"):
                ppath = os.path.join(PROJECT_ROOT, name)
                proxy_url = _first_proxy_url_from_file(ppath)
                if proxy_url:
                    print(f"[*] HTTP proxy from first line of tiktok_final/{name}", flush=True)
                    break
        if not proxy_url:
            proxy_url = (
                os.environ.get("TIKTOK_PROXY")
                or os.environ.get("HTTPS_PROXY")
                or os.environ.get("HTTP_PROXY")
            )
            if proxy_url:
                print("[*] HTTP proxy from TIKTOK_PROXY / HTTPS_PROXY / HTTP_PROXY", flush=True)
        elif args.proxy:
            print("[*] HTTP proxy from --proxy", flush=True)

    if proxy_url and _sign_be == "rapidapi":
        print(
            "[*] Note: RapidAPI get_sign is direct-only; TikTok API calls still use the HTTP proxy above. "
            "If you see ProxyError / tunnel 562, add --no-proxy.",
            flush=True,
        )

    base_device_path = (
        resolve_data_path(args.device)
        if args.device is not None
        else os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
    )

    if args.devices_batch:
        batch_path = (
            args.devices_batch
            if os.path.isabs(args.devices_batch)
            else resolve_data_path(args.devices_batch)
        )
        if not os.path.isfile(batch_path):
            parser.error(f"--devices-batch not found: {batch_path}")
        with open(batch_path, encoding="utf-8") as bf:
            batch = json.load(bf)
        rows = list(batch.get("devices") or [])
        off = max(0, int(args.batch_offset or 0))
        rows = rows[off:]
        lim = int(args.batch_limit or 0)
        if lim > 0:
            rows = rows[:lim]
        if not rows:
            parser.error("No device entries after --batch-offset / --batch-limit")

        if args.proxy_rotate_file and args.no_proxy:
            parser.error("--proxy-rotate-file cannot be used with --no-proxy")
        rotate_proxies: list[str] | None = None
        if args.proxy_rotate_file:
            rpath = (
                args.proxy_rotate_file
                if os.path.isabs(args.proxy_rotate_file)
                else os.path.join(PROJECT_ROOT, args.proxy_rotate_file)
            )
            rotate_proxies = _all_proxy_urls_from_file(rpath)
            if not rotate_proxies:
                parser.error(f"--proxy-rotate-file has no valid proxy lines: {rpath}")
            print(
                f"[*] Batch proxy rotation: {len(rotate_proxies)} line(s) from {rpath}",
                flush=True,
            )

        base_prof = _load_device(base_device_path)
        pw_hex = ""
        if not args.step1 and not args.step2:
            if args.password:
                pw_hex = encode_password(args.password)
            elif args.password_hex:
                pw_hex = args.password_hex
            else:
                parser.error("Full login batch needs --password or --password-hex (or use --step1 / --step2)")
        reg_src = (args.region_email or "").strip() or None

        print(
            f"[*] devices-batch: {len(rows)} profile(s) | base={base_device_path} | batch={batch_path}",
            flush=True,
        )
        tpath = os.path.join(tempfile.gettempdir(), f"_tt_login_batch_{os.getpid()}.json")
        batch_summary: list[dict] = []
        try:
            for pos, ent in enumerate(rows):
                idx = ent.get("batch_index", "?")
                rec = ent.get("record") or {}
                rr = rec.get("register_response") or {}
                did = str(rec.get("device_id_str") or rr.get("device_id_str") or "")
                iid = str(rec.get("install_id_str") or rr.get("install_id_str") or "")
                prof = merge_devices_batch_record_into_profile(base_prof, rec)
                with open(tpath, "w", encoding="utf-8") as wf:
                    json.dump(prof, wf, ensure_ascii=False, indent=2)
                row_proxy = proxy_url
                proxy_idx = None
                if rotate_proxies:
                    proxy_idx = pos % len(rotate_proxies)
                    row_proxy = rotate_proxies[proxy_idx]
                    print(
                        f"  [proxy row {pos}] using rotate index {proxy_idx}/{len(rotate_proxies)}",
                        flush=True,
                    )
                client = TikTokLoginClient(
                    device_path=tpath,
                    proxy=row_proxy,
                    verbose=args.verbose,
                    sign_backend=_sign_be,
                    rapidapi_key=args.rapidapi_key,
                )
                print(f"\n--- batch_index={idx} device_id={did} iid={iid} ---", flush=True)
                row_out: dict = {
                    "batch_index": idx,
                    "batch_pos": pos,
                    "device_id": did,
                    "install_id": iid,
                    "proxy_rotate_index": proxy_idx,
                    "step": "step1" if args.step1 else ("step2" if args.step2 else "login"),
                }
                try:
                    if args.step1:
                        result = client.step1_check_username(args.username)
                        data = result.get("data", result)
                        ec = data.get("error_code", 0)
                        desc = (data.get("description") or "")[:200]
                        print(
                            f"  step1 message={result.get('message')} error_code={ec} "
                            f"registered={data.get('is_registered')} desc={desc!r}",
                            flush=True,
                        )
                        if args.verbose:
                            print(json.dumps(result, indent=2, ensure_ascii=False))
                        row_out["api"] = result
                        row_out["error_code"] = ec
                        row_out["is_registered"] = data.get("is_registered")
                        row_out["description"] = data.get("description")
                    elif args.step2:
                        result = client.step2_pre_check(args.username)
                        data = result.get("data", result)
                        ec = data.get("error_code", "?") if isinstance(data, dict) else "?"
                        print(f"  step2 message={result.get('message')} error_code={ec}", flush=True)
                        if args.verbose:
                            print(json.dumps(result, indent=2, ensure_ascii=False))
                        row_out["api"] = result
                        if isinstance(data, dict):
                            row_out["error_code"] = data.get("error_code")
                    else:
                        results = client.login(
                            args.username,
                            pw_hex,
                            skip_check=args.skip_check,
                            region_id_source=reg_src,
                        )
                        row_out["success"] = bool(results.get("success"))
                        row_out["error"] = results.get("error")
                        if results.get("success"):
                            print("  LOGIN SUCCESS", flush=True)
                            print(f"  uid={results.get('uid')}", flush=True)
                            row_out["uid"] = results.get("uid")
                        else:
                            step3 = results.get("step3", {})
                            data = step3.get("data", step3) if step3 else {}
                            print(
                                f"  LOGIN FAILED error={results.get('error')} "
                                f"error_code={data.get('error_code', '?')}",
                                flush=True,
                            )
                            if args.verbose:
                                print(json.dumps(step3, indent=2, ensure_ascii=False))
                            row_out["step3"] = step3
                            row_out["error_code"] = data.get("error_code") if isinstance(data, dict) else None
                        row_out["full"] = results
                except Exception as e:
                    if not _batch_is_transport_failure(e):
                        raise
                    row_out["transport_error"] = type(e).__name__
                    row_out["error_detail"] = str(e)[:2000]
                    print(
                        f"  [!] transport error (batch continues): {type(e).__name__}: {str(e)[:180]}",
                        flush=True,
                    )
                batch_summary.append(row_out)
        finally:
            try:
                os.unlink(tpath)
            except OSError:
                pass
        if args.batch_summary_out and batch_summary:
            outp = (
                args.batch_summary_out
                if os.path.isabs(args.batch_summary_out)
                else os.path.join(PROJECT_ROOT, args.batch_summary_out)
            )
            with open(outp, "w", encoding="utf-8") as sf:
                n_tr = sum(1 for r in batch_summary if r.get("transport_error"))
                json.dump(
                    {
                        "username": args.username,
                        "batch_file": batch_path,
                        "count": len(batch_summary),
                        "transport_failures": n_tr,
                        "results": batch_summary,
                    },
                    sf,
                    ensure_ascii=False,
                    indent=2,
                )
                sf.write("\n")
            print(f"[*] Batch summary written: {outp}", flush=True)
        sys.exit(0)

    client = TikTokLoginClient(
        device_path=args.device,
        proxy=proxy_url,
        verbose=args.verbose,
        sign_backend=_sign_be,
        rapidapi_key=args.rapidapi_key,
    )

    if args.step1:
        result = client.step1_check_username(args.username)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.step2:
        result = client.step2_pre_check(args.username)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Full login
        if args.password:
            pw_hex = encode_password(args.password)
            print(f"[*] Password encoded: {pw_hex}")
        elif args.password_hex:
            pw_hex = args.password_hex
        else:
            parser.error("Provide --password or --password-hex")

        reg_src = (args.region_email or "").strip() or None
        results = client.login(
            args.username, pw_hex,
            skip_check=getattr(args, "skip_check", False),
            region_id_source=reg_src,
        )
        print("\n" + "="*60)
        if results.get("success"):
            print("LOGIN SUCCESS")
            print(f"  uid        : {results.get('uid', '?')}")
            print(f"  sec_uid    : {str(results.get('sec_uid', '?'))[:40]}...")
            print(f"  session_key: {str(results.get('session_key', '?'))[:40]}...")
            print(f"  x_tt_token : {str(results.get('x_tt_token', '?'))[:40]}...")
            print(f"  cookie     : {client._cookie[:120]}...")
        else:
            print("LOGIN FAILED")
            print(f"  error: {results.get('error', '?')}")
            step3 = results.get("step3", {})
            if step3:
                data = step3.get("data", step3)
                print(f"  error_code : {data.get('error_code', '?')}")
                print(f"  description: {data.get('description', step3.get('message', '?'))}")
                if results.get("passport_ticket"):
                    print(f"  passport_ticket: {results['passport_ticket'][:40]}...")
                    print(f"  pseudo_id      : {results.get('pseudo_id', '?')}")
        print()
        print(json.dumps(results.get("step3", {}), indent=2, ensure_ascii=False))
