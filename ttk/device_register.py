#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
device_register.py — TikTok v44.3.1 Device Registration

Generates a brand-new TikTok device (device_id + install_id + openudid + cdid)
by calling TikTok's device registration endpoint.

Sources:
  - Android JADX: DeviceRegisterManager.java; AppLogNetworkContextImpl (log-va / api.tiktokv.com);
    X/C951640as2 (log.byteoversea.com, log15.byteoversea.com, …); X/C938550aWv.LJ — device_register
    uses ``application/octet-stream;tt-data=b`` + gzip (not ``/service/2/app_log/`` compressor branch).
  - Endpoint: POST /service/2/device_register/
  - Signing: signing_engine; default X-SS-STUB from uncompressed JSON — wire ``java_gzip_sig`` uses
    MD5(gzip bytes) for experiments matching gzip-on-wire verification.
  - TikTok Lite / ``musically.go``: set ``app.aid`` = 1340, ``app.app_name`` = ``musically_go``, package in
    ``app.package``, and put Lite-only header keys (``req_id``, ``apk_first_install_time``, ``sdk_flavor``,
    ``oaid_may_support``, …) under ``device_register.header_extras``. Paste real ``sig_hash`` / ``git_hash`` /
    ``release_build`` from the same APK build (see JADX ``C938760aXG`` + ``C938780aXI``).

Usage:
    python3 device_register.py                          # register + auto-save
    python3 device_register.py --out my_device.json     # custom output path
    python3 device_register.py --base other.json        # use different base profile
    python3 device_register.py --apk /path/base.apk     # استخراج sig_hash من APK ودمجه في الملف الأساسي
    python3 device_register.py --apk base.apk --base device_lite_go.example.json --extract-sig-only --out lite_with_sig.json
    python3 device_register.py --proxy http://127.0.0.1:8888 --verbose
    python3 device_register.py --dump-golden ./golden_out --verbose   # save each attempt JSON for MITM diff
    python3 device_register.py --golden-only ./golden_out              # one request + snapshot, then exit
"""

import argparse
import copy
import datetime
import gzip
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error

from .paths import FIXTURES_DIR, PROJECT_ROOT, resolve_data_path
from .signing_engine import sign as _sign

from .login_client import _proxy_line_to_url
from .tiktok_apk_sig import merge_sig_hash_into_base


# ── Registration hosts (JADX: AppLogNetworkContextImpl; X/C951640as2 regional lists;
#    iOS URL list Untitled-2: log.isnssdk.com, log.sgsnssdk.com, log.snssdk.com, log2.musical.ly)
_HOSTS = [
    "log-va.tiktokv.com",
    "api.tiktokv.com",
    "log.byteoversea.com",
    "log15.byteoversea.com",
    "log.isnssdk.com",
    "log.sgsnssdk.com",
    "log2.musical.ly",
    "log.snssdk.com",
]

_PATH = "/service/2/device_register/"


def server_response_diagnostics(result: object) -> str:
    """
    Collect error / status fields sometimes returned alongside device_id:0
    (not always present — server may only return server_time + zeros).
    """
    lines = []
    if not isinstance(result, dict):
        return ""

    def _walk(obj, prefix: str):
        if isinstance(obj, dict):
            for k in (
                "error_code",
                "message",
                "description",
                "status_code",
                "status_msg",
                "log_id",
                "prompts",
                "captcha",
            ):
                if k in obj and obj[k] not in (None, "", {}):
                    lines.append(f"{prefix}{k}: {obj[k]!r}")
            inner = obj.get("data")
            if isinstance(inner, dict):
                for k in ("error_code", "message", "description", "captcha"):
                    if k in inner and inner[k] not in (None, "", {}):
                        lines.append(f"{prefix}data.{k}: {inner[k]!r}")

    _walk(result, "")
    return "\n".join(lines)


# ── ID generation (matches Android DeviceRegisterManager + UUID.randomUUID()) ──

def new_device_id() -> str:
    """19-digit decimal — matches Android DeviceRegisterManager.getDeviceId()"""
    return str(secrets.randbelow(10**19)).zfill(19)


def new_install_id() -> str:
    """19-digit decimal — matches Android DeviceRegisterManager.getInstallId()"""
    return str(secrets.randbelow(10**19)).zfill(19)


def new_openudid() -> str:
    """UUID v4 — matches iOS OpenUDID / Android UUID.randomUUID()"""
    return str(uuid.uuid4())


def new_cdid() -> str:
    """UUID v4 — matches Android C929670aIb UUID.randomUUID().toString()"""
    return str(uuid.uuid4())


# ══════════════════════════════════════════════════════════════════════════════
# TikTokDeviceRegister
# ══════════════════════════════════════════════════════════════════════════════

def _build_common_params_v2(base: dict) -> str:
    """
    Build x-common-params-v2 header value from a device profile dict.
    Matches the format captured from real TikTok H2 traffic.
    """
    d = base["device"]
    m = base["meta"]
    a = base["app"]
    loc = base["locale"]
    n = base.get("network") or {}

    params = {
        "ab_version": m.get("ab_version", m["version"]),
        "ac": n.get("ac", "wifi"),
        "ac2": n.get("ac2", "unknown"),
        "aid": a["aid"],
        "app_language": loc.get("app_language", "en"),
        "app_name": a["app_name"],
        "app_type": a.get("app_type", "normal"),
        "build_number": m.get("build_number", m["version"]),
        "carrier_region": n.get("carrier_region", loc.get("sys_region", "US")),
        "carrier_region_v2": n.get("carrier_region_v2", "310"),
        "channel": a["channel"],
        "current_region": loc.get("region", "US"),
        "device_brand": d["device_brand"],
        "device_id": d.get("device_id", "0"),
        "device_platform": "android",
        "device_type": d["device_type"],
        "dpi": d["dpi"],
        "iid": d.get("iid", "0"),
        "language": loc.get("language", "en"),
        "locale": loc.get("locale", "en"),
        "manifest_version_code": m["manifest_version_code"],
        "mcc_mnc": n.get("mcc_mnc", "310260"),
        "op_region": loc.get("op_region", "US"),
        "os_api": d["os_api"],
        "os_version": d["os_version"],
        "region": loc.get("region", "US"),
        "residence": loc.get("region", "US"),
        "resolution": d["resolution"],
        "ssmix": a.get("ssmix", "a"),
        "sys_region": loc.get("sys_region", "US"),
        "timezone_name": loc["timezone_name"],
        "timezone_offset": loc["timezone_offset"],
        "uoo": loc.get("uoo", "1"),
        "update_version_code": m["update_version_code"],
        "version_code": m["version_code"],
        "version_name": m["version"],
    }
    return urllib.parse.urlencode(params)


class TikTokDeviceRegister:
    """
    Register a new TikTok device and receive a real device_id + install_id.

    Replicates the first-launch device registration flow from Android/iOS source:
      1. Generate fresh identifiers (openudid, cdid) — locally, matching app logic
      2. POST /service/2/device_register/ with device fingerprint
      3. Server returns new device_id + install_id
      4. Build + save a complete device profile JSON for use with login_client.py

    Parameters:
        base_path : path to device_v44_3_1.json to use as hardware template
        proxy     : optional HTTP proxy "http://host:port"
        verbose   : print full request/response
    """

    def __init__(
        self,
        base_path: str = None,
        base_dict: dict = None,
        proxy: str = None,
        verbose: bool = False,
        allow_local_fallback: bool = False,
        dump_golden_dir: str = None,
    ):
        if base_dict is not None:
            self.base = copy.deepcopy(base_dict)
        else:
            path = base_path or os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
            with open(path, encoding="utf-8") as f:
                self.base = json.load(f)

        self.proxy   = proxy
        self.verbose = verbose
        self.allow_local_fallback = allow_local_fallback
        self.dump_golden_dir = dump_golden_dir

        # Generate fresh identifiers for the new device
        self._openudid   = new_openudid()
        self._cdid       = new_cdid()
        self._clientudid = str(uuid.uuid4())  # JADX C938760aXG: clientudid per install
        self._req_id     = str(uuid.uuid4())  # JADX DeviceRegisterManager.getRequestId() (stable per process)

    # ── Request builders ───────────────────────────────────────────────────────

    def _build_params(self, ts: int) -> dict:
        """Query for device_register — aligned with login_client; JADX: log-va.tiktokv.com."""
        d   = self.base["device"]
        a   = self.base["app"]
        m   = self.base["meta"]
        n   = self.base["network"]
        loc = self.base["locale"]
        rticket = ts * 1000
        return {
            "passport-sdk-version":   "1",
            "device_platform":        "android",
            "os":                     "android",
            "ssmix":                  a["ssmix"],
            "_rticket":               str(rticket),
            "cdid":                   self._cdid,
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
            "app_type":               a["app_type"],
            "sys_region":             loc["sys_region"],
            "last_install_time":      str(ts),
            "mcc_mnc":                n["mcc_mnc"],
            "timezone_name":          loc["timezone_name"].replace("/", "%2F"),
            "carrier_region_v2":      n["carrier_region_v2"],
            "app_language":           loc["app_language"],
            "carrier_region":         n["carrier_region"],
            "timezone_offset":        loc["timezone_offset"],
            "host_abi":               d["host_abi"],
            "locale":                 loc["locale"],
            "ac2":                    n["ac2"],
            "uoo":                    loc["uoo"],
            "op_region":              loc["op_region"],
            "build_number":           m["version"],
            "ts":                     str(ts),
            "iid":                    "0",
            "device_id":              "0",
            "openudid":               self._openudid.replace("-", "")[:16],
            "support_webview":        a["support_webview"],
        }

    def _build_url(self, host: str, params: dict) -> str:
        parts = []
        for k, v in params.items():
            if k == "timezone_name":
                parts.append(f"{k}={v}")
            else:
                parts.append(f"{k}={urllib.parse.quote(str(v), safe='*@')}")
        return f"https://{host}{_PATH}?{'&'.join(parts)}"

    @staticmethod
    def _resolution_height_x_width(res: str) -> str:
        """
        JADX C938760aXG: resolution string uses height×width semantics; body historically uses \"*\".
        Accepts \"1440*3120\" (W*H) or \"3120x1440\" (H×W with letter x) → \"3120*1440\" (taller*shorter).
        """
        if not res:
            return res
        if "*" in res:
            a, b = res.split("*", 1)
        elif "x" in res.lower():
            low = res.lower()
            idx = low.index("x")
            a, b = res[:idx], res[idx + 1 :]
        else:
            return res
        try:
            x, y = int(a.strip()), int(b.strip())
        except ValueError:
            return res
        lo, hi = (x, y) if x <= y else (y, x)
        return f"{hi}*{lo}"

    @staticmethod
    def _dpi_to_display_density(dpi: int) -> str:
        """Same buckets as JADX C938760aXG.LIZJ (densityDpi switch)."""
        if dpi == 120:
            return "ldpi"
        if dpi == 240:
            return "hdpi"
        if dpi == 320:
            return "xhdpi"
        return "mdpi"

    def _build_body(self, ts: int) -> str:
        """
        JSON body for device_register — aligned with JADX X/C938760aXG (RegistrationHeaderHelper)
        + ss_app_log magic_tag. Fresh install uses device_id/install_id \"0\"; optional
        new_user_mode flags first boot (see DeviceRegisterManager.isNewUserMode).
        """
        d    = self.base["device"]
        a    = self.base["app"]
        m    = self.base["meta"]
        loc  = self.base["locale"]
        n    = self.base.get("network") or {}
        dr   = self.base.get("device_register") or {}
        off_s = int(loc["timezone_offset"])
        # JADX: RawOffset ms/3600000 as float hours; same as off_s/3600 for static zones
        tz_hours = round(off_s / 3600.0, 4)

        applog_ver = dr.get("applog_sdk_version", "2.15.0")
        applog_code = dr.get("applog_sdk_version_code", "2150")
        git_hash = dr.get("git_hash", "5ae517f")
        sdk_target = int(dr.get("sdk_target_version", 29))

        manufacturer = d.get("device_manufacturer") or d["device_brand"]
        res_java = self._resolution_height_x_width(d.get("resolution", ""))
        dpi_i = int(d["dpi"])
        display_density = d.get("display_density") or self._dpi_to_display_density(dpi_i)
        disp_name = dr.get("display_name") or m.get("display_name") or "TikTok"
        if "app_version_minor" in dr:
            app_ver_min = dr["app_version_minor"]
        else:
            app_ver_min = m.get("app_version_minor", "0")
        release_build = dr.get("release_build") or m.get("release_build") or m["version"]

        hdr = {
            "display_name":          disp_name,
            "update_version_code":   m["update_version_code"],
            "manifest_version_code": m["manifest_version_code"],
            "app_version_minor":     app_ver_min,
            "aid":                   int(a["aid"]),
            "channel":               a["channel"],
            "os":                    "Android",
            "os_version":            d["os_version"],
            "os_api":                int(d["os_api"]),
            "sdk_version":           applog_ver,
            "sdk_version_code":      str(applog_code),
            "sdk_target_version":    sdk_target,
            "git_hash":              git_hash,
            "device_model":          d["device_type"],
            "device_brand":          d["device_brand"],
            "device_manufacturer":   manufacturer,
            "cpu_abi":               d["host_abi"],
            "release_build":         release_build,
            "density_dpi":           dpi_i,
            "display_density":       display_density,
            "resolution":            res_java,
            "language":              loc["language"],
            "timezone":              tz_hours,
            "access":                n.get("ac", "mobile"),
            "not_request_sender":    0,
            "package":               a["package"],
            "app_version":           m["version"],
            "version_code":          int(m["version_code"]),
            "openudid":              self._openudid.replace("-", "")[:16],
            "cdid":                  self._cdid,
            "clientudid":            self._clientudid,
            "device_id":             "0",
            "install_id":            "0",
            "rom_version":           d.get("build_fingerprint", ""),
            "region":                loc.get("region", loc["sys_region"]),
            "tz_name":               loc["timezone_name"],
            "tz_offset":             off_s,
            "sim_region":            loc["sys_region"],
            "app_language":          loc["app_language"],
            "sys_language":          loc["language"],
        }
        if d.get("rom"):
            hdr["rom"] = d["rom"]
        if "new_user_mode" in dr:
            if dr["new_user_mode"] is not None:
                hdr["new_user_mode"] = dr["new_user_mode"]
        else:
            hdr["new_user_mode"] = 1
        if n.get("mcc_mnc"):
            hdr["mcc_mnc"] = n["mcc_mnc"]
        if n.get("carrier"):
            hdr["carrier"] = n["carrier"]
        sh = dr.get("sig_hash") or d.get("sig_hash")
        if sh:
            hdr["sig_hash"] = sh

        extras = dr.get("header_extras")
        if isinstance(extras, dict):
            hdr.update(extras)
            if extras:
                rid = hdr.get("req_id")
                if rid in (None, "", "REPLACE_UUID_V4"):
                    hdr["req_id"] = self._req_id
                apit = hdr.get("apk_first_install_time")
                if apit in (None, 0, "0"):
                    hdr["apk_first_install_time"] = int(ts * 1000) - secrets.randbelow(2000) - 13000

        body_obj = {
            "magic_tag": "ss_app_log",
            "header": hdr,
            "_gen_time": ts * 1000,
        }
        if "event_filter" in dr:
            if dr["event_filter"] is not None:
                body_obj["event_filter"] = dr["event_filter"]
        elif dr.get("include_event_filter", True):
            body_obj["event_filter"] = 1
        return json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False)

    # ── HTTP ───────────────────────────────────────────────────────────────────

    def _compose_request(self, host: str, wire: str, ts: int) -> dict:
        """Build URL, body, gzip, signing headers, and wire bytes (for _try_host / golden snapshots)."""
        params = self._build_params(ts)
        url = self._build_url(host, params)
        body = self._build_body(ts)
        cookie = self.base.get("session", {}).get("cookie", "store-idc=useast5; tt-target-idc=useast5")
        rticket = ts * 1000

        raw = body.encode("utf-8")
        gz = gzip.compress(raw)

        if wire == "java_gzip_sig":
            sig = _sign(url=url, method="POST", body=gz, cookie=cookie, ts=ts)
            sign_mode = "gzip_bytes"
        else:
            sig = _sign(url=url, method="POST", body=raw, cookie=cookie, ts=ts)
            sign_mode = "raw_utf8_json"

        stub = hashlib.md5(gz).hexdigest().upper()

        # Region info for headers
        loc = self.base.get("locale", {})
        region = loc.get("region", loc.get("sys_region", "US"))

        # ── Complete header set (from H2 HPACK capture of real TikTok v44.3.1) ──
        headers = {
            # Standard
            "User-Agent": self.base["user_agent"],
            "Accept-Encoding": "gzip, deflate, br",
            "Cookie": cookie,

            # Security signatures
            "X-Argus": sig["X-Argus"],
            "X-Gorgon": sig["X-Gorgon"],
            "X-Khronos": str(sig["X-Khronos"]),
            "X-Ladon": sig["X-Ladon"],
            "X-SS-STUB": stub,

            # Required TikTok headers (discovered via H2 HPACK decoding)
            "x-tt-pba-enable": "1",
            "x-tt-dm-status": "login=0;ct=1;rt=6",
            "X-SS-REQ-TICKET": str(rticket),
            "sdk-version": "2",
            "passport-sdk-version": "1",
            "oec-cs-si-a": "2",
            "oec-cs-sdk-version": "v10.02.02.01-bugfix-ov-android_V31",
            "x-vc-bdturing-sdk-version": "2.4.1.i18n",
            "oec-vc-sdk-version": "3.2.1.i18n",
            "rpc-persist-pns-region-1": f"{region}|6252001",
            "rpc-persist-pns-region-2": f"{region}|6252001",
            "rpc-persist-pns-region-3": f"{region}|6252001",
            "x-tt-request-tag": "n=0;nr=011;bg=0;rs=100;s=-1;p=0",
            "x-tt-store-region": region.lower(),
            "x-tt-store-region-src": "did",
            "rpc-persist-pyxis-policy-state-law-is-ca": "0",
            "rpc-persist-pyxis-policy-v-tnc": "1",
            "x-tt-ttnet-origin-host": f"api16-core-useast5.tiktokv.us",
            "x-ss-dp": self.base.get("app", {}).get("aid", "1233"),
            "x-common-params-v2": _build_common_params_v2(self.base),
            "x-tt-trace-id": f"00-{format(ts, '08x')}1069b5d83f35b0060ea904d1-{format(ts, '08x')}1069b5d8-01",
        }

        # Guard headers (device token, ticket guard)
        gh = self.base.get("guard_headers")
        if isinstance(gh, dict):
            for k, v in gh.items():
                if v and k not in headers and not k.startswith("_"):
                    headers[k] = v

        if wire == "java":
            headers["Content-Type"] = "application/octet-stream;tt-data=b"
            headers["Content-Encoding"] = "gzip"
            headers["x-bd-content-encoding"] = "gzip"
            body_bytes = gz
        elif wire == "java_gzip_sig":
            headers["Content-Type"] = "application/octet-stream;tt-data=b"
            headers["Content-Encoding"] = "gzip"
            headers["x-bd-content-encoding"] = "gzip"
            body_bytes = gz
        elif wire == "json_gzip":
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers["Content-Encoding"] = "gzip"
            headers["x-bd-content-encoding"] = "gzip"
            body_bytes = gz
        elif wire == "json_plain":
            headers["Content-Type"] = "application/json; charset=utf-8"
            body_bytes = raw
        else:
            raise ValueError(f"unknown wire format: {wire}")

        xg = sig.get("X-Gorgon") or ""
        return {
            "ts": ts,
            "host": host,
            "wire": wire,
            "url": url,
            "params": params,
            "body_json": body,
            "body_utf8_sha256": hashlib.sha256(raw).hexdigest(),
            "gzip_len": len(gz),
            "gzip_sha256": hashlib.sha256(gz).hexdigest(),
            "sign_mode": sign_mode,
            "headers": headers,
            "body_bytes": body_bytes,
            "cookie": cookie,
            "openudid": self._openudid,
            "cdid": self._cdid,
            "clientudid": self._clientudid,
            "req_id": self._req_id,
            "xgorgon_prefix": xg[:8] if len(xg) >= 8 else xg,
        }

    def _write_golden_snapshot(
        self,
        snap: dict,
        response: object = None,
        path: str = None,
    ) -> str:
        """Write one JSON file for diffing against a real device / MITM capture."""
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        m = self.base.get("meta") or {}
        a = self.base.get("app") or {}
        out = {
            "generator": "tiktok_final.device_register",
            "profile_hint": {
                "version_name": m.get("version"),
                "version_code": m.get("version_code"),
                "aid": a.get("aid"),
                "package": a.get("package"),
                "user_agent_prefix": (self.base.get("user_agent") or "")[:120],
            },
            "request": {k: v for k, v in snap.items() if k != "body_bytes"},
            "response": response,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        return path

    def dump_first_golden(self, out_dir: str) -> str:
        """
        Single POST (log-va, wire=java) + save request snapshot and response.
        Use to align Python output with a MITM golden capture.
        """
        ts = int(time.time())
        host = _HOSTS[0]
        wire = "java"
        snap = self._compose_request(host, wire, ts)
        path = os.path.join(
            out_dir,
            f"golden_device_register_{host}_{wire}_{ts}.json",
        )
        req = urllib.request.Request(snap["url"], method="POST")
        for k, v in snap["headers"].items():
            req.add_header(k, v)

        import ssl as _ssl
        _ctx = _ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode = _ssl.CERT_NONE

        if self.proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}),
                urllib.request.HTTPSHandler(context=_ctx),
            )
            _open = opener.open
        else:
            _open = lambda *a, **kw: urllib.request.urlopen(*a, context=_ctx, **kw)
        try:
            resp = _open(req, data=snap["body_bytes"], timeout=45)
            resp_body = resp.read()
        except urllib.error.HTTPError as e:
            resp_body = e.read()
        except Exception as ex:
            self._write_golden_snapshot(snap, {"_error": str(ex)}, path)
            print(f"[golden] wrote (request only, error): {path}")
            return path

        if resp_body[:2] == b"\x1f\x8b":
            try:
                resp_body = gzip.decompress(resp_body)
            except Exception:
                pass
        try:
            result = json.loads(resp_body.decode("utf-8", errors="replace"))
        except Exception:
            result = {"_raw": resp_body.decode("utf-8", errors="replace")}

        self._write_golden_snapshot(snap, result, path)
        diag = server_response_diagnostics(result)
        print(f"[golden] wrote: {path}")
        if diag:
            print("[golden] response diagnostics:\n" + diag)
        return path

    def _try_host(self, host: str, wire: str = "java"):
        """
        Attempt registration against one host. Uses a **fresh** ts for URL, body _gen_time, and
        signing so _rticket/ts match X-Khronos (per-request, unlike a single stale timestamp).

        JADX X/C938550aWv.LJ + AbstractC938700aXA.LIZ: gzip = standard GZIPOutputStream bytes.

        wire:
          - "java"          — tt-data=b + gzip; sign **uncompressed** JSON (typical ByteDance)
          - "java_gzip_sig" — tt-data=b + gzip; sign **gzip** bytes (some stacks verify wire body)
          - "json_gzip" / "json_plain" — fallbacks
        """
        ts = int(time.time())
        snap = self._compose_request(host, wire, ts)
        url = snap["url"]
        body = snap["body_json"]
        headers = snap["headers"]
        body_bytes = snap["body_bytes"]

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"POST {url}  (wire={wire})")
            for k, v in headers.items():
                print(f"  {k}: {str(v)[:100]}")
            print(f"  Body (uncompressed JSON prefix): {body[:300]}")
            print(f"  sign_mode={snap['sign_mode']}  gzip_sha256={snap['gzip_sha256'][:16]}...")

        req = urllib.request.Request(url, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)

        import ssl as _ssl
        _ctx = _ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode = _ssl.CERT_NONE

        if self.proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}),
                urllib.request.HTTPSHandler(context=_ctx),
            )
            _open = opener.open
        else:
            _open = lambda *a, **kw: urllib.request.urlopen(*a, context=_ctx, **kw)

        try:
            resp = _open(req, data=body_bytes, timeout=45)
            resp_body = resp.read()
        except urllib.error.HTTPError as e:
            resp_body = e.read()
        except Exception as ex:
            print(f"  [{host}] error: {ex}")
            return None

        import gzip as _gzip

        if resp_body[:2] == b"\x1f\x8b":
            try:
                resp_body = _gzip.decompress(resp_body)
            except Exception:
                pass

        try:
            result = json.loads(resp_body.decode("utf-8", errors="replace"))
        except Exception:
            result = {"_raw": resp_body.decode("utf-8", errors="replace")}

        if self.dump_golden_dir:
            gpath = os.path.join(
                self.dump_golden_dir,
                f"device_register_{host}_{wire}_{ts}.json",
            )
            self._write_golden_snapshot(snap, result, gpath)
            print(f"  [golden] saved → {gpath}")

        if self.verbose:
            print(f"  Response (full):\n{json.dumps(result, indent=2, ensure_ascii=False)}")
            diag = server_response_diagnostics(result)
            if diag:
                print(f"  Response diagnostics:\n{diag}")
            else:
                print("  Response diagnostics: (no error_code/message fields)")

        return result

    # ── Public API ─────────────────────────────────────────────────────────────

    def register(self) -> dict:
        """
        Register a new device with TikTok, trying each host in order.

        Returns dict with:
            device_id   : new TikTok device_id (str)
            install_id  : new install_id / iid (str)
            openudid    : openudid used (UUID v4 format)
            cdid        : cdid used (UUID v4 format)
            server_resp : raw server response (or None on fallback)
        """
        # Order: Java wire first, then gzip-stub variant, then plain JSON fallbacks.
        _WIRE_TRIES = ("java", "java_gzip_sig", "json_gzip", "json_plain")

        for host in _HOSTS:
            for wire in _WIRE_TRIES:
                tag = f"{host} wire={wire}"
                print(f"[register] Trying {tag} ...")
                result = self._try_host(host, wire=wire)

                if result is None:
                    continue

                data = result.get("data", result)
                if not isinstance(data, dict):
                    data = result
                raw_did = data.get("device_id", data.get("did"))
                raw_iid = data.get("install_id", data.get("iid", data.get("install_id_str")))
                device_id  = "" if raw_did is None else str(raw_did).strip()
                install_id = "" if raw_iid is None else str(raw_iid).strip()

                if device_id and device_id not in ("0", ""):
                    print(f"  ✓ device_id={device_id}  install_id={install_id}  (server OK)")
                    return {
                        "device_id":   device_id,
                        "install_id":  install_id,
                        "openudid":    self._openudid,
                        "cdid":        self._cdid,
                        "server_resp": result,
                    }

                print(f"  [{tag}] no real device_id: {json.dumps(result)[:200]}")

        if not self.allow_local_fallback:
            raise RuntimeError(
                "TikTok servers did not assign device_id/install_id (all responses had 0). "
                "Check: (1) DNS/adblock not blocking log*.tiktokv.com / log.*.byteoversea.com; "
                "(2) optional \"sig_hash\" (APK sig) in device JSON device_register.sig_hash from a real capture; "
                "(3) residential proxy / non-emulator profile. "
                "Or use --allow-local-fallback for offline-only testing."
            )

        print("[register] Fallback — local IDs only (not registered on TikTok servers)")
        return {
            "device_id":   new_device_id(),
            "install_id":  new_install_id(),
            "openudid":    self._openudid,
            "cdid":        self._cdid,
            "server_resp": None,
        }

    def build_profile(self, reg: dict, out_path: str = None) -> dict:
        """
        Build a complete device JSON profile from registration result.
        Compatible with login_client.py (same schema as device_v44_3_1.json).

        Args:
            reg      : dict returned by register()
            out_path : if given, write JSON to this path

        Returns:
            Full device profile dict
        """
        profile = copy.deepcopy(self.base)

        # Inject new identifiers
        profile["device"]["device_id"] = reg["device_id"]
        profile["device"]["iid"]       = reg["install_id"]
        profile["device"]["openudid"]  = reg["openudid"].replace("-", "")[:16]
        profile["device"]["cdid"]      = reg["cdid"]

        # Update meta
        now = int(time.time())
        profile["meta"]["source_capture"]  = "device_register.py"
        profile["meta"]["registered_at"]   = now
        profile["meta"]["registered_date"]  = (
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        # Build realistic session cookies matching captured traffic
        loc = profile.get("locale", {})
        region = loc.get("region", loc.get("sys_region", "US"))
        idc = profile.get("session", {}).get("idc") or "useast5"

        # Extract IDC from existing cookie if present
        existing_cookie = profile.get("session", {}).get("cookie", "")
        if "store-idc=" in existing_cookie:
            try:
                idc = existing_cookie.split("store-idc=")[1].split(";")[0].strip()
            except (IndexError, AttributeError):
                pass

        # Generate ttreq token (device token hash — 1$<sha1_hex>)
        ttreq_raw = f"{reg['device_id']}:{reg['install_id']}:{now}"
        ttreq_hash = hashlib.sha1(ttreq_raw.encode()).hexdigest()
        ttreq = f"1${ttreq_hash}"

        # Generate odin_tt (128-char hex — device fingerprint hash)
        odin_raw = f"{reg['device_id']}:{reg['openudid']}:{reg['cdid']}:{now}"
        odin_tt = hashlib.sha512(odin_raw.encode()).hexdigest()[:128]

        # Build complete cookie string matching real TikTok traffic
        cookie_parts = [
            f"store-idc={idc}",
            f"store-country-code={region.lower()}",
            "store-country-code-src=did",
            f"install_id={reg['install_id']}",
            f"ttreq={ttreq}",
            f"odin_tt={odin_tt}",
            f"tt-target-idc={idc}",
        ]
        cookie = "; ".join(cookie_parts)

        profile["session"]["cookie"]            = cookie
        profile["session"]["x_tt_token"]        = ""
        profile["session"]["last_install_time"] = str(now)

        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, ensure_ascii=False)
            print(f"[register] Profile saved → {out_path}")

        return profile


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TikTok v44.3.1 — Register a new real device"
    )
    parser.add_argument("--base",    default=None,
                        help="Base hardware profile JSON (default: device_v44_3_1.json)")
    parser.add_argument(
        "--apk",
        default=None,
        metavar="PATH",
        help="مسار APK — استخراج sig_hash (MD5 كتلة التوقيع v1) ودمجه في device_register قبل الطلب",
    )
    parser.add_argument(
        "--extract-sig-only",
        action="store_true",
        help="مع --apk و --out: يحدّث JSON بـ sig_hash فقط دون تسجيل جهاز على الخادم",
    )
    parser.add_argument(
        "--virtual",
        metavar="REGION",
        default=None,
        help="Build base from virtual_devices.generate_device_profile(REGION), e.g. US, EG (overrides --base)",
    )
    parser.add_argument("--out",     default=None,
                        help="Output device JSON (default: device_<ts>.json)")
    parser.add_argument("--proxy",   default=None,
                        help="HTTP proxy e.g. http://user:pass@host:port")
    parser.add_argument("--proxy-file", default=None,
                        help="First host:port:user:pass line → proxy URL")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full request/response")
    parser.add_argument(
        "--allow-local-fallback",
        action="store_true",
        help="If TikTok returns only 0, still write a profile with random local IDs (NOT server-registered)",
    )
    parser.add_argument(
        "--dump-golden",
        metavar="DIR",
        default=None,
        help="Save request+response JSON per attempt (for comparison with MITM capture)",
    )
    parser.add_argument(
        "--golden-only",
        metavar="DIR",
        default=None,
        help="Run a single device_register (log-va, java), write golden JSON, exit 0 (no full register loop)",
    )
    args = parser.parse_args()

    if args.extract_sig_only:
        if not args.apk:
            parser.error("--extract-sig-only requires --apk")
        if not args.out:
            parser.error("--extract-sig-only requires --out")

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

    def _load_base_dict() -> dict:
        if args.virtual is not None:
            from .virtual_devices import generate_device_profile, profile_to_device_register_base

            return profile_to_device_register_base(generate_device_profile(args.virtual))
        base_file = args.base or os.path.join(FIXTURES_DIR, "device_v44_3_1.json")
        if not os.path.isabs(base_file):
            base_file = resolve_data_path(base_file)
        with open(base_file, encoding="utf-8") as f:
            return json.load(f)

    base_dict = None
    base_path = args.base
    if args.virtual is not None:
        base_dict = _load_base_dict()
        base_path = None
    elif args.apk or args.extract_sig_only:
        base_dict = _load_base_dict()
        base_path = None

    if args.apk:
        apk_path = args.apk if os.path.isabs(args.apk) else os.path.join(os.getcwd(), args.apk)
        if not os.path.isfile(apk_path):
            apk_path = os.path.join(PROJECT_ROOT, args.apk)
        base_dict, sig_info = merge_sig_hash_into_base(base_dict, apk_path)
        if args.verbose or args.extract_sig_only:
            print(f"[apk] {sig_info}")
        if sig_info.get("error") and not sig_info.get("sig_hash"):
            print(f"[apk] WARNING: {sig_info.get('error')}", file=sys.stderr)
        if args.extract_sig_only:
            if not sig_info.get("sig_hash"):
                print("[apk] فشل استخراج sig_hash — تحقق من مسار APK (ملف كامل وليس split).", file=sys.stderr)
                sys.exit(2)
            out_path = args.out if os.path.isabs(args.out) else os.path.join(os.getcwd(), args.out)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(base_dict, f, indent=2, ensure_ascii=False)
            print(f"[apk] sig_hash → {sig_info.get('sig_hash')}")
            print(f"[apk] saved → {out_path}")
            sys.exit(0)

    dr = TikTokDeviceRegister(
        base_path=base_path,
        base_dict=base_dict,
        proxy=proxy_url,
        verbose=args.verbose,
        allow_local_fallback=args.allow_local_fallback,
        dump_golden_dir=None if args.golden_only else args.dump_golden,
    )

    if args.golden_only:
        gdir = args.golden_only if os.path.isabs(args.golden_only) else os.path.join(PROJECT_ROOT, args.golden_only)
        dr.dump_first_golden(gdir)
        sys.exit(0)

    try:
        reg = dr.register()
    except RuntimeError as e:
        print(f"[register] FAILED: {e}", file=sys.stderr)
        sys.exit(1)

    out_path = args.out or os.path.join(PROJECT_ROOT, f"device_{int(time.time())}.json")
    profile  = dr.build_profile(reg, out_path)

    print("\n" + "="*60)
    print("New Device Identifiers:")
    print(f"  device_id  : {reg['device_id']}")
    print(f"  install_id : {reg['install_id']}")
    print(f"  openudid   : {reg['openudid']}")
    print(f"  cdid       : {reg['cdid']}")
    src = "server" if reg["server_resp"] else "local fallback"
    print(f"  source     : {src}")
    print(f"\nProfile saved → {out_path}")
    print(f"\nNext step — login with new device:")
    print(f"  python3 -m ttk.login_client --device {out_path} --username USER --password PASS")
