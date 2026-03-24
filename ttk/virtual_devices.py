#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
virtual_devices.py — توليد بروفايل جهاز أندرويد ديناميكي كامل
================================================================
كل قيمة تُولَّد عشوائياً (device_id, iid, ECDSA key pair, ...).
لا توجد قيم مثبّتة — كل جهاز فريد تماماً.
"""

import base64
import json
import os
import random
import secrets
import time
import uuid

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from .paths import FIXTURES_DIR

# ── قائمة أجهزة أندرويد واقعية للتنويع ───────────────────────────────────────
_DEVICE_MODELS = [
    # (device_type, device_brand, os_api, os_version, resolution, dpi, host_abi)
    # Samsung Galaxy S series
    ("SM-S928B",  "samsung", "35", "15", "1440*3120", "560", "arm64-v8a"),  # S24 Ultra
    ("SM-S926B",  "samsung", "35", "15", "1080*2340", "420", "arm64-v8a"),  # S24+
    ("SM-S921B",  "samsung", "35", "15", "1080*2340", "420", "arm64-v8a"),  # S24
    ("SM-S918B",  "samsung", "34", "14", "1440*3088", "560", "arm64-v8a"),  # S23 Ultra
    ("SM-S916B",  "samsung", "34", "14", "1080*2340", "420", "arm64-v8a"),  # S23+
    ("SM-S911B",  "samsung", "34", "14", "1080*2340", "420", "arm64-v8a"),  # S23
    ("SM-G991B",  "samsung", "34", "14", "1080*2400", "420", "arm64-v8a"),  # S21
    # Samsung Galaxy A series
    ("SM-A556B",  "samsung", "35", "15", "1080*2340", "420", "arm64-v8a"),  # A55
    ("SM-A546B",  "samsung", "34", "14", "1080*2340", "420", "arm64-v8a"),  # A54
    ("SM-A536B",  "samsung", "34", "14", "1080*2408", "450", "arm64-v8a"),  # A53
    # Google Pixel
    ("Pixel 8 Pro", "google", "35", "15", "1344*2992", "489", "arm64-v8a"),
    ("Pixel 8",     "google", "35", "15", "1080*2400", "428", "arm64-v8a"),
    ("Pixel 7 Pro", "google", "34", "14", "1440*3120", "512", "arm64-v8a"),
    ("Pixel 7",     "google", "34", "14", "1080*2400", "416", "arm64-v8a"),
    # Xiaomi
    ("2311DRK48C", "Xiaomi", "34", "14", "1440*3200", "522", "arm64-v8a"),  # 14 Pro
    ("M2101K6G",   "Xiaomi", "34", "14", "1080*2400", "440", "arm64-v8a"),  # Mi 11
    ("2201116TG",  "Xiaomi", "34", "14", "1080*2400", "440", "arm64-v8a"),  # 12
    # OnePlus
    ("CPH2449",   "OnePlus", "34", "14", "1440*3216", "526", "arm64-v8a"),  # 11
    ("NE2215",    "OnePlus", "34", "14", "1080*2400", "420", "arm64-v8a"),  # 10 Pro
    # OPPO / realme / vivo
    ("CPH2269",   "OPPO",    "34", "14", "1080*2400", "409", "arm64-v8a"),
    ("RMX3085",   "realme",  "34", "14", "1080*2400", "409", "arm64-v8a"),
    ("V2109",     "vivo",    "34", "14", "1080*2400", "440", "arm64-v8a"),
]

# ── نطاقات timezone حسب المنطقة ─────────────────────────────────────────────
_REGION_TZ = {
    "US": ("America/New_York", "-18000"),
    "GB": ("Europe/London",    "0"),
    "CA": ("America/Toronto",  "-18000"),
    "AU": ("Australia/Sydney", "39600"),
    "MY": ("Asia/Kuala_Lumpur","28800"),
    "SG": ("Asia/Singapore",   "28800"),
    "ID": ("Asia/Jakarta",     "25200"),
    "TH": ("Asia/Bangkok",     "25200"),
    "BR": ("America/Sao_Paulo","-10800"),
    "MX": ("America/Mexico_City","-21600"),
    "FR": ("Europe/Paris",     "3600"),
    "DE": ("Europe/Berlin",    "3600"),
    "JP": ("Asia/Tokyo",       "32400"),
    "KR": ("Asia/Seoul",       "32400"),
    "SA": ("Asia/Riyadh",      "10800"),
    "AE": ("Asia/Dubai",       "14400"),
    "IN": ("Asia/Kolkata",     "19800"),
    "PH": ("Asia/Manila",      "28800"),
    "VN": ("Asia/Ho_Chi_Minh", "25200"),
    "TW": ("Asia/Taipei",      "28800"),
    "EG": ("Africa/Cairo",     "7200"),
    "TR": ("Europe/Istanbul",  "10800"),
    "AR": ("America/Argentina/Buenos_Aires", "-10800"),
    "CO": ("America/Bogota",   "-18000"),
    "NG": ("Africa/Lagos",     "3600"),
    "PK": ("Asia/Karachi",     "18000"),
    "BD": ("Asia/Dhaka",       "21600"),
}

# ── MCC/MNC افتراضي حسب المنطقة ─────────────────────────────────────────────
_REGION_MCC = {
    "US": "310260", "GB": "23420", "CA": "302220",
    "AU": "50501",  "MY": "50216", "SG": "52505",
    "ID": "51021",  "TH": "52001", "BR": "72410",
    "MX": "33420",  "FR": "20815", "DE": "26207",
    "JP": "44020",  "KR": "45008", "SA": "42001",
    "AE": "42402",  "IN": "40415", "PH": "51503",
    "VN": "45204",  "TW": "46601", "EG": "60201",
    "TR": "28603",  "AR": "22210", "CO": "73001",
    "NG": "62120",  "PK": "41001", "BD": "47001",
}

# ── IDC (install datacenter) حسب المنطقة ─────────────────────────────────────
_REGION_IDC = {
    "US": "useast5", "GB": "eu", "CA": "useast5",
    "AU": "sg",      "MY": "my", "SG": "sg",
    "ID": "sg",      "TH": "sg", "BR": "us",
    "MX": "useast5", "FR": "eu", "DE": "eu",
    "JP": "jp",      "KR": "kr", "SA": "sg",
    "AE": "sg",      "IN": "sg", "PH": "sg",
    "VN": "sg",      "TW": "sg", "EG": "eu",
    "TR": "eu",      "AR": "us", "CO": "us",
    "NG": "eu",      "PK": "sg", "BD": "sg",
}


# ─────────────────────────────────────────────────────────────────────────────
#  تحويل توقيع P1363 (64 بايت R||S) إلى DER (تنسيق ASN.1)
# ─────────────────────────────────────────────────────────────────────────────
def _p1363_to_der(sig64: bytes) -> bytes:
    """تحويل توقيع ECDSA-P256 من P1363 إلى DER-ASN.1."""
    assert len(sig64) == 64
    r = sig64[:32]
    s = sig64[32:]

    def encode_int(b: bytes) -> bytes:
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    r_enc = encode_int(r)
    s_enc = encode_int(s)
    seq = r_enc + s_enc
    return bytes([0x30, len(seq)]) + seq


# ─────────────────────────────────────────────────────────────────────────────
#  توليد ID جهاز عشوائي (19 رقم كـ TikTok)
# ─────────────────────────────────────────────────────────────────────────────
def _rand_device_id() -> str:
    return str(random.randint(7_000_000_000_000_000_000, 7_999_999_999_999_999_999))


# ─────────────────────────────────────────────────────────────────────────────
#  حساب dtoken_sign لجهاز جديد
# ─────────────────────────────────────────────────────────────────────────────
def _compute_dtoken_sign(device_token_inner: str, private_key) -> str:
    """توقيع device_token_inner بـ ECDSA-P256-SHA256 وإرجاع ts.1.{DER_b64}."""
    h = SHA256.new(device_token_inner.encode("utf-8"))
    signer = DSS.new(private_key, "fips-186-3")
    sig_p1363 = signer.sign(h)
    sig_der = _p1363_to_der(sig_p1363)
    return "ts.1." + base64.b64encode(sig_der).decode()


def compute_dreq_sign(device_token: str, path: str, timestamp: int, private_key) -> str:
    """
    توقيع per-request لـ dreq_sign.
    المحتوى: device_token + path + str(timestamp)
    المصدر: BDDeviceTokenInterceptor / tt-device-guard-client-data req_content
    """
    msg = (device_token + path + str(timestamp)).encode("utf-8")
    h = SHA256.new(msg)
    signer = DSS.new(private_key, "fips-186-3")
    sig_p1363 = signer.sign(h)
    sig_der = _p1363_to_der(sig_p1363)
    return "ts.1." + base64.b64encode(sig_der).decode()


def compute_treq_sign(ticket: str, path: str, timestamp: int, private_key) -> str:
    """
    توقيع per-request لـ req_sign في tt-ticket-guard-client-data.
    المحتوى: ticket + path + str(timestamp)
    """
    msg = (ticket + path + str(timestamp)).encode("utf-8")
    h = SHA256.new(msg)
    signer = DSS.new(private_key, "fips-186-3")
    sig_p1363 = signer.sign(h)
    sig_der = _p1363_to_der(sig_p1363)
    return "ts.1." + base64.b64encode(sig_der).decode()


# ─────────────────────────────────────────────────────────────────────────────
#  توليد بروفايل جهاز جديد كامل
# ─────────────────────────────────────────────────────────────────────────────
def generate_device_profile(region: str = "US") -> dict:
    """
    توليد بروفايل جهاز أندرويد جديد كامل:
      - device_id, iid, openudid, cdid: عشوائية
      - ECDSA P-256 key pair: جديد لكل جهاز
      - dtoken_sign: محسوب تلقائياً
      - جميع معلمات الجهاز: واقعية
    """
    region = (region or "US").upper()
    now = int(time.time())

    # جهاز عشوائي
    model = random.choice(_DEVICE_MODELS)
    device_type, device_brand, os_api, os_version, resolution, dpi, host_abi = model

    # IDs
    device_id = _rand_device_id()
    iid = _rand_device_id()
    openudid = secrets.token_hex(8)
    cdid = str(uuid.uuid4())
    fit = str(now - random.randint(7 * 86400, 90 * 86400))   # installed 1–3 months ago

    # Timezone
    tz_name, tz_offset = _REGION_TZ.get(region, ("America/New_York", "-18000"))
    mcc_mnc = _REGION_MCC.get(region, "310260")
    idc = _REGION_IDC.get(region, "us")

    # App version (44.3.15) — matches MITM proxy capture 2026-03-23
    version_name = "44.3.15"
    manifest_version_code = "2024403150"
    update_version_code = "2024403150"
    version_code = manifest_version_code
    ab_version = version_name
    build_number = version_name

    # Screen dimensions in dp (derived from resolution + dpi)
    _w_px, _h_px = map(int, resolution.split("*"))
    _density = int(dpi) / 160.0
    screen_width  = str(round(_w_px / _density))
    screen_height = str(round(_h_px / _density))

    # User-Agent
    user_agent = (
        f"com.zhiliaoapp.musically/{manifest_version_code} "
        f"(Linux; U; Android {os_version}; en; {device_type}; "
        f"Build/BE2A.250530.026.F3; Cronet/TTNetVersion:80a1e1d9 2026-01-21 "
        f"QuicVersion:5f252c33 2025-12-30)"
    )

    # ECDSA P-256 key pair
    ec_key = ECC.generate(curve="P-256")
    pub_raw = ec_key.public_key().export_key(format="raw")   # 04 || X || Y (65 bytes)
    pub_b64 = base64.b64encode(pub_raw).decode()
    priv_pem = ec_key.export_key(format="PEM")

    # device_token_inner + dtoken_sign
    device_token_inner = json.dumps(
        {
            "aid": 1233,
            "av":  version_name,
            "did": device_id,
            "iid": iid,
            "fit": fit,
            "s":   1,
            "idc": idc,
            "ts":  fit,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    dtoken_sign = _compute_dtoken_sign(device_token_inner, ec_key)

    return {
        # Identity
        "device_id":          device_id,
        "iid":                iid,
        "openudid":           openudid,
        "cdid":               cdid,
        "first_install_time": fit,

        # Hardware
        "device_type":   device_type,
        "device_brand":  device_brand,
        "os_api":        os_api,
        "os_version":    os_version,
        "resolution":    resolution,
        "dpi":           dpi,
        "host_abi":      host_abi,
        "device_platform": "android",

        # App
        "aid":                   "1233",
        "app_name":              "musical_ly",
        "app_type":              "normal",
        "channel":               "googleplay",
        "version_name":          version_name,
        "app_version":           version_name,   # alias so login_api.py finds it directly
        "version_code":          version_code,
        "manifest_version_code": manifest_version_code,
        "update_version_code":   update_version_code,
        "ab_version":            ab_version,
        "build_number":          build_number,

        # Screen
        "screen_width":  screen_width,
        "screen_height": screen_height,

        # Locale
        "region":          region,
        "sys_region":      region,
        "op_region":       region,
        "carrier_region":  region,
        "current_region":  region,
        "residence":       region,
        "language":        "en",
        "app_language":    "en",
        "locale":          "en",
        "timezone_name":   tz_name,
        "timezone_offset": tz_offset,
        "mcc_mnc":         mcc_mnc,
        "carrier_region_v2": mcc_mnc[:3],

        # Network
        "ac":    "wifi",
        "ac2":   "unknown",   # captured traffic shows "unknown", not "wifi"
        "ssmix": "a",
        "uoo":   "1",         # captured traffic shows "1" (opted out)
        "is_pad": "0",
        "last_install_time": fit,

        # UA
        "user_agent": user_agent,

        # Signing
        "license_id":      1611921764,
        "sdk_version_str": "v04.04.05-ov-android",
        "sdk_version_int": 134744640,

        # SDK versions (from MITM proxy capture 2026-03-23)
        "oec_cs_sdk_version": "v10.02.02.01-bugfix-ov-android_V31",
        "vc_bdturing_sdk_version": "2.4.1.i18n",
        "oec_vc_sdk_version": "3.2.1.i18n",
        "sig_hash": "194326e82c84a639a52e5c023116f12a",

        # Device guard (ECDSA)
        "ticket_guard_public_key": pub_b64,
        "ecdsa_private_key_pem":   priv_pem,
        "dtoken_sign":             dtoken_sign,
        "device_token_inner":      device_token_inner,
        "device_token":            f"1|{device_token_inner}",
        "idc":                     idc,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  إدارة قاعدة الأجهزة (JSON على القرص)
# ─────────────────────────────────────────────────────────────────────────────
_DEFAULT_PATH = os.path.join(FIXTURES_DIR, "virtual_devices.json")


def load_devices(path: str = _DEFAULT_PATH) -> list:
    """تحميل قائمة الأجهزة المحفوظة."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_devices(devices: list, path: str = _DEFAULT_PATH) -> None:
    """حفظ قائمة الأجهزة."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(devices, f, ensure_ascii=False, indent=2)


def get_device(device_id: str, path: str = _DEFAULT_PATH) -> dict | None:
    """جلب جهاز بـ device_id."""
    for d in load_devices(path):
        if isinstance(d, dict) and str(d.get("device_id")) == str(device_id):
            return d
    return None


def get_device_for_region(region: str, path: str = _DEFAULT_PATH, random_choice: bool = False) -> dict | None:
    """جلب أول جهاز مطابق للمنطقة."""
    region = (region or "US").upper()
    matches = [d for d in load_devices(path) if isinstance(d, dict) and str(d.get("region", "")).upper() == region]
    if not matches:
        return None
    return random.choice(matches) if random_choice else matches[0]


def get_device_with_guard(path: str = _DEFAULT_PATH) -> dict | None:
    """جلب أول جهاز يملك مفاتيح ECDSA."""
    for d in load_devices(path):
        if isinstance(d, dict) and d.get("ecdsa_private_key_pem") and d.get("dtoken_sign"):
            return d
    return None


def get_device_with_guard_for_region(region: str, path: str = _DEFAULT_PATH) -> dict | None:
    """جلب جهاز بمفاتيح ECDSA ومطابق للمنطقة."""
    region = (region or "US").upper()
    for d in load_devices(path):
        if (isinstance(d, dict)
                and str(d.get("region", "")).upper() == region
                and d.get("ecdsa_private_key_pem")
                and d.get("dtoken_sign")):
            return d
    return None


def import_device_from_request_file(path: str) -> dict | None:
    """
    استيراد جهاز من ملف request (JSON أو plain text مع headers).
    يقرأ device_id, iid, User-Agent من الملف ويبني بروفايل جزئي.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}

        device_id = (
            data.get("device_id")
            or _extract_param(content, "device_id")
        )
        iid = (
            data.get("iid")
            or _extract_param(content, "iid")
        )
        ua = data.get("user_agent") or data.get("User-Agent") or _extract_header(content, "User-Agent")

        if not device_id:
            return None

        profile = generate_device_profile(region="US")
        profile["device_id"] = str(device_id)
        if iid:
            profile["iid"] = str(iid)
        if ua:
            profile["user_agent"] = ua
        return profile
    except Exception:
        return None


def _extract_param(text: str, key: str) -> str:
    """استخراج قيمة من query string أو JSON داخل نص."""
    import re
    m = re.search(rf"[?&]{re.escape(key)}=([^&\s\"]+)", text)
    return m.group(1) if m else ""


def _extract_header(text: str, header: str) -> str:
    """استخراج قيمة هيدر من نص HTTP raw."""
    import re
    m = re.search(rf"^{re.escape(header)}:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else ""


# ─────────────────────────────────────────────────────────────────────────────
#  بناء device guard headers ديناميكياً لأي بروفايل
# ─────────────────────────────────────────────────────────────────────────────
def profile_to_device_register_base(profile: dict) -> dict:
    """
    تحويل مخرجات ``generate_device_profile()`` إلى نفس مخطط ``device_v44_3_1.json``
    لاستخدامه مع ``TikTokDeviceRegister`` / ``login_client``.
    """
    now = int(time.time())
    brand = profile.get("device_brand") or "generic"
    manu = brand[:1].upper() + brand[1:] if brand else "Generic"
    m = profile.get("meta") or {}
    version_name = profile.get("version_name") or m.get("version", "44.3.15")
    vcode = profile.get("version_code") or m.get("version_code", "2024403150")
    mvc = profile.get("manifest_version_code") or m.get("manifest_version_code", "2024403150")
    uvc = profile.get("update_version_code") or m.get("update_version_code", mvc)
    ab = profile.get("ab_version") or version_name
    bn = profile.get("build_number") or version_name
    tz_off = str(profile.get("timezone_offset", "0"))
    cr_v2 = profile.get("carrier_region_v2")
    if cr_v2 is None and profile.get("mcc_mnc"):
        cr_v2 = str(profile["mcc_mnc"])[:3]
    else:
        cr_v2 = str(cr_v2 or "310")
    fp = profile.get("build_fingerprint") or "BE2A.250530.026.F3"
    gh = build_device_guard_headers(profile, path="/service/2/device_register/")
    guard = {
        **gh,
        "sdk-version": "2",
        "passport-sdk-settings": "x-tt-token",
        "passport-sdk-sign": "x-tt-token",
        "passport-sdk-version": "1",
        "x-tt-bypass-dp": "1",
        "x-vc-bdturing-sdk-version": "2.4.1.i18n",
    }
    region = profile.get("sys_region") or profile.get("region") or "US"
    idc = profile.get("idc") or _REGION_IDC.get(region.upper(), "useast5")
    return {
        "_comment": "Generated from virtual_devices.generate_device_profile — use with device_register / login_client",
        "meta": {
            "version": version_name,
            "version_code": str(vcode),
            "manifest_version_code": str(mvc),
            "update_version_code": str(uvc),
            "ab_version": ab,
            "build_number": bn,
            "source_capture": "virtual_devices.profile_to_device_register_base",
            "captured_at": now,
            "captured_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        },
        "device": {
            "device_id": str(profile.get("device_id", "0")),
            "iid": str(profile.get("iid", "0")),
            "openudid": profile.get("openudid", ""),
            "cdid": profile.get("cdid", ""),
            "device_type": profile["device_type"],
            "device_brand": profile["device_brand"],
            "device_manufacturer": profile.get("device_manufacturer") or manu,
            "os_version": str(profile["os_version"]),
            "os_api": str(profile["os_api"]),
            "resolution": profile["resolution"],
            "dpi": str(profile["dpi"]),
            "host_abi": profile["host_abi"],
            "build_fingerprint": fp,
            "is_pad": str(profile.get("is_pad", "0")),
        },
        "app": {
            "app_name": profile.get("app_name", "musical_ly"),
            "package": "com.zhiliaoapp.musically",
            "aid": profile.get("aid", "1233"),
            "channel": profile.get("channel", "googleplay"),
            "ssmix": profile.get("ssmix", "a"),
            "app_type": profile.get("app_type", "normal"),
            "support_webview": "1",
        },
        "network": {
            "ac": profile.get("ac", "wifi"),
            "ac2": profile.get("ac2", "unknown"),
            "mcc_mnc": profile.get("mcc_mnc", "310260"),
            "carrier_region": profile.get("carrier_region", region),
            "carrier_region_v2": cr_v2,
        },
        "locale": {
            "timezone_name": profile["timezone_name"],
            "timezone_offset": tz_off,
            "language": profile.get("language", "en"),
            "locale": profile.get("locale", "en"),
            "app_language": profile.get("app_language", "en"),
            "sys_region": region,
            "region": region,
            "op_region": profile.get("op_region", region),
            "uoo": str(profile.get("uoo", "1")),
        },
        "device_register": {
            "applog_sdk_version": "2.15.0",
            "applog_sdk_version_code": "2150",
            "git_hash": profile.get("git_hash") or "5ae517f",
            "sdk_target_version": 29,
            "sig_hash": profile.get("sig_hash") or "194326e82c84a639a52e5c023116f12a",
            "sdk_version": profile.get("sdk_version") or "2.5.14.3",
            "sdk_version_code": profile.get("sdk_version_code") or 205140390,
            "release_build": version_name,
            "include_event_filter": True,
        },
        "user_agent": profile["user_agent"],
        "session": {
            "cookie": f"store-idc={idc}; store-country-code={region.lower()}; store-country-code-src=did; tt-target-idc={idc}",
            "last_install_time": str(profile.get("last_install_time", now)),
            "x_tt_token": "",
        },
        "guard_headers": guard,
    }


def build_device_guard_headers(profile: dict, path: str = "/passport/user/login/") -> dict:
    """
    بناء tt-device-guard-* و tt-ticket-guard-* ديناميكياً.
    إذا كان profile يحتوي ecdsa_private_key_pem → يُحسب dreq_sign و req_sign تلقائياً.
    """
    device_token = profile.get("device_token") or f"1|{profile.get('device_token_inner', '')}"
    pub_b64 = profile.get("ticket_guard_public_key", "")
    dtoken_sign = profile.get("dtoken_sign", "")
    now = int(time.time())

    dreq_sign = ""
    req_sign = ""

    ec_key = None
    pem = profile.get("ecdsa_private_key_pem", "")
    if pem:
        try:
            ec_key = ECC.import_key(pem)
        except Exception:
            ec_key = None

    if ec_key:
        try:
            dreq_sign = compute_dreq_sign(device_token, path, now, ec_key)
        except Exception:
            dreq_sign = ""
        try:
            req_sign = compute_treq_sign("", path, now, ec_key)
        except Exception:
            req_sign = ""

    device_data = {
        "device_token": device_token,
        "timestamp":    now,
        "req_content":  "device_token,path,timestamp",
        "dtoken_sign":  dtoken_sign,
        "dreq_sign":    dreq_sign,
    }
    ticket_data = {
        "req_content": "ticket,path,timestamp",
        "req_sign":    req_sign,
        "timestamp":   now,
        "ts_sign":     "",
    }

    return {
        "tt-ticket-guard-version":            "3",
        "tt-ticket-guard-public-key":         pub_b64,
        "tt-ticket-guard-iteration-version":  "0",
        "tt-ticket-guard-client-data":        base64.b64encode(
            json.dumps(ticket_data, ensure_ascii=False).encode()
        ).decode(),
        "tt-device-guard-iteration-version":  "1",
        "tt-device-guard-client-data":        base64.b64encode(
            json.dumps(device_data, ensure_ascii=False).encode()
        ).decode(),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  CLI: توليد جهاز جديد
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    region = sys.argv[1] if len(sys.argv) > 1 else "US"
    p = generate_device_profile(region=region)
    devices = load_devices()
    devices.append(p)
    save_devices(devices)
    print(f"[+] جهاز جديد: device_id={p['device_id']} iid={p['iid']} region={p['region']}")
    print(json.dumps({k: v for k, v in p.items() if k != "ecdsa_private_key_pem"}, ensure_ascii=False, indent=2))
