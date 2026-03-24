#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TikTok Android request signing via RapidAPI (tiktok-api-signer … /android/get_sign).

Returns the same header shape as signing_engine.sign(): X-Argus, X-Gorgon, X-Khronos, X-Ladon,
and X-SS-STUB when the body is non-empty (stub is computed locally; API does not return it).

Environment:
  RAPIDAPI_KEY       — required for remote signing
  RAPIDAPI_SIGN_URL  — optional, default RapidAPI endpoint
  RAPIDAPI_SIGN_HOST — optional, default x-rapidapi-host value

get_sign **never** uses a proxy: HTTP(S)_PROXY, ALL_PROXY, and system proxy are ignored
so calls always use a direct route (unlike TikTok requests in login_client).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request


def dev_info_from_profile(prof: dict) -> dict:
    """
    Map device_v44_3_1-style profile → dev_info for /android/get_sign.

    Optional overrides in profile["rapidapi_dev_info"] (merged on top), e.g.::
        "rapidapi_dev_info": {
            "mssdk_ver_str": "v05.02.00-ov-android",
            "mssdk_ver_code": "205140390",
            "license_id": "1611921764"
        }
    """
    d = prof.get("device") or {}
    a = prof.get("app") or {}
    m = prof.get("meta") or {}
    ov = d.get("os_version")
    if ov is None or ov == "":
        ov = "14"
    base = {
        "app_id": str(a.get("aid", "1233")),
        "device_id": str(d.get("device_id", "")),
        "mssdk_ver_str": "v05.02.00-ov-android",
        "mssdk_ver_code": str(m.get("sdk_version_code", 205140390)),
        "app_version": str(m.get("version", "44.3.15")),
        "channel": str(a.get("channel", "googleplay")),
        "license_id": "1611921764",
        "device_type": str(d.get("device_type", "SM-S916B")),
        "os": "Android",
        "os_version": str(ov),
        "sec_device_id_token": "",
        "lanusk": "",
        "lanusv": "",
        "seed": "",
        "seed_algorithm": "",
    }
    extra = prof.get("rapidapi_dev_info")
    if isinstance(extra, dict):
        base.update({k: str(v) if v is not None else "" for k, v in extra.items()})
    return base


def sign_via_rapidapi(
    url: str,
    method: str,
    body: str | bytes,
    cookie: str,
    dev_info: dict,
    api_key: str | None = None,
) -> dict:
    """
    Call RapidAPI get_sign and return headers compatible with signing_engine.sign().
    """
    from .signing_engine import compute_stub

    key = (api_key or os.environ.get("RAPIDAPI_KEY") or os.environ.get("X_RAPIDAPI_KEY") or "").strip()
    if not key:
        raise ValueError("RapidAPI signing requires RAPIDAPI_KEY (or pass api_key=)")

    endpoint = (
        os.environ.get("RAPIDAPI_SIGN_URL") or ""
    ).strip() or "https://tiktok-api-signer.p.rapidapi.com/android/get_sign"
    host = (os.environ.get("RAPIDAPI_SIGN_HOST") or "").strip() or "tiktok-api-signer.p.rapidapi.com"

    method_u = (method or "GET").upper()
    body_bytes = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    if method_u == "GET" or not body_bytes:
        payload_b64 = ""
    else:
        payload_b64 = base64.b64encode(body_bytes).decode("ascii")

    req_obj: dict = {"url": url, "dev_info": dev_info, "payload": payload_b64}
    if cookie:
        req_obj["cookie"] = cookie

    data = json.dumps(req_obj, ensure_ascii=False).encode("utf-8")
    ua = (
        os.environ.get("RAPIDAPI_HTTP_USER_AGENT") or ""
    ).strip() or (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    req = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": ua,
            "x-rapidapi-host": host,
            "x-rapidapi-key": key,
        },
    )
    ctx = ssl.create_default_context()
    # Never use any proxy for RapidAPI (env + system): direct connection only.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPHandler(),
    )
    try:
        with opener.open(req, timeout=90) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:2000]
        hint = ""
        if e.code == 403 and ("1010" in err_body or "cloudflare" in err_body.lower()):
            hint = (
                " (Cloudflare 403/1010: جرّب شبكة أخرى أو راجع اشتراك RapidAPI؛ "
                "get_sign يتصل مباشرة بدون بروكسي.)"
            )
        raise RuntimeError(f"RapidAPI get_sign HTTP {e.code}: {err_body}{hint}") from e

    try:
        j = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"RapidAPI get_sign invalid JSON: {raw[:500]}") from e

    def _g(k: str) -> str:
        v = j.get(k)
        if v is None and k != k.lower():
            v = j.get(k.lower())
        if v is None:
            return ""
        return str(v).strip()

    kh = _g("x-khronos") or _g("X-Khronos")
    if not kh:
        raise RuntimeError(f"RapidAPI response missing x-khronos: {raw[:500]}")

    out = {
        "X-Khronos": kh,
        "X-Gorgon": _g("x-gorgon") or _g("X-Gorgon"),
        "X-Ladon": _g("x-ladon") or _g("X-Ladon"),
        "X-Argus": _g("x-argus") or _g("X-Argus"),
    }
    if not all(out.get(k) for k in ("X-Gorgon", "X-Ladon", "X-Argus")):
        raise RuntimeError(f"RapidAPI response missing sign fields: {raw[:800]}")

    if body_bytes and method_u != "GET":
        out["X-SS-STUB"] = compute_stub(body_bytes)

    return out
