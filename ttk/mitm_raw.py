#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mitm_raw.py — قراءة مجلدات اعتراض api-proxy / Charles بنفس تسمية الملفات:

  ``[NNNN] Request - host_path.txt``

يُستخدم لاستخراج كيف تُجلب القيم وتُرسل (URL، Cookie، User-Agent، توقيعات، body)
ومقارنتها مع ``login_client`` / ``signing_engine``.

تصدير بصمة جهاز من مجلد Raw::

    python3 mitm_raw.py /path/to/Raw_03-23-....folder \\
        --export-device device_mitm_fingerprint_Raw_03_23.json \\
        --template fixtures/device_v44_3_1.json

    # أو ملف طلب محدد:
    python3 mitm_raw.py /path/to/Raw_....folder \\
        --export-device out.json --template fixtures/device_v44_3_1.json \\
        --from-file \"[841] Request - ...check_login_name_registered_.txt\"
"""

from __future__ import annotations

import copy
import json
import os
import re
import urllib.parse
from typing import Any, Iterator

from .paths import resolve_data_path


def parse_raw_request(path: str) -> tuple[str, str, dict[str, str], str]:
    """
    يستخرج (method, full_url, headers_dict, body) من ملف طلب خام.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    lines = content.replace("\r\n", "\n").split("\n")
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2:
        raise ValueError(f"Bad first line in {path!r}")
    method = parts[0]
    path_with_query = parts[1]
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            break
        if ":" in line:
            name, val = line.split(":", 1)
            headers[name.strip()] = val.strip()
        i += 1
    body = "\n".join(lines[i:]).strip()
    host = headers.get("Host") or headers.get("host") or ""
    scheme = "https"
    url = f"{scheme}://{host}{path_with_query}"
    return method, url, headers, body


def _natural_sort_key(name: str) -> tuple[int, str]:
    m = re.match(r"\[(\d+)\]", name)
    return (int(m.group(1)), name) if m else (999999, name)


def iter_request_files(folder: str) -> Iterator[str]:
    """كل ملفات *Request* تحت المجلد."""
    if not folder or not os.path.isdir(folder):
        return
    for name in sorted(os.listdir(folder), key=_natural_sort_key):
        if "Request" in name and name.endswith(".txt"):
            yield os.path.join(folder, name)


def filter_passport_login(paths: list[str]) -> list[str]:
    """طلبات passport/login ذات الصلة بالتدفق."""
    keys = (
        "passport_user_login_",
        "passport_user_check_login",
        "passport_user_login_pre_check",
        "passport_app_region",
        "passport_auth_get_nonce",
        "passport_aaas_authenticate",
        "captcha_verify",
        "captcha_get",
        "sdi_get_token",
    )
    out = []
    for p in paths:
        low = os.path.basename(p).lower()
        if any(k in low for k in keys):
            out.append(p)
    return out


def query_params_from_url(url: str) -> dict[str, str]:
    q = urllib.parse.urlparse(url).query
    return {k: v[0] if len(v) == 1 else v for k, v in urllib.parse.parse_qs(q).items()}


def suggest_profile_patch(method: str, url: str, headers: dict[str, str], body: str) -> dict[str, Any]:
    """
    يُرجع أجزاء يمكن دمجها في device JSON (يدويّاً) من طلب واحد.
    """
    qp = query_params_from_url(url)
    ua = headers.get("User-Agent") or headers.get("user-agent") or ""
    cookie = headers.get("Cookie") or headers.get("cookie") or ""
    patch: dict[str, Any] = {
        "_mitm_source": "parse_raw_request",
        "user_agent": ua,
    }
    if cookie:
        patch["session"] = {"cookie": cookie}
    if headers.get("x-tt-dm-status"):
        patch["passport_headers"] = {"x-tt-dm-status": headers["x-tt-dm-status"]}

    dev_keys = (
        "device_id", "iid", "openudid", "cdid",
    )
    meta_keys = (
        "version_code", "version_name", "manifest_version_code", "update_version_code",
    )
    app_keys = ("channel", "app_name", "aid")
    loc_keys = (
        "sys_region", "op_region", "timezone_name", "timezone_offset",
        "language", "locale", "app_language",
    )
    net_keys = ("ac", "ac2", "mcc_mnc", "carrier_region", "carrier_region_v2")

    d: dict[str, Any] = {}
    for k in dev_keys:
        if qp.get(k):
            d[k] = qp[k]
    if qp.get("device_type"):
        d["device_type"] = qp["device_type"]
    if qp.get("device_brand"):
        d["device_brand"] = qp["device_brand"]
    if qp.get("os_version"):
        d["os_version"] = qp["os_version"]
    if qp.get("os_api"):
        d["os_api"] = qp["os_api"]
    if qp.get("resolution"):
        d["resolution"] = qp["resolution"]
    if qp.get("dpi"):
        d["dpi"] = qp["dpi"]
    if qp.get("host_abi"):
        d["host_abi"] = qp["host_abi"]
    if qp.get("is_pad") is not None and str(qp.get("is_pad", "")).strip() != "":
        d["is_pad"] = str(qp["is_pad"])
    if d:
        patch["device"] = d

    m: dict[str, Any] = {}
    for k in meta_keys:
        if qp.get(k):
            m[k] = qp[k]
    if qp.get("build_number"):
        m["build_number"] = qp["build_number"]
    if m:
        patch["meta"] = m

    a: dict[str, Any] = {}
    for k in app_keys:
        if qp.get(k):
            a[k] = qp[k]
    if a:
        patch["app"] = a

    loc: dict[str, Any] = {}
    for k in loc_keys:
        if qp.get(k):
            loc[k] = qp[k]
    if qp.get("current_region"):
        loc["region"] = qp["current_region"]
        loc["current_region"] = qp["current_region"]
    if qp.get("residence"):
        loc["residence"] = qp["residence"]
    if loc:
        patch["locale"] = loc

    n: dict[str, Any] = {}
    for k in net_keys:
        if qp.get(k):
            n[k] = qp[k]
    if n:
        patch["network"] = n

    if qp.get("last_install_time"):
        sess = patch.setdefault("session", {})
        sess["last_install_time"] = qp["last_install_time"]

    patch["_captured_signing_headers"] = {
        k: headers[k]
        for k in ("X-Argus", "X-Gorgon", "X-Khronos", "X-Ladon", "X-SS-STUB")
        if headers.get(k)
    }
    patch["_request_method"] = method
    patch["_request_body_preview"] = (body[:200] + "…") if len(body) > 200 else body
    return patch


def _deep_merge_dict(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Recursive merge: patch wins; nested dicts merged."""
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if v is None:
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge_dict(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def find_check_login_name_registered_request(folder: str) -> str | None:
    """أول ملف Request يحتوي check_login_name_registered (بصمة جهاز كاملة في الـ query)."""
    if not os.path.isdir(folder):
        return None
    for p in iter_request_files(folder):
        if "check_login_name_registered" in os.path.basename(p).lower():
            return p
    return None


def _build_fingerprint_from_user_agent(ua: str) -> str:
    m = re.search(r"Build/([^;)]+)", ua or "")
    return m.group(1).strip() if m else ""


def export_device_profile_from_mitm(
    folder: str,
    template_path: str,
    out_path: str,
    raw_request_path: str | None = None,
) -> dict[str, Any]:
    """
    يدمج بصمة الجهاز من اعتراض MITM (طلب check_login_name_registered) داخل قالب JSON جاهز.

    - يحدّث: device (النموذج، العلامة، os، dpi، …)، app.channel، locale، network، user_agent،
      session.cookie، passport_headers، last_install_time من الـ query.
    - يحافظ على: device_id / iid / openudid / cdid / guard_keys من القالب إن لم تكن في الـ URL.

    ``folder``: مسار ``Raw_MM-DD-YYYY-....folder`` (مثل api-proxy/Raw_03-23-2026-14-39-43.folder).
    """
    req_path = raw_request_path or find_check_login_name_registered_request(folder)
    if not req_path or not os.path.isfile(req_path):
        raise FileNotFoundError(
            f"No check_login_name_registered Request file under {folder!r} "
            "(pass raw_request_path= to a specific .txt file)."
        )
    with open(template_path, encoding="utf-8") as f:
        base = json.load(f)
    method, url, headers, body = parse_raw_request(req_path)
    patch = suggest_profile_patch(method, url, headers, body)
    qp = query_params_from_url(url)

    # Optional ids from capture if present (usually same as template)
    dev_patch = patch.get("device") or {}
    for k in ("openudid", "cdid", "clientudid"):
        if qp.get(k):
            dev_patch[k] = str(qp[k])
    if dev_patch:
        patch["device"] = dev_patch

    ua = patch.get("user_agent") or ""
    bf = _build_fingerprint_from_user_agent(ua)
    if bf:
        patch.setdefault("device", {})["build_fingerprint"] = bf

    # Drop merge of internal / diagnostic keys into top-level profile
    meta_mitm = {
        "mitm_export_request": os.path.basename(req_path),
        "mitm_export_folder": os.path.abspath(folder),
    }
    signing_snap = patch.pop("_captured_signing_headers", None)
    patch.pop("_mitm_source", None)
    patch.pop("_request_method", None)
    patch.pop("_request_body_preview", None)

    merged = _deep_merge_dict(base, patch)
    merged.setdefault("meta", {}).update(meta_mitm)
    if signing_snap:
        merged["_mitm_signing_snapshot"] = signing_snap

    # Align manufacturer with brand when query does not send it (avoid stale template e.g. samsung + google).
    b = (merged.get("device") or {}).get("device_brand")
    if b:
        merged.setdefault("device", {})["device_manufacturer"] = b

    merged["_comment"] = (
        (merged.get("_comment") or "") + " — device fingerprint merged from MITM "
        f"{meta_mitm['mitm_export_request']}."
    ).strip(" —")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as wf:
        json.dump(merged, wf, ensure_ascii=False, indent=2)
        wf.write("\n")
    return merged


def scan_folder_summary(folder: str) -> dict[str, Any]:
    """ملخص سريع لمجلد اعتراض."""
    if not os.path.isdir(folder):
        return {"error": "not_a_directory", "path": folder}
    all_req = list(iter_request_files(folder))
    login_req = filter_passport_login(all_req)
    return {
        "folder": folder,
        "request_count": len(all_req),
        "passport_login_related": [os.path.basename(p) for p in login_req],
    }


# ترتيب مرجعي مقابل ``TikTokLoginClient.login()`` (من login_flow_captured_values.json)
_EXPECTED_LOGIN_CLIENT_ORDER = [
    "get_nonce",
    "sdi_get_token",
    "app_region",
    "check_login_name",
    "pre_check",
    "login",
    "captcha_get",
    "captcha_verify",
    "login_retry",
    "aaas_action_3",
    "aaas_action_4",
    "login_retry",
    "auth_broadcast",
    "device_register",
    "basic_info",
]


def raw_request_basename_to_step(name: str) -> str | None:
    """
    يحوّل اسم ملف طلب MITM إلى وسماً يقابل خطوة في ``login_client``.
    يُستخدم لمقارنة ترتيب المجلد مع التدفق المتوقع.
    """
    n = name.lower()
    if "passport_auth_get_nonce" in n or "_get_nonce" in n:
        return "get_nonce"
    if "sdi_get_token" in n or "_sdi_get_token" in n:
        return "sdi_get_token"
    if "passport_app_region" in n:
        return "app_region"
    if "check_login_name_registered" in n:
        return "check_login_name"
    if "login_pre_check" in n or "pre_check" in n:
        return "pre_check"
    if "passport_user_login_" in n and "pre_check" not in n and "aaas" not in n:
        return "login"
    if "captcha_get" in n:
        return "captcha_get"
    if "captcha_verify" in n:
        return "captcha_verify"
    if "passport_aaas_authenticate" in n or "aaas_authenticate" in n:
        if "action_3" in n or "action%3d3" in n:
            return "aaas_action_3"
        if "action_4" in n or "action%3d4" in n:
            return "aaas_action_4"
        return "aaas"
    if "auth_broadcast" in n:
        return "auth_broadcast"
    if "device_register" in n or "service_2_device_register" in n:
        return "device_register"
    if "basic_info" in n and "passport" in n:
        return "basic_info"
    return None


def flow_sequence_vs_login_client(folder: str) -> dict[str, Any]:
    """
    يستخرج ترتيب الطلبات ذات الصلة من مجلد Raw ويقارنها بترتيب ``login()`` المرجعي.
    إذا لم يوجد Raw_03-23، مرّر مجلد Raw آخر (مثل Raw_03-17-...).
    """
    if not os.path.isdir(folder):
        return {"error": "not_a_directory", "path": folder}
    all_req = list(iter_request_files(folder))
    login_req = filter_passport_login(all_req)
    steps: list[dict[str, Any]] = []
    for p in login_req:
        base = os.path.basename(p)
        tag = raw_request_basename_to_step(base)
        steps.append({"file": base, "step": tag})
    tags_in_order = [s["step"] for s in steps if s["step"]]
    return {
        "folder": folder,
        "expected_login_client_order": _EXPECTED_LOGIN_CLIENT_ORDER,
        "observed_step_sequence": tags_in_order,
        "observed_steps_per_file": steps,
        "note": "Compare observed_step_sequence to expected_login_client_order; file order is MITM index order.",
    }


def main_cli() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Parse api-proxy / MITM Raw *.folder request files")
    p.add_argument("folder", help="Path to Raw_MM-DD-YYYY-....folder")
    p.add_argument("--list", action="store_true", help="List passport-related request files")
    p.add_argument("--dump", metavar="FILE", help="Parse one request file → JSON on stdout")
    p.add_argument("--suggest", metavar="FILE", help="Suggest device JSON patch from one request")
    p.add_argument(
        "--flow-diff",
        action="store_true",
        help="Compare MITM request order (passport/sdi/captcha/…) vs login_client.login() reference",
    )
    p.add_argument(
        "--export-device",
        metavar="OUT.json",
        help="Merge MITM fingerprint into device template → OUT.json (needs --template)",
    )
    p.add_argument(
        "--template",
        metavar="BASE.json",
        help="Base device profile (e.g. device_v44_3_1.json) for --export-device",
    )
    p.add_argument(
        "--from-file",
        metavar="REQUEST.txt",
        help="Specific Raw Request .txt instead of auto pick check_login_name_registered",
    )
    args = p.parse_args()

    if args.export_device:
        if not args.template:
            p.error("--export-device requires --template BASE.json")
        export_device_profile_from_mitm(
            folder=args.folder,
            template_path=resolve_data_path(args.template),
            out_path=args.export_device,
            raw_request_path=args.from_file,
        )
        print(json.dumps({"ok": True, "written": os.path.abspath(args.export_device)}, indent=2))
        return

    if args.flow_diff:
        r = flow_sequence_vs_login_client(args.folder)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    if args.list or not args.dump and not args.suggest:
        s = scan_folder_summary(args.folder)
        print(json.dumps(s, indent=2, ensure_ascii=False))
    if args.dump:
        m, url, h, b = parse_raw_request(args.dump)
        out = {
            "method": m,
            "url": url,
            "headers": h,
            "body": b,
            "query": query_params_from_url(url),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.suggest:
        m, url, h, b = parse_raw_request(args.suggest)
        patch = suggest_profile_patch(m, url, h, b)
        print(json.dumps(patch, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main_cli()
