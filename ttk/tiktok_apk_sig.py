#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
استخراج sig_hash من APK لـ TikTok (نفس منطق JADX C938760aXG.LIZLLL):
MD5(أول كتلة PKCS#7 في META-INF/*.RSA|DSA|EC) → hex 32 حرفاً.

ملفات ``.apkm`` (APKMirror): يُقرأ ``base.apk`` من داخل الأرشيف — **لا** تُستخدم كتلة
``META-INF/APKMIRRO.RSA`` في جذر الحزمة (ذلك توقيع المثبت وليس التطبيق).

يُستخدم في رأس device_register (حقل sig_hash). استخدم نفس بناء الـ APK المطابق لـ User-Agent.
"""

from __future__ import annotations

import copy
import hashlib
import io
import os
import zipfile
from typing import Any


def first_signature_block_from_zip(z: zipfile.ZipFile) -> bytes | None:
    """أول ملف META-INF/*.RSA / *.DSA / *.EC (كتلة توقيع JAR v1) داخل ZipFile مفتوح."""
    names = [n for n in z.namelist() if n.startswith("META-INF/")]
    for ext in (".RSA", ".DSA", ".EC"):
        for n in sorted(names):
            if n.endswith(ext) and not n.endswith("MANIFEST.MF"):
                return z.read(n)
    return None


def first_meta_inf_signature_bytes(apk_path: str) -> bytes | None:
    """أول كتلة توقيع داخل ملف APK عادي."""
    with zipfile.ZipFile(apk_path, "r") as z:
        return first_signature_block_from_zip(z)


def sig_hash_from_apk(apk_path: str) -> str | None:
    """
    يُرجع sig_hash أو None.

    • ملف ``.apk`` عادي: MD5 أول كتلة PKCS#7 في META-INF.
    • ملف ``.apkm`` (حزمة APKMirror): يُستخرج ``base.apk`` من الداخل ثم يُحسب التوقيع —
      **لا** تستخدم الـ ``META-INF`` الخاصة بمثبت APKMirror في الجذر.
    """
    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        return None

    raw: bytes | None = None
    if apk_path.lower().endswith(".apkm"):
        with zipfile.ZipFile(apk_path, "r") as outer:
            if "base.apk" not in outer.namelist():
                return None
            inner_bytes = outer.read("base.apk")
        with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner:
            raw = first_signature_block_from_zip(inner)
    else:
        raw = first_meta_inf_signature_bytes(apk_path)

    if not raw:
        return None
    return hashlib.md5(raw).hexdigest()


def merge_sig_hash_into_base(base: dict, apk_path: str) -> tuple[dict, dict[str, Any]]:
    """
    ينسخ base ويضع device_register.sig_hash (و device.sig_hash إن وُجد المفتاح في الأعلى).

    Returns:
        (نسخة محدثة, معلومات: sig_hash, error, apk)
    """
    apk_path = os.path.abspath(apk_path)
    info: dict[str, Any] = {"apk": apk_path}
    if not os.path.isfile(apk_path):
        info["error"] = "file_not_found"
        return copy.deepcopy(base), info

    if apk_path.lower().endswith(".apkm"):
        info["sig_source"] = "apkm:base.apk (not outer META-INF/APKMIRRO)"

    sh = sig_hash_from_apk(apk_path)
    info["sig_hash"] = sh
    if not sh:
        info["error"] = (
            "no_v1_signature_block — استخدم APK كاملاً موقّعاً بـ v1 (مثل base.apk من الحزمة)، "
            "وليس split أو v2-only فقط"
        )
        return copy.deepcopy(base), info

    out = copy.deepcopy(base)
    out.setdefault("device_register", {})["sig_hash"] = sh
    info["merged"] = True
    return out, info
