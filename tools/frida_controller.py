#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frida_controller.py — تحكم في Frida من Python

يشغّل الـ hook ويستخرج النتائج تلقائياً.

الاستخدام:
    python3 frida_controller.py                        # تشغيل عادي
    python3 frida_controller.py --spawn                # تشغيل التطبيق من الصفر
    python3 frida_controller.py --sign-url "https://..." # توقيع URL مباشرة
    python3 frida_controller.py --dump                 # فقط تصدير النتائج
    python3 frida_controller.py --filter device_register
"""

import argparse
import json
import os
import sys
import time
import signal
from pathlib import Path

try:
    import frida
except ImportError:
    print("[!] frida غير مثبت. شغّل: pip install frida-tools")
    sys.exit(1)

PACKAGE = "com.zhiliaoapp.musically"
SCRIPT_PATH = Path(__file__).parent / "frida_hook_tiktok.js"
OUTPUT_FILE = Path(__file__).parent / "captured_signs.json"


def get_script_source(filter_url: str = "") -> str:
    src = SCRIPT_PATH.read_text(encoding="utf-8")
    if filter_url:
        src = src.replace(
            'filter_url:       "",',
            f'filter_url:       "{filter_url}",'
        )
    return src


def on_message(message, data):
    if message["type"] == "send":
        print(f"[Frida] {message['payload']}")
    elif message["type"] == "error":
        print(f"[Frida ERROR] {message['stack']}")


def attach_or_spawn(spawn: bool = False, filter_url: str = ""):
    device = frida.get_usb_device(timeout=10)
    print(f"[+] الجهاز: {device.name}")

    if spawn:
        print(f"[*] تشغيل {PACKAGE} من الصفر...")
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        print(f"[+] PID: {pid}")
    else:
        print(f"[*] الاتصال بـ {PACKAGE}...")
        try:
            session = device.attach(PACKAGE)
        except frida.ProcessNotFoundError:
            print(f"[!] التطبيق لا يعمل. شغّله يدوياً أو استخدم --spawn")
            sys.exit(1)

    src = get_script_source(filter_url)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    print("[+] Script مُحمَّل")

    if spawn:
        device.resume(pid)
        print("[+] التطبيق استُؤنف")

    return session, script


def interactive_loop(script, output_file: Path):
    """انتظر المدخلات وتحكم في الـ hook"""
    print("\n[i] أوامر متاحة:")
    print("    s — عرض النتائج المُجمَّعة")
    print("    c — مسح النتائج")
    print("    d — تصدير JSON")
    print("    q — خروج\n")

    collected = []
    try:
        while True:
            time.sleep(0.1)
            try:
                cmd = input("» ").strip().lower()
            except EOFError:
                time.sleep(1)
                continue

            if cmd == "s":
                signs = script.exports_sync.get_signs()
                print(f"\n[+] {len(signs)} توقيع مُجمَّع:")
                for i, s in enumerate(signs[-5:], 1):
                    print(f"\n  [{i}] {s.get('time', '')}")
                    print(f"      URL: {s.get('url', '')[:80]}")
                    for k in ["X-Gorgon", "X-Khronos", "X-Argus", "X-Ladon"]:
                        v = s.get("headers", {}).get(k) or s.get(k)
                        if v:
                            print(f"      {k}: {v[:60]}")
                collected = signs

            elif cmd == "c":
                script.exports_sync.clear()
                print("[+] مُسح")

            elif cmd == "d":
                signs = script.exports_sync.get_signs()
                output_file.write_text(json.dumps(signs, indent=2, ensure_ascii=False))
                print(f"[+] حُفظ في: {output_file}")

            elif cmd == "q":
                break

    except KeyboardInterrupt:
        pass

    return collected


def sign_url_direct(script, url: str):
    """توقيع URL مباشرة عبر RPC"""
    print(f"[*] توقيع: {url[:80]}")
    result = script.exports_sync.sign_url(url)
    if result:
        print("\n[+] النتيجة:")
        for k, v in result.items():
            print(f"  {k:14s}: {v}")
        return result
    else:
        print("[!] فشل التوقيع — تأكد أن التطبيق يعمل وتم تهيئة metasec")
        return None


def main():
    p = argparse.ArgumentParser(description="TikTok Frida Controller")
    p.add_argument("--spawn",      action="store_true", help="تشغيل التطبيق من الصفر")
    p.add_argument("--filter",     default="",  help="فلتر URL (مثل device_register)")
    p.add_argument("--sign-url",   metavar="URL", help="توقيع URL مباشرة وطباعة النتيجة")
    p.add_argument("--dump",       action="store_true", help="تصدير النتائج فقط")
    p.add_argument("--out",        default=str(OUTPUT_FILE), help="مسار ملف الإخراج")
    args = p.parse_args()

    output_file = Path(args.out)

    print("=" * 60)
    print("  TikTok Frida Hook Controller")
    print("=" * 60)

    try:
        session, script = attach_or_spawn(
            spawn=args.spawn,
            filter_url=args.filter,
        )
    except Exception as e:
        print(f"[!] خطأ في الاتصال: {e}")
        print("    تأكد من:")
        print("    1. frida-server يعمل على الجهاز")
        print("    2. adb devices تُظهر الجهاز")
        print("    3. الجهاز مُتجذَّر (rooted)")
        sys.exit(1)

    if args.sign_url:
        # انتظر تهيئة التطبيق
        time.sleep(3)
        result = sign_url_direct(script, args.sign_url)
        if result and output_file:
            output_file.write_text(json.dumps([result], indent=2))
        return

    if args.dump:
        signs = script.exports_sync.get_signs()
        output_file.write_text(json.dumps(signs, indent=2, ensure_ascii=False))
        print(f"[+] {len(signs)} توقيع في: {output_file}")
        return

    # وضع التشغيل التفاعلي
    try:
        collected = interactive_loop(script, output_file)
        if collected:
            output_file.write_text(json.dumps(collected, indent=2, ensure_ascii=False))
            print(f"\n[+] حُفظ {len(collected)} توقيع في: {output_file}")
    finally:
        session.detach()
        print("[+] انتهى")


if __name__ == "__main__":
    main()
