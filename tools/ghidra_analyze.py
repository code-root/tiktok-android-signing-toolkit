#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghidra_analyze.py — تحليل libmetasec_ov.so بـ Ghidra API
========================================================

يُنفّذ تحليلاً كاملاً تلقائياً:
  1. استيراد الملف وتحليله
  2. إيجاد JNI_OnLoad والدوال المستدعاة منها
  3. البحث عن opcode dispatch (frameSign / X-Gorgon)
  4. تحديد دوال التشفير (AES / SIMON / RC4-like / SM3)
  5. استخراج الثوابت والـ xrefs
  6. توليد تقرير JSON + تسمية الدوال تلقائياً

الاستخدام:
    python3 ghidra_analyze.py
    python3 ghidra_analyze.py --target ../../../tiktok_jadx_ARM64_v8a/resources/lib/arm64-v8a/libmetasec_ov.so
    python3 ghidra_analyze.py --out report.json
    python3 ghidra_analyze.py --label    (يُعيد تسمية الدوال فقط)
    python3 ghidra_analyze.py --decompile-jni   (يُولّد كود C لـ JNI_OnLoad)
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

GHIDRA_HOME = Path("/Users/mo/Downloads/ghidra_12.0.4_PUBLIC")
SO_PATH = Path("/Users/mo/Documents/tik-api copy/tiktok_jadx_ARM64_v8a/resources/lib/arm64-v8a/libmetasec_ov.so")
PROJECT_DIR = Path("/tmp/ghidra_metasec")
PROJECT_NAME = "metasec_analysis"

# ── تهيئة PyGhidra ────────────────────────────────────────────────────
import pyghidra
pyghidra.start(install_dir=GHIDRA_HOME)

# استيراد Ghidra APIs
import ghidra
from ghidra.app.script           import GhidraScript
from ghidra.program.model.listing import Function, CodeUnit
from ghidra.program.model.symbol  import SymbolType, RefType
from ghidra.program.model.address import Address
from ghidra.app.decompiler        import DecompInterface, DecompileOptions
from ghidra.util.task             import ConsoleTaskMonitor


# ══════════════════════════════════════════════════════════════════════
# تحميل البرنامج
# ══════════════════════════════════════════════════════════════════════

def open_program(so_path: Path):
    """يفتح / يستورد الـ .so ويُنفّذ التحليل الكامل."""
    from ghidra.base.project.storage import LocalStorageLocator
    from ghidra.program.flatapi       import FlatProgramAPI
    from ghidra.app.util.importer      import MessageLog
    from ghidra.formats.gzip           import GZipLoader
    import ghidra.app.util.bin.format.elf as elf_pkg

    PROJECT_DIR.mkdir(parents=True, exist_ok=True)

    with pyghidra.open_program(
        so_path,
        project_location=str(PROJECT_DIR),
        project_name=PROJECT_NAME,
        analyze=True,          # تحليل تلقائي كامل
    ) as flat_api:
        return flat_api, flat_api.getCurrentProgram()


# ══════════════════════════════════════════════════════════════════════
# أدوات المساعدة
# ══════════════════════════════════════════════════════════════════════

def addr(prog, offset: int):
    """تحويل offset إلى Address object."""
    return prog.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def func_at(prog, offset: int):
    """الدالة عند offset."""
    a = addr(prog, offset)
    return prog.getFunctionManager().getFunctionAt(a)


def all_functions(prog):
    """قائمة بكل الدوال."""
    fm = prog.getFunctionManager()
    return list(fm.getFunctions(True))


def decompile(func, prog) -> str:
    """يعيد كود C المُولَّد من Ghidra Decompiler."""
    ifc = DecompInterface()
    opts = DecompileOptions()
    ifc.setOptions(opts)
    ifc.openProgram(prog)
    mon = ConsoleTaskMonitor()
    result = ifc.decompileFunction(func, 60, mon)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return ""


def get_called_functions(func, prog) -> list:
    """الدوال التي تستدعيها func."""
    called = []
    fm  = prog.getFunctionManager()
    rm  = prog.getReferenceManager()
    listing = prog.getListing()

    body = func.getBody()
    addrs = body.getAddresses(True)
    while addrs.hasNext():
        a = addrs.next()
        refs = rm.getReferencesFrom(a)
        for ref in refs:
            if ref.getReferenceType().isCall():
                target = fm.getFunctionAt(ref.getToAddress())
                if target:
                    called.append({
                        "name":   target.getName(),
                        "offset": ref.getToAddress().getOffset(),
                        "from":   a.getOffset(),
                    })
    return called


def get_xrefs_to(func, prog) -> list:
    """من يستدعي func."""
    fm = prog.getFunctionManager()
    rm = prog.getReferenceManager()
    refs = rm.getReferencesTo(func.getEntryPoint())
    callers = []
    for ref in refs:
        if ref.getReferenceType().isCall():
            caller = fm.getFunctionContaining(ref.getFromAddress())
            if caller:
                callers.append({
                    "name":   caller.getName(),
                    "offset": caller.getEntryPoint().getOffset(),
                })
    return callers


def find_strings(prog, min_len=6) -> list:
    """يستخرج كل الـ strings من الـ .rodata."""
    listing = prog.getListing()
    mem = prog.getMemory()
    result = []
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        d = data_iter.next()
        dt = d.getDataType()
        if "string" in dt.getName().lower() or "char" in dt.getName().lower():
            val = d.getValue()
            if val and len(str(val)) >= min_len:
                result.append({
                    "addr":   d.getAddress().getOffset(),
                    "string": str(val),
                    "len":    len(str(val)),
                })
    return result


# ══════════════════════════════════════════════════════════════════════
# التحليل الرئيسي
# ══════════════════════════════════════════════════════════════════════

KNOWN_OFFSETS = {
    0x4b680: "JNI_OnLoad",
}

# أنماط اسم للدوال المشبوهة
CRYPTO_PATTERNS = [
    ("aes",        "AES"),
    ("simon",      "SIMON128"),
    ("sm3",        "SM3Hash"),
    ("rc4",        "RC4"),
    ("md5",        "MD5"),
    ("gorgon",     "Gorgon"),
    ("argus",      "Argus"),
    ("ladon",      "Ladon"),
    ("hmac",       "HMAC"),
    ("sha",        "SHA"),
    ("base64",     "Base64"),
    ("proto",      "Protobuf"),
    ("dispatch",   "Dispatcher"),
    ("framesign",  "FrameSign"),
]


def classify_function(func, decompiled_c: str) -> list[str]:
    """يُصنّف الدالة بناءً على محتوى الـ decompile."""
    tags = []
    c_lower = decompiled_c.lower()

    # ثوابت SIMON cipher
    if "0x3dc94c3a" in decompiled_c or "046d678b" in c_lower:
        tags.append("SIMON-128-CONST")

    # XOR loops كثيفة = تشفير
    xor_count = decompiled_c.count("^ ")
    if xor_count > 20:
        tags.append(f"HEAVY-XOR({xor_count})")

    # rot / shift patterns = bit operations
    if (">> " in decompiled_c or "<< " in decompiled_c) and xor_count > 5:
        tags.append("BIT-ROTATION")

    # حلقات 256 = S-box / KSA
    if "256" in decompiled_c and ("for" in c_lower or "while" in c_lower):
        tags.append("SBOX-OR-KSA")

    # حلقات 72 = SIMON rounds
    if "0x48" in decompiled_c or "72" in decompiled_c:
        tags.append("SIMON-ROUNDS")

    # حلقات 64 = SM3 / SHA rounds
    if "64" in decompiled_c and "for" in c_lower:
        tags.append("HASH-ROUNDS")

    # AES patterns
    if "0x63" in decompiled_c and "sbox" in c_lower:
        tags.append("AES-SBOX")

    # Base64
    if "0x3d" in decompiled_c and "64" in decompiled_c:
        tags.append("BASE64")

    # Protobuf varint
    if "0x7f" in decompiled_c and "0x80" in decompiled_c:
        tags.append("PROTOBUF-VARINT")

    # JNI calls
    if "JNIEnv" in decompiled_c or "jni" in c_lower:
        tags.append("JNI")

    # switch/case كبير = dispatcher
    switch_count = decompiled_c.count("case ")
    if switch_count > 5:
        tags.append(f"SWITCH({switch_count}cases)")

    return tags


def rename_function(func, new_name: str, prog):
    """يُعيد تسمية الدالة في Ghidra."""
    from ghidra.program.model.symbol import SourceType
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        return True
    except Exception as e:
        return False


def analyze_jni_onload(prog, flat_api, report: dict):
    """تحليل JNI_OnLoad وشجرة الاستدعاء."""
    jni_func = func_at(prog, 0x4b680)
    if not jni_func:
        print("  ❌ JNI_OnLoad لم يُعثر عليها")
        report["jni_onload"] = {"error": "not found"}
        return

    print(f"  ✅ JNI_OnLoad @ {jni_func.getEntryPoint()}")
    print(f"     size: {jni_func.getBody().getNumAddressRanges()} ranges")

    called = get_called_functions(jni_func, prog)
    print(f"     تستدعي: {len(called)} دالة")

    report["jni_onload"] = {
        "offset":  0x4b680,
        "address": str(jni_func.getEntryPoint()),
        "called":  called[:30],
    }

    # طبع أهم الدوال
    for c in called[:10]:
        print(f"       → {c['name']} @ 0x{c['offset']:08x}")


def find_dispatcher(prog, report: dict):
    """يبحث عن دالة الـ dispatch (تعالج opcodes 0x2000001-0x200000A)."""
    print("\n  [~] البحث عن دالة الـ dispatch...")

    # نبحث عن دوال كبيرة فيها switch
    candidates = []
    for func in all_functions(prog):
        body_size = sum(r.getLength() for r in func.getBody())
        if 500 < body_size < 50000:
            candidates.append(func)

    print(f"  [~] {len(candidates)} دالة مرشحة للـ dispatch")

    # decompile أول 30 للبحث عن patterns
    dispatcher_candidates = []
    for func in candidates[:50]:
        try:
            c_code = decompile(func, prog)
            if not c_code:
                continue
            tags = classify_function(func, c_code)
            if "SWITCH" in " ".join(tags) and len(c_code) > 500:
                sw = [t for t in tags if t.startswith("SWITCH")]
                dispatcher_candidates.append({
                    "name":   func.getName(),
                    "offset": func.getEntryPoint().getOffset(),
                    "size":   len(c_code),
                    "tags":   tags,
                    "switch": sw,
                })
                print(f"  🔶 مرشح dispatch: {func.getName()} @ 0x{func.getEntryPoint().getOffset():08x}  {tags}")
        except Exception:
            continue

    report["dispatcher_candidates"] = dispatcher_candidates


def find_crypto_functions(prog, report: dict, do_label: bool = False):
    """يُحدد دوال التشفير ويُسمّيها."""
    print("\n  [~] تحليل دوال التشفير...")
    funcs = all_functions(prog)
    print(f"  [~] إجمالي الدوال: {len(funcs)}")

    crypto_funcs = []
    stats = {}

    # نُحلّل الدوال متوسطة الحجم (50-5000 bytes)
    candidates = [f for f in funcs if 50 < sum(r.getLength() for r in f.getBody()) < 5000]
    print(f"  [~] دوال مرشحة للتحليل: {len(candidates)}")

    analyzed = 0
    for func in candidates:
        try:
            c_code = decompile(func, prog)
            if not c_code:
                continue
            tags = classify_function(func, c_code)
            if not tags:
                continue

            analyzed += 1
            entry = {
                "name":   func.getName(),
                "offset": func.getEntryPoint().getOffset(),
                "tags":   tags,
                "size":   len(c_code),
            }
            crypto_funcs.append(entry)

            # تسمية تلقائية
            if do_label:
                tag_str = "_".join(tags[:2])
                new_name = f"SIGN_{tag_str}_{func.getEntryPoint().getOffset():06x}"
                rename_function(func, new_name, prog)
                entry["renamed_to"] = new_name

            for t in tags:
                stats[t] = stats.get(t, 0) + 1

        except Exception:
            continue

    print(f"\n  [+] دوال مُصنَّفة: {analyzed}")
    for tag, count in sorted(stats.items(), key=lambda x: -x[1])[:15]:
        print(f"       {tag:30s}: {count}")

    # أهم الدوال
    important = [f for f in crypto_funcs if
                 any(t in ["SIMON-128-CONST","SBOX-OR-KSA","HEAVY-XOR(","SIMON-ROUNDS"]
                     for t in f["tags"])]
    if important:
        print(f"\n  ✅ دوال تشفير مهمة:")
        for f in important[:10]:
            print(f"     {f['name']:30s} @ 0x{f['offset']:08x}  {f['tags']}")

    report["crypto_functions"] = crypto_funcs
    report["crypto_stats"]     = stats
    return crypto_funcs


def extract_strings_analysis(prog, report: dict):
    """استخراج كل الـ strings."""
    print("\n  [~] استخراج strings...")
    strings = find_strings(prog)
    print(f"  [+] {len(strings)} string")

    # فلتر المهم
    interesting = [s for s in strings if any(
        kw in s["string"].lower() for kw in
        ["sign", "gorgon", "argus", "ladon", "khronos", "token", "key",
         "aes", "simon", "md5", "crypto", "request", "header", "device",
         "http", "version", "error", "fail"]
    )]

    print(f"  [+] strings مثيرة للاهتمام: {len(interesting)}")
    for s in interesting[:20]:
        print(f"     0x{s['addr']:08x}: {s['string'][:80]}")

    report["strings_total"]       = len(strings)
    report["strings_interesting"] = interesting[:100]


def decompile_jni_onload(prog, flat_api):
    """طباعة كود C الكامل لـ JNI_OnLoad."""
    jni_func = func_at(prog, 0x4b680)
    if not jni_func:
        print("❌ JNI_OnLoad لم يُعثر عليها")
        return
    print(f"\n{'='*60}")
    print(f"  JNI_OnLoad — Decompiled C")
    print(f"{'='*60}")
    c = decompile(jni_func, prog)
    print(c or "(فشل الـ decompile)")


# ══════════════════════════════════════════════════════════════════════
# main
# ══════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="Ghidra API Analysis — libmetasec_ov.so")
    p.add_argument("--target",         default=str(SO_PATH),  help="مسار .so")
    p.add_argument("--out",            default="ghidra_report.json", help="ملف JSON")
    p.add_argument("--label",          action="store_true",   help="إعادة تسمية الدوال")
    p.add_argument("--decompile-jni",  action="store_true",   help="طباعة C لـ JNI_OnLoad")
    p.add_argument("--no-crypto",      action="store_true",   help="تخطي تحليل التشفير")
    args = p.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] الملف غير موجود: {target}")
        sys.exit(1)

    print("=" * 60)
    print("  Ghidra API — تحليل libmetasec_ov.so")
    print("=" * 60)
    print(f"[*] الملف: {target}")
    print(f"[*] Ghidra: {GHIDRA_HOME}")
    print(f"[*] المشروع: {PROJECT_DIR / PROJECT_NAME}\n")

    print("[1] تحميل البرنامج وتشغيل تحليل Ghidra...")

    # حذف المشروع القديم لتجنب LockException
    proj_path = PROJECT_DIR / PROJECT_NAME
    if proj_path.exists():
        shutil.rmtree(proj_path)
    PROJECT_DIR.mkdir(parents=True, exist_ok=True)

    with pyghidra.open_program(
        target,
        project_location=str(PROJECT_DIR),
        project_name=PROJECT_NAME,
        analyze=True,
    ) as flat_api:
        prog = flat_api.getCurrentProgram()

        print(f"[+] برنامج: {prog.getName()}")
        print(f"[+] Language: {prog.getLanguageID()}")
        print(f"[+] Compiler: {prog.getCompilerSpec().getCompilerSpecID()}")
        print(f"[+] Image base: 0x{prog.getImageBase().getOffset():08x}")
        funcs = all_functions(prog)
        print(f"[+] عدد الدوال: {len(funcs)}")

        report = {
            "file":     str(target),
            "name":     prog.getName(),
            "language": str(prog.getLanguageID()),
            "base":     prog.getImageBase().getOffset(),
            "functions_total": len(funcs),
        }

        print("\n[2] تحليل JNI_OnLoad...")
        analyze_jni_onload(prog, flat_api, report)

        print("\n[3] البحث عن dispatcher...")
        find_dispatcher(prog, report)

        if not args.no_crypto:
            print("\n[4] تحليل دوال التشفير...")
            find_crypto_functions(prog, report, do_label=args.label)

        print("\n[5] استخراج Strings...")
        extract_strings_analysis(prog, report)

        if args.decompile_jni:
            decompile_jni_onload(prog, flat_api)

        # حفظ التقرير
        out_path = Path(args.out)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str)
        )
        print(f"\n[+] التقرير حُفظ في: {out_path}")
        print(f"    الحجم: {out_path.stat().st_size / 1024:.1f} KB")

        # ملخص سريع
        print(f"\n{'='*60}")
        print("  ملخص النتائج")
        print(f"{'='*60}")
        print(f"  دوال إجمالية   : {len(funcs)}")
        print(f"  مرشحو dispatch : {len(report.get('dispatcher_candidates', []))}")
        print(f"  دوال تشفير    : {len(report.get('crypto_functions', []))}")
        print(f"  strings مثيرة : {len(report.get('strings_interesting', []))}")

        if report.get("dispatcher_candidates"):
            print("\n  أهم مرشحي dispatch:")
            for c in report["dispatcher_candidates"][:3]:
                print(f"    {c['name']} @ 0x{c['offset']:08x}  {c['tags']}")


if __name__ == "__main__":
    main()
