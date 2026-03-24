#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jadx_analyzer.py — أداة تحليل كود JADX لفهم خوارزميات التوقيع

الاستخدام:
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --target gorgon
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --target all
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --class DeviceRegisterManager
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --find-native
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --find-bytes "1e 40 e0 d9"
    python3 jadx_analyzer.py --jadx /path/to/jadx_output/ --diff signing_engine.py
"""

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# الأنماط المستهدفة
# ══════════════════════════════════════════════════════════════════════════════

SIGN_KEYWORDS = {
    "gorgon":  ["gorgon", "Gorgon", "GORGON", "xgorgon", "X-Gorgon"],
    "argus":   ["argus", "Argus", "ARGUS", "xargus", "X-Argus", "metasec"],
    "ladon":   ["ladon", "Ladon", "LADON", "xladon", "X-Ladon"],
    "khronos": ["khronos", "Khronos", "KHRONOS", "X-Khronos", "khronos"],
    "stub":    ["SS-STUB", "ss_stub", "ssstub", "X-SS-STUB"],
    "simon":   ["simon", "Simon", "SIMON", "simon128", "Simon128"],
    "sm3":     ["SM3", "sm3", "SmHash", "GmSm3"],
    "rc4":     ["RC4", "rc4", "Rc4", "KSA", "PRGA"],
    "aes":     ["AES", "aes", "AesCipher", "CBC", "MODE_CBC"],
    "md5":     ["MD5", "md5", "MessageDigest.*MD5"],
    "protobuf":["proto", "Proto", "protobuf", "ProtoBuf", "pb"],
}

# ثوابت بحث في المصفوفات (من signing_engine.py)
KNOWN_CONSTANTS = {
    "argus_sign_key": [
        0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94,
        0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d, 0xd8,
    ],
    "gorgon_0404_hexstr": [30, 64, 224, 217, 147, 69, 0, 180],
    "ladon_license_id": [1611921764],
    "argus_xor_head": [0xf2, 0xf7, 0xfc, 0xff, 0xf2, 0xf7, 0xfc, 0xff],
    "argus_prefix": [0xa6, 0x6e, 0xad, 0x9f, 0x77, 0x01, 0xd0, 0x0c, 0x18],
}

# أنماط استدعاء دوال native
NATIVE_PATTERNS = [
    r"native\s+\w+\s+\w+\(",
    r"System\.loadLibrary\(",
    r"\.so[\"']",
    r"libmetasec",
    r"libsscronet",
    r"JNI_OnLoad",
]

# أنماط المعالجة الثنائية
CRYPTO_PATTERNS = {
    "byte_array":      r"\{[\s\d,\-]+\}",           # مصفوفات bytes
    "hex_string":      r'"[0-9a-fA-F]{16,}"',         # سلاسل hex
    "base64":          r'Base64\.(encode|decode)',
    "md5":             r'MessageDigest\.getInstance\("MD5"\)',
    "aes":             r'Cipher\.getInstance\("AES[^"]*"\)',
    "xor_op":          r'\^=?\s*0x[0-9a-fA-F]+',
    "bit_rotate":      r'(>>>|<<<|\bror\b|\brol\b)',
    "const_magic":     r'0x[0-9a-fA-F]{4,8}',
}


# ══════════════════════════════════════════════════════════════════════════════
# أدوات قراءة الملفات
# ══════════════════════════════════════════════════════════════════════════════

def find_java_files(jadx_dir: str) -> list[Path]:
    """يجد كل ملفات .java و .smali في مجلد JADX."""
    root = Path(jadx_dir)
    files = []
    for ext in ("*.java", "*.smali", "*.kt"):
        files.extend(root.rglob(ext))
    return sorted(files)


def read_file_safe(path: Path) -> str:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# المحلل الرئيسي
# ══════════════════════════════════════════════════════════════════════════════

class JadxAnalyzer:
    def __init__(self, jadx_dir: str, verbose: bool = False):
        self.jadx_dir = jadx_dir
        self.verbose   = verbose
        self.files     = find_java_files(jadx_dir)
        self._cache: dict[Path, str] = {}
        print(f"[+] وجدت {len(self.files)} ملف Java/Smali في {jadx_dir}")

    def _content(self, path: Path) -> str:
        if path not in self._cache:
            self._cache[path] = read_file_safe(path)
        return self._cache[path]

    # ── بحث بالكلمات المفتاحية ──────────────────────────────────────────────

    def search_keyword(self, keyword: str, context_lines: int = 4) -> list[dict]:
        """يبحث عن كلمة مفتاحية في كل الملفات ويعيد النتائج مع السياق."""
        results = []
        for path in self.files:
            content = self._content(path)
            if keyword.lower() not in content.lower():
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if keyword.lower() in line.lower():
                    start = max(0, i - context_lines)
                    end   = min(len(lines), i + context_lines + 1)
                    results.append({
                        "file":    str(path.relative_to(self.jadx_dir)),
                        "line":    i + 1,
                        "match":   line.strip(),
                        "context": "\n".join(
                            f"  {'>>>' if j == i else '   '} {j+1:4d}: {lines[j]}"
                            for j in range(start, end)
                        ),
                    })
        return results

    def search_target(self, target: str) -> dict:
        """يبحث عن كل الكلمات المفتاحية لهدف معين (gorgon/argus/ladon...)."""
        keywords = SIGN_KEYWORDS.get(target, [target])
        all_results = {}
        for kw in keywords:
            hits = self.search_keyword(kw)
            if hits:
                all_results[kw] = hits
        return all_results

    # ── تحليل الفئة (Class) ──────────────────────────────────────────────────

    def analyze_class(self, class_name: str) -> dict:
        """يستخرج كل المعلومات من class معين: دوال، ثوابت، native calls."""
        report = {
            "class_name": class_name,
            "files":      [],
            "methods":    [],
            "constants":  [],
            "native_calls": [],
            "crypto_ops": [],
            "callees":    [],
        }

        for path in self.files:
            content = self._content(path)
            if class_name not in content:
                continue

            report["files"].append(str(path.relative_to(self.jadx_dir)))

            # استخراج الدوال
            for m in re.finditer(
                r'(public|private|protected|static|native)[\w\s<>\[\]]+\s+(\w+)\s*\([^)]*\)',
                content,
            ):
                report["methods"].append(m.group(0).strip()[:120])

            # استخراج مصفوفات الـ bytes
            for m in re.finditer(r'(?:byte|int)\[\]\s*\w*\s*=\s*\{([^}]+)\}', content):
                vals = m.group(1).strip()
                if len(vals) > 5:
                    report["constants"].append(f"byte[] = {{{vals[:80]}...}}")

            # استخراج native
            for m in re.finditer(r'native\s+[\w\s<>\[\]]+\s+(\w+)\s*\(', content):
                report["native_calls"].append(m.group(0).strip())

            # عمليات crypto
            for name, pat in CRYPTO_PATTERNS.items():
                for m in re.finditer(pat, content):
                    report["crypto_ops"].append(f"[{name}] {m.group(0)[:80]}")

            # استدعاءات الدوال الأخرى
            for m in re.finditer(r'(\w+)\.(sign|encrypt|decrypt|hash|compute|generate)\(', content):
                report["callees"].append(f"{m.group(1)}.{m.group(2)}()")

        # إزالة التكرار
        for key in ("methods", "constants", "native_calls", "crypto_ops", "callees"):
            report[key] = list(dict.fromkeys(report[key]))

        return report

    # ── البحث عن native methods ──────────────────────────────────────────────

    def find_native_methods(self) -> list[dict]:
        """يجد كل الدوال native ومكتبات الـ .so المُحمَّلة."""
        results = []
        for path in self.files:
            content = self._content(path)
            for pat in NATIVE_PATTERNS:
                for m in re.finditer(pat, content):
                    lines = content.splitlines()
                    # إيجاد رقم السطر
                    pos = m.start()
                    ln  = content[:pos].count("\n") + 1
                    results.append({
                        "file":  str(path.relative_to(self.jadx_dir)),
                        "line":  ln,
                        "match": m.group(0).strip(),
                    })
        # تجميع حسب الملف
        by_file: dict[str, list] = defaultdict(list)
        for r in results:
            by_file[r["file"]].append(f"L{r['line']}: {r['match']}")
        return [{"file": f, "hits": hits} for f, hits in by_file.items()]

    # ── البحث بتسلسل bytes ──────────────────────────────────────────────────

    def find_byte_sequence(self, hex_seq: str) -> list[dict]:
        """
        يبحث عن تسلسل bytes ثابت في كود Java (مثل مفاتيح التشفير).
        hex_seq: "1e 40 e0 d9" أو "ac1adaae95a7af94"
        """
        # تحويل لقائمة أرقام
        hex_seq = hex_seq.replace(" ", "").replace(",", "")
        if len(hex_seq) % 2 != 0:
            print(f"[!] تسلسل hex غير صحيح: {hex_seq}")
            return []

        target = [int(hex_seq[i:i+2], 16) for i in range(0, len(hex_seq), 2)]

        # بناء أنماط بحث مختلفة (Java قد تكتب بطرق متعددة)
        patterns = []
        # مثال: (byte)0xac, (byte)0x1a, ...
        patterns.append(",\\s*".join(
            f"\\(?(?:byte\\s*\\)\\s*)?(?:0[xX]{b:02x}|{b}|{b - 256})"
            for b in target[:4]  # نبحث بأول 4 bytes
        ))
        # مثال: -84, 26, -38, ...
        signed = [b if b < 128 else b - 256 for b in target[:4]]
        patterns.append(",\\s*".join(str(b) for b in signed))

        results = []
        for path in self.files:
            content = self._content(path)
            for pat in patterns:
                try:
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        ln = content[:m.start()].count("\n") + 1
                        results.append({
                            "file":  str(path.relative_to(self.jadx_dir)),
                            "line":  ln,
                            "match": content.splitlines()[ln - 1].strip()[:120],
                        })
                except re.error:
                    continue

        return results

    # ── بناء شجرة الاستدعاء ──────────────────────────────────────────────────

    def build_call_tree(self, entry_class: str, depth: int = 3) -> dict:
        """يبني شجرة استدعاء ابتداءً من class معين."""
        visited = set()
        tree    = {}

        def _recurse(cls: str, d: int):
            if d == 0 or cls in visited:
                return {}
            visited.add(cls)
            node = {}
            for path in self.files:
                content = self._content(path)
                if cls not in content:
                    continue
                # إيجاد كل الكلاسات المستدعاة
                for m in re.finditer(r'\b([A-Z][A-Za-z0-9_$]+)\.' , content):
                    callee = m.group(1)
                    if callee not in visited and callee[0].isupper():
                        node[callee] = _recurse(callee, d - 1)
            return node

        tree[entry_class] = _recurse(entry_class, depth)
        return tree

    # ── مقارنة مع signing_engine.py ─────────────────────────────────────────

    def diff_with_engine(self, engine_path: str) -> dict:
        """
        يقارن الثوابت المُستخرجة من JADX مع ما في signing_engine.py
        للتحقق من صحة القيم.
        """
        report = {
            "engine_file": engine_path,
            "found_in_jadx": {},
            "missing_from_jadx": [],
        }

        engine_content = Path(engine_path).read_text(encoding="utf-8")

        # استخراج الثوابت من signing_engine.py
        engine_consts = {}
        for m in re.finditer(
            r'([A-Z_]{4,})\s*=\s*\(?[\n\s]*b"([^"]+)"', engine_content
        ):
            name = m.group(1)
            raw  = m.group(2)
            engine_consts[name] = raw

        # البحث عن كل ثابت في كود JADX
        for const_name, const_vals in KNOWN_CONSTANTS.items():
            hex_seq = "".join(f"{v:02x}" for v in const_vals[:8])
            hits    = self.find_byte_sequence(hex_seq)
            if hits:
                report["found_in_jadx"][const_name] = hits
            else:
                report["missing_from_jadx"].append({
                    "name":    const_name,
                    "hex":     hex_seq,
                    "values":  const_vals[:8],
                })

        return report

    # ── تحليل شامل لـ target ─────────────────────────────────────────────────

    def full_analysis(self, target: str) -> dict:
        """تحليل كامل لخوارزمية معينة."""
        print(f"\n{'='*60}")
        print(f"  تحليل: {target.upper()}")
        print(f"{'='*60}")

        result = {
            "target":       target,
            "keyword_hits": {},
            "classes":      [],
            "native_refs":  [],
            "byte_consts":  {},
        }

        # 1. بحث بالكلمات المفتاحية
        kw_results = self.search_target(target)
        result["keyword_hits"] = {k: len(v) for k, v in kw_results.items()}

        # 2. استخراج أسماء الكلاسات المتصلة
        class_names = set()
        for kw, hits in kw_results.items():
            for hit in hits:
                # استخرج اسم الكلاس من مسار الملف
                fname = Path(hit["file"]).stem
                if fname and fname[0].isupper():
                    class_names.add(fname)
        result["classes"] = list(class_names)

        # 3. تحليل كل كلاس
        for cls in list(class_names)[:5]:  # أول 5 فقط
            cls_report = self.analyze_class(cls)
            if cls_report["methods"] or cls_report["native_calls"]:
                _print_class_report(cls_report)

        # 4. عرض النتائج بسياق
        for kw, hits in kw_results.items():
            print(f"\n── [{kw}] → {len(hits)} تطابق ──")
            for hit in hits[:3]:
                print(f"\n  📄 {hit['file']} : L{hit['line']}")
                print(hit["context"])
            if len(hits) > 3:
                print(f"  ... و {len(hits)-3} تطابق آخر")

        return result


# ══════════════════════════════════════════════════════════════════════════════
# أدوات العرض
# ══════════════════════════════════════════════════════════════════════════════

def _print_class_report(r: dict):
    print(f"\n  🔷 Class: {r['class_name']}")
    if r["files"]:
        print(f"     ملفات: {', '.join(r['files'][:2])}")
    if r["native_calls"]:
        print(f"     Native calls:")
        for n in r["native_calls"][:5]:
            print(f"       • {n}")
    if r["methods"]:
        print(f"     دوال رئيسية:")
        for m in r["methods"][:6]:
            print(f"       • {m}")
    if r["crypto_ops"]:
        print(f"     عمليات crypto:")
        for c in list(set(r["crypto_ops"]))[:5]:
            print(f"       • {c}")
    if r["callees"]:
        print(f"     يستدعي:")
        for c in r["callees"][:4]:
            print(f"       → {c}")


def _print_diff_report(r: dict):
    print(f"\n{'='*60}")
    print("  مقارنة ثوابت JADX vs signing_engine.py")
    print(f"{'='*60}")
    print(f"\n✅ ثوابت موجودة في JADX ({len(r['found_in_jadx'])}):")
    for name, hits in r["found_in_jadx"].items():
        print(f"  • {name}")
        for h in hits[:2]:
            print(f"    └─ {h['file']} : L{h['line']}")
            print(f"       {h['match']}")

    print(f"\n❌ ثوابت غير موجودة في JADX ({len(r['missing_from_jadx'])}):")
    for item in r["missing_from_jadx"]:
        vals_str = " ".join(f"{v:02x}" for v in item["values"])
        print(f"  • {item['name']}: [{vals_str}...]")
        print(f"    → ربما في مكتبة native (.so) أو مُشفَّرة بطريقة أخرى")


def _print_native_report(hits: list[dict]):
    print(f"\n{'='*60}")
    print(f"  Native Methods & .so Libraries ({len(hits)} ملف)")
    print(f"{'='*60}")
    for h in hits:
        print(f"\n  📄 {h['file']}")
        for line in h["hits"][:6]:
            print(f"    • {line}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="تحليل كود JADX لفهم خوارزميات توقيع TikTok",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  python3 jadx_analyzer.py --jadx ./sources/ --target gorgon
  python3 jadx_analyzer.py --jadx ./sources/ --target all
  python3 jadx_analyzer.py --jadx ./sources/ --class DeviceRegisterManager
  python3 jadx_analyzer.py --jadx ./sources/ --find-native
  python3 jadx_analyzer.py --jadx ./sources/ --find-bytes "ac 1a da ae 95 a7"
    python3 jadx_analyzer.py --jadx ./sources/ --diff ../ttk/signing_engine.py
  python3 jadx_analyzer.py --jadx ./sources/ --keyword "X-Gorgon" --context 6
  python3 jadx_analyzer.py --jadx ./sources/ --call-tree AppLogNetworkContext
        """,
    )
    p.add_argument("--jadx",       required=True, help="مسار مجلد كود JADX المُفكَّك")
    p.add_argument("--target",     help="gorgon | argus | ladon | simon | sm3 | rc4 | aes | md5 | all")
    p.add_argument("--class",      dest="cls",    help="تحليل class معين بالاسم")
    p.add_argument("--find-native",action="store_true", help="إيجاد كل native methods و .so")
    p.add_argument("--find-bytes", metavar="HEX", help="البحث عن تسلسل bytes (مثل: 'ac 1a da ae')")
    p.add_argument("--diff",       metavar="ENGINE_PY", help="مقارنة الثوابت مع signing_engine.py")
    p.add_argument("--keyword",    help="بحث حر بكلمة مفتاحية")
    p.add_argument("--context",    type=int, default=4, help="عدد أسطر السياق (افتراضي: 4)")
    p.add_argument("--call-tree",  metavar="CLASS", help="بناء شجرة استدعاء")
    p.add_argument("--out",        help="حفظ النتيجة JSON في ملف")
    p.add_argument("--verbose",    action="store_true")
    args = p.parse_args()

    if not os.path.isdir(args.jadx):
        print(f"[!] المسار غير موجود: {args.jadx}")
        sys.exit(1)

    analyzer = JadxAnalyzer(args.jadx, verbose=args.verbose)
    output   = {}

    # ── الأوضاع المختلفة ──────────────────────────────────────────────────────

    if args.target:
        targets = (
            list(SIGN_KEYWORDS.keys())
            if args.target == "all"
            else [args.target]
        )
        for t in targets:
            output[t] = analyzer.full_analysis(t)

    if args.cls:
        report = analyzer.analyze_class(args.cls)
        _print_class_report(report)
        output["class"] = report

    if args.find_native:
        hits = analyzer.find_native_methods()
        _print_native_report(hits)
        output["native"] = hits

    if args.find_bytes:
        hits = analyzer.find_byte_sequence(args.find_bytes)
        print(f"\n{'='*60}")
        print(f"  نتائج البحث عن: {args.find_bytes}")
        print(f"{'='*60}")
        if hits:
            for h in hits:
                print(f"\n  📄 {h['file']} : L{h['line']}")
                print(f"     {h['match']}")
        else:
            print("  ❌ لم يُعثر على التسلسل — ربما في native library")
        output["byte_search"] = hits

    if args.diff:
        report = analyzer.diff_with_engine(args.diff)
        _print_diff_report(report)
        output["diff"] = report

    if args.keyword:
        hits = analyzer.search_keyword(args.keyword, context_lines=args.context)
        print(f"\n{'='*60}")
        print(f"  بحث عن: '{args.keyword}' → {len(hits)} نتيجة")
        print(f"{'='*60}")
        for h in hits:
            print(f"\n  📄 {h['file']} : L{h['line']}")
            print(h["context"])
        output["keyword"] = hits

    if args.call_tree:
        tree = analyzer.build_call_tree(args.call_tree, depth=3)
        print(f"\n{'='*60}")
        print(f"  شجرة الاستدعاء: {args.call_tree}")
        print(f"{'='*60}")
        _print_tree(tree, indent=0)
        output["call_tree"] = tree

    if not any([args.target, args.cls, args.find_native,
                args.find_bytes, args.diff, args.keyword, args.call_tree]):
        print("\n[i] لم تحدد عملية. استخدم --help لمعرفة الخيارات.")
        print("\nالكلمات المفتاحية المدعومة:")
        for k, v in SIGN_KEYWORDS.items():
            print(f"  {k:10s}: {', '.join(v[:3])}")
        sys.exit(0)

    # ── حفظ النتيجة ──────────────────────────────────────────────────────────
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n[+] النتائج حُفظت في: {args.out}")


def _print_tree(node: dict, indent: int):
    for key, children in node.items():
        print("  " * indent + f"└─ {key}")
        if isinstance(children, dict):
            _print_tree(children, indent + 1)


if __name__ == "__main__":
    main()
