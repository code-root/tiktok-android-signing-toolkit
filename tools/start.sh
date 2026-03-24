#!/usr/bin/env bash
# ══════════════════════════════════════════════════════
# start.sh — تشغيل gorgon_bruteforce على VPS Linux
# ══════════════════════════════════════════════════════
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# ── الإعدادات — عدّلها قبل التشغيل ──────────────────
THREADS=8
URL_MD5="00000000000000000000000000000000"
STUB=""
COOKIE_MD5=""
TS="0"
TARGET="840400000000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
FIXED="0,0,0,0,0,0,0,0"
LOG="output.log"

# ── تجميع إذا لم يكن موجوداً ──────────────────────────
if [ ! -f "./gorgon_bf" ]; then
    echo "[*] تجميع gorgon_bruteforce.c ..."
    if ! command -v gcc &>/dev/null; then
        echo "[!] GCC غير موجود. شغّل: sudo apt install gcc"
        exit 1
    fi
    gcc -O3 -march=native \
        -o gorgon_bf gorgon_bruteforce.c \
        -lpthread
    echo "[+] تم التجميع."
fi

# ── بناء الأمر ────────────────────────────────────────
CMD="./gorgon_bf --url-md5 $URL_MD5 --ts $TS --target $TARGET --fixed \"$FIXED\" --threads $THREADS"
if [ -n "$STUB" ]; then
    CMD="$CMD --stub $STUB"
fi
if [ -n "$COOKIE_MD5" ]; then
    CMD="$CMD --cookie-md5 $COOKIE_MD5"
fi

# ── تشغيل في الخلفية عبر nohup ──────────────────────
echo "[*] بدء التشغيل في الخلفية..."
echo "[*] النتائج في: $LOG"

nohup bash -c "$CMD" > "$LOG" 2>&1 &
PID=$!
echo $PID > gorgon_bf.pid

echo "[+] PID: $PID"
echo ""
echo "لمتابعة النتائج:"
echo "  tail -f $LOG"
echo ""
echo "لإيقافه:"
echo "  kill \$(cat gorgon_bf.pid)"
