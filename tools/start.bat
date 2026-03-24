@echo off
:: ══════════════════════════════════════════════════════
:: start.bat — تشغيل gorgon_bruteforce على VPS Windows
:: أو ترجمة وتشغيل على Windows (مع GCC/MinGW)
:: ══════════════════════════════════════════════════════
setlocal

:: ── الإعدادات ──────────────────────────────────────────
set THREADS=8
set URL_MD5=00000000000000000000000000000000
set STUB=
set COOKIE_MD5=
set TS=0
set TARGET=840400000000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
set FIXED=0,0,0,0,0,0,0,0

:: ── تجميع إذا لم يكن موجوداً ──────────────────────────
if not exist gorgon_bf.exe (
    echo [*] تجميع gorgon_bruteforce.c ...
    where gcc >nul 2>&1
    if errorlevel 1 (
        echo [!] GCC غير موجود. حمل MinGW أو استخدم WSL.
        pause
        exit /b 1
    )
    gcc -O3 -o gorgon_bf.exe gorgon_bruteforce.c -lpthread
    if errorlevel 1 (
        echo [!] فشل التجميع.
        pause
        exit /b 1
    )
    echo [+] تم التجميع بنجاح.
)

:: ── تشغيل في الخلفية ──────────────────────────────────
echo [*] بدء gorgon_bruteforce في الخلفية...
echo [*] النتائج في: output.log

if "%STUB%"=="" (
    start /B gorgon_bf.exe ^
        --url-md5 %URL_MD5% ^
        --ts %TS% ^
        --target %TARGET% ^
        --fixed "%FIXED%" ^
        --threads %THREADS% ^
        > output.log 2>&1
) else (
    start /B gorgon_bf.exe ^
        --url-md5 %URL_MD5% ^
        --stub %STUB% ^
        --cookie-md5 %COOKIE_MD5% ^
        --ts %TS% ^
        --target %TARGET% ^
        --fixed "%FIXED%" ^
        --threads %THREADS% ^
        > output.log 2>&1
)

echo [+] يعمل في الخلفية. لمتابعة النتائج:
echo     type output.log
echo     أو: powershell Get-Content output.log -Wait
echo.
echo [!] لإيقافه: taskkill /IM gorgon_bf.exe /F
endlocal
