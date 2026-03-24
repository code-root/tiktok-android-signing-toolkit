/**
 * frida_hook_tiktok.js
 * TikTok v44.x — اعتراض توقيعات X-Gorgon / X-Argus / X-Ladon / X-Khronos
 *
 * التشغيل:
 *   frida -U -f com.zhiliaoapp.musically --no-pause -l frida_hook_tiktok.js
 *   frida -U com.zhiliaoapp.musically    -l frida_hook_tiktok.js   (إذا كان يعمل)
 *
 * الإخراج:
 *   frida -U -f com.zhiliaoapp.musically --no-pause -l frida_hook_tiktok.js \
 *         2>&1 | tee captured_signs.log
 *
 * المستويات:
 *   LEVEL 1 — Java layer: g2.frameSign()  (أسهل، يُظهر النتيجة الكاملة)
 *   LEVEL 2 — Java layer: ms.bd.o.k.a()  (الـ JNI dispatcher)
 *   LEVEL 3 — Native: libmetasec_ov JNI_OnLoad + memory scan
 *   LEVEL 4 — Network: OkHttp / TTNet headers (يلتقط الطلب النهائي)
 */

"use strict";

// ══════════════════════════════════════════════════════════════════════
// إعدادات
// ══════════════════════════════════════════════════════════════════════
const CONFIG = {
    // ما الذي يُطبع
    log_framesign:    true,   // النتيجة النهائية (X-Gorgon etc)
    log_native_ka:    true,   // كل استدعاءات k.a()
    log_network:      true,   // headers في الطلبات الفعلية
    log_native_mem:   false,  // scan الذاكرة (ثقيل)
    log_device_info:  true,   // device_id, install_id عند الضبط
    save_to_file:     false,  // حفظ في /data/local/tmp/tiktok_signs.json
    filter_url:       "",     // فلتر URL (مثل "device_register") — فارغ = الكل
};

// ══════════════════════════════════════════════════════════════════════
// أدوات مساعدة
// ══════════════════════════════════════════════════════════════════════
const tag  = "[TikTok-Hook]";
const sep  = "─".repeat(60);
let capturedSigns = [];

function log(msg)  { console.log(`${tag} ${msg}`); }
function warn(msg) { console.warn(`${tag} ⚠️  ${msg}`); }
function ok(msg)   { console.log(`${tag} ✅ ${msg}`); }
function err(msg)  { console.error(`${tag} ❌ ${msg}`); }

function ts() {
    return new Date().toISOString().replace("T", " ").substring(0, 23);
}

function javaMapToObj(javaMap) {
    try {
        const result = {};
        const iter = javaMap.entrySet().iterator();
        while (iter.hasNext()) {
            const entry = iter.next();
            result[entry.getKey().toString()] = entry.getValue().toString();
        }
        return result;
    } catch(e) {
        return {};
    }
}

function saveSign(record) {
    capturedSigns.push(record);
    if (CONFIG.save_to_file && capturedSigns.length % 5 === 0) {
        try {
            const f = new File("/data/local/tmp/tiktok_signs.json", "w");
            f.write(JSON.stringify(capturedSigns, null, 2));
            f.flush();
            f.close();
        } catch(e) {}
    }
}

// ══════════════════════════════════════════════════════════════════════
// LEVEL 1: Hook g2.frameSign() — النتيجة النهائية
// ══════════════════════════════════════════════════════════════════════
function hookFrameSign() {
    try {
        const g2 = Java.use("ms.bd.o.g2");

        g2.frameSign.implementation = function(url, flags) {
            const result = this.frameSign(url, flags);

            if (!CONFIG.log_framesign) return result;
            if (CONFIG.filter_url && url && !url.includes(CONFIG.filter_url)) return result;

            const headers = javaMapToObj(result);
            const record = {
                time:    ts(),
                source:  "frameSign",
                url:     url,
                flags:   flags,
                headers: headers,
            };

            console.log("\n" + sep);
            log(`frameSign() — ${ts()}`);
            log(`URL: ${url ? url.substring(0, 120) : "(null)"}`);
            log(`flags: ${flags}`);

            for (const [k, v] of Object.entries(headers)) {
                console.log(`  ${k.padEnd(14)}: ${v}`);
            }

            saveSign(record);
            return result;
        };

        ok("g2.frameSign hooked");
    } catch(e) {
        err(`g2.frameSign: ${e.message}`);
    }
}

// ══════════════════════════════════════════════════════════════════════
// LEVEL 2: Hook ms.bd.o.k.a() — JNI native dispatcher
// ══════════════════════════════════════════════════════════════════════
const OPCODES = {
    33554433: "report",
    33554434: "setDeviceID",
    33554435: "setInstallID",
    33554436: "setUserID",
    33554441: "destroy",
    33554442: "frameSign",      // ← الأهم
    33554443: "updateSettings",
    16777217: "decrypt_string", // داخلي
};

function hookNativeDispatcher() {
    try {
        const k = Java.use("ms.bd.o.k");

        k.a.overload("int", "int", "long", "java.lang.String", "java.lang.Object")
          .implementation = function(op, flags, sessionId, str, obj) {

            const name = OPCODES[op] || `op_${op}`;
            const result = this.a(op, flags, sessionId, str, obj);

            if (!CONFIG.log_native_ka) return result;

            if (op === 33554442) {
                // frameSign — تُعالج في hookFrameSign بشكل أوضح
                return result;
            }

            if (op === 33554434 && CONFIG.log_device_info) {
                log(`setDeviceID("${str}")`);
            } else if (op === 33554435 && CONFIG.log_device_info) {
                log(`setInstallID("${str}")`);
            } else if (op === 33554436 && CONFIG.log_device_info) {
                log(`setUserID("${str}")`);
            } else if (op === 33554433) {
                // report — كثير جداً، أخفه
            } else {
                log(`k.a(${name}, flags=${flags}, str="${str ? str.substring(0,60) : ""}")`);
            }

            return result;
        };

        ok("ms.bd.o.k.a() hooked");
    } catch(e) {
        err(`ms.bd.o.k.a: ${e.message}`);
    }
}

// ══════════════════════════════════════════════════════════════════════
// LEVEL 3: Hook Native JNI_OnLoad في libmetasec_ov.so
// ══════════════════════════════════════════════════════════════════════
function hookNativeLibrary() {
    const libName = "libmetasec_ov.so";

    // Frida 17: Module.findBaseAddress removed → Process.findModuleByName
    function findBase(name) {
        var m = Process.findModuleByName(name);
        return m ? m.base : null;
    }
    // Frida 17: Module.findExportByName(null,x) removed → DebugSymbol.fromName
    function findExportAddr(name) {
        try {
            var sym = DebugSymbol.fromName(name);
            if (sym && !sym.address.isNull()) return sym.address;
        } catch(e) {}
        return null;
    }

    // انتظر حتى يُحمَّل
    let libBase = findBase(libName);
    if (!libBase) {
        log(`${libName} لم يُحمَّل بعد — سنراقب dlopen...`);

        const dlopenSym =
            findExportAddr("android_dlopen_ext") ||
            findExportAddr("__loader_android_dlopen_ext") ||
            findExportAddr("dlopen");

        if (dlopenSym) {
            Interceptor.attach(dlopenSym, {
                onLeave(retval) {
                    if (!libBase) {
                        libBase = findBase(libName);
                        if (libBase) {
                            log(`${libName} حُمِّل @ ${libBase}`);
                            attachNativeHooks(libBase);
                        }
                    }
                }
            });
        } else {
            // fallback: استطلاع كل 500ms حتى يُحمَّل
            warn("dlopen symbol not found — polling for lib load...");
            const pollTimer = setInterval(() => {
                libBase = findBase(libName);
                if (libBase) {
                    clearInterval(pollTimer);
                    log(`${libName} حُمِّل @ ${libBase}`);
                    attachNativeHooks(libBase);
                }
            }, 500);
        }
    } else {
        log(`${libName} موجود @ ${libBase}`);
        attachNativeHooks(libBase);
    }
}

function attachNativeHooks(libBase) {
    // JNI_OnLoad @ offset 0x4b680 (من التحليل السابق)
    const jniOnLoad = libBase.add(0x4b680);
    log(`JNI_OnLoad @ ${jniOnLoad}`);

    // Hook JNI_OnLoad للتأكد من التحميل الناجح
    try {
        Interceptor.attach(jniOnLoad, {
            onEnter(args) {
                ok(`libmetasec_ov JNI_OnLoad استُدعيت — JavaVM=${args[0]}`);
            },
            onLeave(retval) {
                log(`JNI_OnLoad returned: ${retval}`);
                scanForSigningFunctions(libBase);
            }
        });
        ok("JNI_OnLoad hook تم");
    } catch(e) {
        warn(`JNI_OnLoad hook فشل: ${e.message}`);
    }

    // ── Ghidra-discovered hooks ─────────────────────────────────────
    // Dispatcher رئيسي SWITCH(111cases) @ 0x0ef0f0
    try {
        Interceptor.attach(libBase.add(0x0ef0f0), {
            onEnter(args) {
                this.opcode = args[0].toInt32();
                log(`[DISPATCH-111] opcode=0x${this.opcode.toString(16)}  a1=${args[1]}  a2=${args[2]}`);
            },
            onLeave(retval) {
                log(`[DISPATCH-111] opcode=0x${this.opcode.toString(16)} → ret=${retval}`);
            }
        });
        ok("Dispatcher SWITCH(111) hooked @ +0x0ef0f0");
    } catch(e) { warn(`Dispatcher-111: ${e.message}`); }

    // Dispatcher ثانوي SWITCH(64cases) @ 0x169424
    try {
        Interceptor.attach(libBase.add(0x169424), {
            onEnter(args) {
                this.opcode = args[0].toInt32();
                log(`[DISPATCH-64] opcode=0x${this.opcode.toString(16)}  a1=${args[1]}`);
            }
        });
        ok("Dispatcher SWITCH(64) hooked @ +0x169424");
    } catch(e) { warn(`Dispatcher-64: ${e.message}`); }

    // X-Gorgon RC4 KSA @ 0x0a5bf0
    try {
        Interceptor.attach(libBase.add(0x0a5bf0), {
            onEnter(args) {
                log(`[GORGON-KSA] in:  ${hexdump(args[0], {length:20, ansi:false}).split('\n')[0]}`);
                this.out = args[1];
            },
            onLeave(retval) {
                try {
                    log(`[GORGON-KSA] out: ${hexdump(this.out, {length:26, ansi:false}).split('\n')[0]}`);
                } catch(_) {}
            }
        });
        ok("X-Gorgon KSA hooked @ +0x0a5bf0");
    } catch(e) { warn(`Gorgon-KSA: ${e.message}`); }

    // X-Argus (SIMON+BASE64) @ 0x10c1e8
    try {
        Interceptor.attach(libBase.add(0x10c1e8), {
            onEnter(args) {
                log(`[ARGUS] called — a0=${args[0]} a1=${args[1]} a2=${args[2]}`);
                this.outPtr = args[0];
            },
            onLeave(retval) {
                try {
                    // قراءة أول 64 byte من المخرجات
                    const bytes = Memory.readByteArray(this.outPtr, 64);
                    log(`[ARGUS] output[0..63]: ${buf2hex(bytes)}`);
                } catch(_) {}
            }
        });
        ok("X-Argus SIMON+BASE64 hooked @ +0x10c1e8");
    } catch(e) { warn(`Argus: ${e.message}`); }
}

function buf2hex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2,'0')).join(' ');
}

function scanForSigningFunctions(libBase) {
    if (!CONFIG.log_native_mem) return;

    log("بدء memory scan لإيجاد دوال التوقيع...");
    try {
        const libSize = Process.findModuleByName("libmetasec_ov.so").size;

        // نبحث عن pattern: تعليمات ARM64 تُعالج opcode 0x200000A
        // stp x29, x30 + sub sp (prologue نموذجي)
        const prologuePattern = "fd 7b ?? a9 ff ?? ?? d1";
        const matches = Memory.scanSync(libBase, libSize, prologuePattern);
        log(`وجدت ${matches.length} دالة بـ prologue نموذجي`);

        // اطبع أول 20
        matches.slice(0, 20).forEach((m, i) => {
            const offset = m.address.sub(libBase).toInt32();
            log(`  func[${i}] @ ${m.address} (offset +0x${offset.toString(16)})`);
        });
    } catch(e) {
        warn(`memory scan: ${e.message}`);
    }
}

// ══════════════════════════════════════════════════════════════════════
// LEVEL 4: Hook Network — TTNet / OkHttp headers
// ══════════════════════════════════════════════════════════════════════
function hookNetworkLayer() {
    if (!CONFIG.log_network) return;

    // Hook C938550aWv.LJ() — دالة إرسال الطلب مع التوقيع
    try {
        const C938550aWv = Java.use("X.C938550aWv");

        // LJ(interface, url, body, context, bool, string[], map, bool, bool)
        C938550aWv.LJ.overload(
            "X.InterfaceC928760aH8",
            "java.lang.String",
            "[B",
            "android.content.Context",
            "boolean",
            "[Ljava.lang.String;",
            "java.util.Map",
            "boolean",
            "boolean"
        ).implementation = function(iface, url, body, ctx, z, strs, map, z2, z3) {
            if (!CONFIG.filter_url || (url && url.includes(CONFIG.filter_url))) {
                log(`\n${sep}`);
                log(`HTTP Request → ${url ? url.substring(0, 120) : ""}`);
                if (map) {
                    const headers = javaMapToObj(map);
                    for (const [k, v] of Object.entries(headers)) {
                        if (k.toLowerCase().startsWith("x-")) {
                            console.log(`  ${k.padEnd(14)}: ${v}`);
                        }
                    }
                }
            }
            return this.LJ(iface, url, body, ctx, z, strs, map, z2, z3);
        };
        ok("C938550aWv.LJ (HTTP sender) hooked");
    } catch(e) {
        warn(`C938550aWv.LJ: ${e.message}`);
    }

    // Hook OkHttp (إذا كان TTNet يمر عليه)
    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        const Request = Java.use("okhttp3.Request");
        const Chain = Java.use("okhttp3.Interceptor$Chain");

        // intercept
        const RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function() {
            const req = this.request();
            const url = req.url().toString();
            if (!CONFIG.filter_url || url.includes(CONFIG.filter_url)) {
                const headers = req.headers();
                const gorgon = headers.get("X-Gorgon");
                if (gorgon) {
                    console.log("\n" + sep);
                    log(`OkHttp Request → ${url.substring(0, 100)}`);
                    console.log(`  X-Gorgon  : ${gorgon}`);
                    console.log(`  X-Khronos : ${headers.get("X-Khronos")}`);
                    console.log(`  X-Argus   : ${headers.get("X-Argus") || "(none)"}`);
                    console.log(`  X-Ladon   : ${headers.get("X-Ladon") || "(none)"}`);
                    console.log(`  X-SS-Stub : ${headers.get("X-SS-Stub") || "(none)"}`);

                    saveSign({
                        time: ts(),
                        source: "OkHttp",
                        url: url,
                        "X-Gorgon":  gorgon,
                        "X-Khronos": headers.get("X-Khronos"),
                        "X-Argus":   headers.get("X-Argus"),
                        "X-Ladon":   headers.get("X-Ladon"),
                        "X-SS-Stub": headers.get("X-SS-Stub"),
                    });
                }
            }
            return this.execute();
        };
        ok("OkHttp RealCall.execute hooked");
    } catch(e) {
        warn(`OkHttp hook: ${e.message}`);
    }
}

// ══════════════════════════════════════════════════════════════════════
// LEVEL 5: استخراج ثوابت التشفير من الذاكرة
// ══════════════════════════════════════════════════════════════════════
function dumpCryptoConstants() {
    log("محاولة استخراج ثوابت التشفير من الذاكرة...");

    // بعد تشغيل التطبيق، الثوابت ستكون مفككة في الذاكرة
    // نبحث عنها بعد أول استدعاء لـ frameSign

    setTimeout(() => {
        try {
            const libBase = (function(){ var m = Process.findModuleByName("libmetasec_ov.so"); return m ? m.base : null; })();
            if (!libBase) {
                warn("libmetasec_ov لم يُحمَّل بعد");
                return;
            }

            const libSize = Process.findModuleByName("libmetasec_ov.so").size;
            log(`فحص ${libSize} bytes في libmetasec_ov...`);

            // البحث عن argus prefix f281 (وجدناه عند 0x04F37B في static analysis)
            const f281Pattern = "f2 81";
            const f281Hits = Memory.scanSync(libBase, libSize, f281Pattern);
            log(`f2 81 prefix (argus): ${f281Hits.length} موقع`);
            f281Hits.slice(0, 5).forEach(m => {
                const buf = m.address.readByteArray(32);
                log(`  @ ${m.address}: ${bufToHex(buf)}`);
            });

            // البحث عن SIMON cipher constant 0x3DC94C3A046D678B
            const simonPattern = "8b 67 6d 04 3a 4c c9 3d";
            const simonHits = Memory.scanSync(libBase, libSize, simonPattern);
            if (simonHits.length > 0) {
                ok(`SIMON-128 constant وُجد في الذاكرة @ ${simonHits[0].address}`);
                simonHits.forEach(m => {
                    const buf = m.address.readByteArray(16);
                    log(`  @ ${m.address}: ${bufToHex(buf)}`);
                });
            } else {
                log("SIMON constant: غير موجود كـ plaintext (مُشفَّر)");
            }

            // البحث عن X-Gorgon string في الذاكرة (بعد فك التشفير)
            for (const header of ["X-Gorgon", "X-Argus", "X-Ladon", "X-Khronos"]) {
                const pattern = strToPattern(header);
                const hits = Memory.scanSync(libBase, libSize, pattern);
                if (hits.length > 0) {
                    ok(`"${header}" وُجد في الذاكرة @ ${hits[0].address}`);
                } else {
                    log(`"${header}": مُشفَّر في الذاكرة أيضاً`);
                }
            }

        } catch(e) {
            warn(`dumpCryptoConstants: ${e.message}`);
        }
    }, 10000); // انتظر 10 ثوانٍ بعد بدء التطبيق
}

function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join(" ");
}

function strToPattern(str) {
    return Array.from(str).map(c => c.charCodeAt(0).toString(16).padStart(2,"0")).join(" ");
}

// ══════════════════════════════════════════════════════════════════════
// تصدير النتائج عبر RPC
// ══════════════════════════════════════════════════════════════════════
rpc.exports = {
    // استدعاء من Python: session.exports.get_signs()
    get_signs() {
        return capturedSigns;
    },

    // تشغيل frameSign مباشرة بـ URL معين
    sign_url(url) {
        let result = null;
        Java.perform(() => {
            try {
                const h2 = Java.use("ms.bd.o.h2");
                const appId = "1233"; // TikTok aid
                const instance = h2.LIZ(appId);
                if (instance) {
                    const map = instance.frameSign(url, 0);
                    result = javaMapToObj(map);
                }
            } catch(e) {
                result = { error: e.message };
            }
        });
        return result;
    },

    // جلب device_id الحالي
    get_device_id() {
        let did = null;
        Java.perform(() => {
            try {
                const mgr = Java.use("com.ss.android.deviceregister.DeviceRegisterManager");
                did = mgr.getDeviceId();
            } catch(e) {
                did = "error: " + e.message;
            }
        });
        return did;
    },

    clear() {
        capturedSigns = [];
        return "cleared";
    }
};

// ══════════════════════════════════════════════════════════════════════
// نقطة الدخول — مع انتظار Java bridge
// ══════════════════════════════════════════════════════════════════════

// LEVEL 3 — خارج Java.perform (native hooks مباشرة)
hookNativeLibrary();

// Java hooks — تنتظر حتى يُهيَّأ ART
function initJavaHooks() {
    if (typeof Java === "undefined" || !Java.available) {
        setTimeout(initJavaHooks, 150);
        return;
    }
    Java.perform(() => {
        log("=".repeat(60));
        log("TikTok Signing Hook — بدء التهيئة");
        log("=".repeat(60));

        hookFrameSign();          // LEVEL 1 — الأهم
        hookNativeDispatcher();   // LEVEL 2
        hookNetworkLayer();       // LEVEL 4
        dumpCryptoConstants();    // LEVEL 5

        log("جاهز — في انتظار استدعاءات frameSign...\n");
    });
}

initJavaHooks();
