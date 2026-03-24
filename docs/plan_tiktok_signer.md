 خطة: tiktok_signer.py — موقّع طلبات TikTok الشامل

## Context
المشروع يحتاج ملف Python واحد يولّد التوقيعات الأربعة (X-Gorgon, X-Khronos, X-Argus, X-Ladon)
بالاستفادة من:
- الملفات المعترضة في `tik-api-1/` (1838 طلب حقيقي من v44.3.1)
- المكتبات الموجودة في `x-gorogn-khronos-argus-ladon-main/lib/`

البنية الحالية فيها `tiktok_signer_local.py` لكنها تفتقر لـ:
- استخراج جلسات الجهاز من ملفات الطلب المعترضة
- دعم Body المضغوط (gzip) وحساب X-SS-STUB الصحيح
- واجهة موحّدة تجمع كل التوقيعات

## الملف المستهدف
`/Users/mo/Documents/tik-api copy/tiktok/tiktok_signer.py`

## الملفات الحالية المستخدمة (لا تُعدَّل)
| الملف | الدور |
|---|---|
| `x-gorogn-khronos-argus-ladon-main/lib/XGorgon.py` | خوارزمية X-Gorgon (hex_str=all-zeros للإصدار 8404) |
| `x-gorogn-khronos-argus-ladon-main/lib/XArgus.py` | حساب X-Argus (يعمل محلياً) |
| `x-gorogn-khronos-argus-ladon-main/lib/XLadon.py` | حساب X-Ladon عبر `ladon_encrypt()` |
| `x-gorogn-khronos-argus-ladon-main/lib/sign.py` | Sign الشامل (Gorgon+Argus+Ladon) |
| `tiktok/sign_headers.py` | Facade موجود (يُكمَل بالاستدعاء من tiktok_signer.py) |
| `tik-api-1/Raw_*.folder/` | ملفات الطلب المعترضة (مصدر الجلسات) |

## هيكل الملف الجديد

```
tiktok_signer.py
├── _parse_raw_request_file(path)     # مُحلِّل ملفات .txt المعترضة
├── class DeviceSession               # بيانات جهاز مستخرجة من طلب حقيقي
├── class SessionStore                # يحمل كل الجلسات من جميع المجلدات
├── def compute_stub(body)            # X-SS-STUB = MD5(body_قبل_الضغط).upper()
├── def gzip_body(body)               # ضغط + إرجاع (compressed, stub)
├── def sign_request(...)             # الدالة الرئيسية العامة
└── if __name__ == "__main__"         # اختبار سريع
```

## تفاصيل التنفيذ

### 1. `_parse_raw_request_file(path)` → dict
```
method, host, path_query, headers{}, body_raw, body_original
```
- السطر الأول: `METHOD /path?query HTTP/1.1`
- الهيدرز: حتى السطر الفارغ
- إن وُجد `x-bd-content-encoding: gzip` → `body_original = gzip.decompress(body_raw)`
- إن كان الجسم `<Data Binary>` → `body_raw = body_original = b""`
- يستخرج من query_string: `device_id`, `iid`, `aid`, `version_code`, إلخ

### 2. `class DeviceSession`
حقول تُستخرج من الطلب المعترض:
```python
device_id, iid, openudid, cdid
cookies, x_tt_token, user_agent
aid, version_name, version_code
device_type, device_brand, os_version
x_argus, x_ladon, x_khronos: int
device_guard_headers: dict  # tt-device-guard-*, tt-ticket-guard-*
```
- `is_fresh()`: True إن (`time() - x_khronos`) < 86400

### 3. `class SessionStore`
```python
__init__(folders: list[str])      # يمسح كل مجلدات Raw_*.folder
get(device_id=None) → DeviceSession | None  # أحدث جلسة
list_devices() → list[str]
```
**المجلدات الافتراضية** (مسار نسبي من موقع tiktok_signer.py):
```
../tik-api-1/Raw_03-16-2026-01-10-54.folder
../tik-api-1/Raw_03-16-2026-01-22-49.folder
../tik-api-1/Raw_03-16-2026-02-44-45.folder
../tik-api-1/Raw_03-17-2026-03-49-53.folder
../tik-api-1/Raw_03-17-2026-03-58-36.folder
```
يحتفظ فقط بأحدث جلسة لكل `device_id` (الأعلى `x_khronos`).

### 4. `sign_request(url, method, body, session, device_id, gzip_body, signer_url)` → dict

**الخوارزمية:**
```
1. ts = int(time.time())
2. body_bytes = body.encode() if str else body
3. stub = MD5(body_bytes).upper()  إن POST وبه body
4. body_to_send = gzip(body_bytes) إن gzip_body=True
5. X-Khronos = str(ts)
6. X-SS-STUB = stub
7. X-Gorgon  ← XGorgon().calculate(query_string, {"x-ss-stub": stub, "cookie": session.cookies})
8. X-Ladon   ← ladon_encrypt(ts, 1611921764, 1233)  [محلي، يعمل دائماً]
9. X-Argus   ← Sign(params, headers) أو session.x_argus إن فشل Sign
10. تُضاف session headers: cookies, x_tt_token, device_guard_headers
```

**الاستراتيجية الهرمية لـ X-Argus:**
1. حساب محلي عبر `lib.sign.Sign()` (يعمل لمعظم الـ endpoints)
2. إن فشل: استخدام `session.x_argus` من الجلسة المعترضة (صالح ~24 ساعة)

### 5. الاستخدام كـ CLI
```bash
python3 tiktok_signer.py --url "https://api.../path?..." --method POST --body "..."
python3 tiktok_signer.py --url "..." --device-id 7617232110762329614
python3 tiktok_signer.py --list-devices
```

### 6. التكامل مع sign_headers.py
`tiktok_signer.py` يُصدّر دالة `sign(url, method, body, cookie)` بنفس توقيع `tiktok_signer_local.py`
→ يمكن إضافته كخيار 5 في `sign_headers.py` بدون تعديل الملف الحالي.

## التحقق
```bash
cd "/Users/mo/Documents/tik-api copy"
# اختبار مباشر
python3 tiktok/tiktok_signer.py --url "https://api16-normal-c-alisg.tiktokv.com/passport/user/login/?device_id=7617232110762329614&ts=..." --method POST --body "username=...&password=..."

# التحقق من الهيكل:
# X-Gorgon: 52 حرف hex يبدأ بـ 8404
# X-Khronos: timestamp حالي
# X-Argus: base64 > 400 حرف
# X-Ladon: base64 ~44 حرف
# X-SS-STUB: 32 حرف hex كبير

# اختبار الجلسات
python3 tiktok/tiktok_signer.py --list-devices

# اختبار body مضغوط
python3 tiktok/tiktok_signer.py --url "..." --method POST --body "..." --gzip
```

## التبعيات (موجودة بالفعل في .venv)
- `hashlib`, `gzip`, `urllib.parse`, `glob`, `dataclasses` — stdlib
- `pycryptodome` — موجود في .venv (مطلوب لـ XArgus)