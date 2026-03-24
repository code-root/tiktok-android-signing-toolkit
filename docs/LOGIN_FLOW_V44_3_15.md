# TikTok Android — تدفق تسجيل الدخول الكامل (v44.3.15)

**التطبيق:** `com.zhiliaoapp.musically` · **version_code:** `440315` · **version_name:** `44.3.15`  
**المصدر:** التقاط MITM حقيقي (آذار 2026) + مطابقة مع `login_client.py` / `signing_engine.py` في هذا المجلد.

> **تنبيه:** استخدام واجهات غير الرسمية قد يخالف شروط خدمة TikTok. هذا المستند لأغراض البحث والتوافق مع الأجهزة التي تملكها.

---

## نظرة عامة على التدفق

| # | الخطوة | الوصف المختصر |
|---|--------|----------------|
| 1 | `POST /passport/app/region/` على **useast5** | اكتشاف أولي للمنطقة / إعادة توجيه منطقي نحو الكانونية |
| 2 | `POST /passport/app/region/` على **الدومين الكانوني** (مثل alisg) | استلام `domain` + `device_redirect_info` + `captcha_domain` |
| 3 | `POST /captcha/verify` (على `captcha_domain`) | تحقق منزلق pre-login عند الطلب؛ الـ body داخل `edata` مشفّر |
| 4 | `POST /passport/user/login/` | عند تسجيل مشبوه: `error_code` **2135** + `passport_ticket` + `verify_ticket` (يتطلب 2FA/IDV) |
| 5 | `POST /passport/aaas/authenticate/` **`action=3`** | طلب إرسال OTP للبريد (`challenge_type=2`) |
| 6 | `POST /passport/aaas/authenticate/` **`action=4`** | إرسال كود OTP بعد ترميزه بنفس طريقة الحقول في تسجيل الدخول |
| 7 | `POST /passport/app/region/` مرة أخرى | تجديد `device_redirect_info` بعد نجاح AAAS |

في التطبيق الفعلي تسبق هذه الخطوات غالباً: `get_nonce`، `check_login_name_registered`، `login/pre_check` — مُنفَّذة في `TikTokLoginClient.login()`.

---

## الخطوة 1 و 2 — اكتشاف المنطقة (`/passport/app/region/`)

### Host الأول (مثال)

`POST https://api16-normal-useast5.tiktokv.us/passport/app/region/`

### معاملات الاستعلام الأساسية (مثال من الالتقاط)

| Parameter | Value (مثال) |
|-----------|----------------|
| `device_platform` | `android` |
| `aid` | `1233` |
| `app_name` | `musical_ly` |
| `version_code` | `440315` |
| `version_name` | `44.3.15` |
| `iid` | معرف التثبيت |
| `device_id` | معرف الجهاز |

### Body (form-urlencoded)

```
hashed_id=<SHA-256(hex)>&type=3
```

- **`type=3`:** سياق تسجيل عبر البريد / المعرف الحسابي.
- **`hashed_id`:** في تدفق البريد يُشفَّر غالباً **SHA-256** لسلسلة المعرف (بريد مُطبَّع `strip` + `lower` إن وُجد `@`).  
  إن لم يُمرَّر بريد، يمكن استخدام **SHA-256(`device_id`)** كمسار بديل (ضيف / قبل ربط الحساب) — انظر `TikTokLoginClient._region_hashed_id()`.

### استجابة نموذجية

```json
{
  "data": {
    "domain": "api16-normal-c-alisg.tiktokv.com",
    "device_redirect_info": "<token>",
    "captcha_domain": "rc-verification-sg.tiktokv.com",
    "country_code": "-"
  }
}
```

**`device_redirect_info`:** token حساس؛ يُضاف كمعامل `device_redirect_info` في طلبات `passport` اللاحقة (انظر `_base_params(..., include_device_redirect=True)`).

**في الكود:** `step_app_region_chain()` ينفّذ [1] ثم [2] تلقائياً.

---

## الخطوة 3 — CAPTCHA (Slide / Pre-login)

- **Endpoint (مثال):** `POST https://<captcha_domain>/captcha/verify`
- **Body:** JSON يحتوي **`edata`** (~7KB) — تشفير تطبيقي (AES/RSA حسب عميل TikTok).
- **الاستجابة:** `edata` مشفّر؛ يُستخرج منه token يُخزَّن في كوكي **`msToken`** بعد الدمج مع `Set-Cookie`.

عند `error_code` **1105** على `/passport/user/login/` يجب حل CAPTCHA ثم إعادة المحاولة — يتطلب ذلك حلاً خارجياً أو خدمة متوافقة (غير مضمنة هنا).

---

## الخطوة 4 — تسجيل الدخول الفعلي

**Endpoint (مثال):**  
`POST https://api16-normal-c-alisg.tiktokv.com/passport/user/login/`

### معاملات إضافية عن `region`

| Parameter | ملاحظة |
|-----------|--------|
| `passport-sdk-version` | `1` |
| `_rticket` | طابع زمني بالمللي ثانية |
| `device_redirect_info` | من خطوة region |

### Body (x-www-form-urlencoded)

```
password=<hex>&account_sdk_source=app&multi_login=1&mix_mode=1&username=<hex>
```

### ترميز الحقول (`mix_mode=1`)

لكل محرف في اسم المستخدم أو كلمة المرور أو كود OTP:

`hex( (ord(char) XOR K) )` بحرفين hex.

- **v44.3.15 (مطابقة الالتقاط):** `K = 0x05` — الثابت `LOGIN_BODY_XOR_KEY` في `login_client.py`.  
  مثال: `storegs2` → `76716a7760627637`.  
- **بنيات أقدم:** قد تستخدم `K = 0x17` — استدعِ `encode_password(..., xor_key=0x17)`.

### استجابة 2FA (مثال)

```json
{
  "data": {
    "error_code": 2135,
    "passport_ticket": "PPT...",
    "verify_ticket": "VTI..."
  },
  "message": "error"
}
```

### رؤوس مهمة في الاستجابة

- **`D-Ticket`:** قيمة تُدمج كـ **`d_ticket`** في الكوكي (يُعالج في `TikTokLoginClient._http`).
- **`Set-Cookie: d_ticket=...`**
- **`X-Tt-Verify-Idv-Decision-Conf`:** JSON يحتوي `passport_ticket` و`pseudo_id` وغيرها — يُحلَّل في `login()` لاستخراج `pseudo_id`.

---

## الخطوة 5 — طلب OTP (`AAAS` `action=3`)

**POST** `.../passport/aaas/authenticate/`

معاملات الاستعلام تشمل مثلاً: `challenge_type=2`, `action=3`, `passport_ticket`, `pseudo_id`, `mix_mode=0`, `fixed_mix_mode=0`, `skip_handler=error_handler`.

**Body:** يطابق الحقول الظاهرة في الاستعلام (form).

**رأس مهم:** `x-tt-referer: https://inapp.tiktokv.com/ucenter_web/idv_core/verification`

---

## الخطوة 6 — التحقق من OTP (`AAAS` `action=4`)

- **`action=4`**, **`mix_mode=1`**, **`fixed_mix_mode=1`**
- **`code=`** بنفس ترميث hex (XOR **0x05** افتراضياً) لسلسلة الأرقام الستة.

عند النجاح: `{"data": null, "message": "success"}` غالباً مع **`X-Tt-Store-Sec-Uid`** وتحديث الكوكيز.

---

## الخطوة 7 — تجديد `device_redirect_info`

بعد نجاح `action=4`، يستدعي `login()` داخلياً `step_app_region(region_id_source=...)` مرة أخرى لمزامنة التوجيه مع الخادم.

---

## التوقيعات ومكافحة الروبوت

| Header | دور تقريبي |
|--------|------------|
| **X-Argus** | توقيع protobuf + تشفير — يتغيّر كل طلب |
| **X-Gorgon** | HMAC/سلسلة بايتات على المسار + الجسم + زمن |
| **X-Khronos** | Unix timestamp (ثوانٍ) |
| **X-Ladon** | توقيع ثانوي مرتبط ببنية Argus |
| **X-SS-STUB** | `MD5(body).upper()` للـ POST ذي الجسم النصي |

التوليد المحلي: **`signing_engine.sign()`**.

---

## Device / Ticket Guard

- **`tt-device-guard-client-data`:** Base64 لـ JSON فيه `device_token`, `timestamp`, `dtoken_sign`, `dreq_sign` (ECDSA).
- **`tt-ticket-guard-public-key`:** مفتاح ECDSA عام (ثابت للجلسة غالباً).
- **`tt-ticket-guard-version`**, **`tt-device-guard-iteration-version`**, **`sdk-version`**, إلخ.

يُبنى ديناميكياً عبر `device_guard.build_guard_headers()` عند وجود `guard_keys.private_pem` في ملف الجهاز.

---

## الكوكيز المهمة

| Cookie | دور |
|--------|-----|
| `store-idc` | منطقة التخزين بعد region |
| `tt-target-idc` | IDC مستهدف |
| `msToken` | بعد CAPTCHA / التدفق |
| `d_ticket` | بعد login حتى عند خطأ 2135 |
| `odin_tt` | جلسة / دوران عبر التدفق |

لطلبات `passport` بعد `pre_check` يجب إرسال **`msToken`** و**`d_ticket`** عند توفرهما في الكوكي — الدالة **`_cookie_for_passport_request()`** تجمع ذلك.

---

## ترتيب الرؤوس (ملخص)

راجع `TikTokLoginClient._sign_and_build_headers()` — يشمل على سبيل المثال:

`User-Agent`, `Cookie`, `x-tt-dm-status`, `X-SS-REQ-TICKET`, `X-SS-STUB`, `x-tt-trace-id`, مفاتيح guard، `X-Argus`, `X-Gorgon`, `X-Khronos`, `X-Ladon`.

---

## أوامر سريعة

```bash
# فحص اسم مستخدم فقط
python3 login_client.py --username USER --step1

# تسجيل دخول كامل (مع بريد لـ hashed_id في region إن لزم)
python3 login_client.py --username USER --password '...' --region-email 'you@example.com'

# تدفق: تسجيل جهاز + دخول
python3 flow.py --username USER --password '...' --region-email 'you@example.com'
```

---

## مراجع داخل المستودع

| ملف | المحتوى |
|-----|---------|
| `login_client.py` | `TikTokLoginClient`, `encode_password`, `step_app_region_chain`, `login()` |
| `signing_engine.py` | توليد X-Gorgon / Argus / Ladon / STUB |
| `device_guard.py` | رؤوس guard الديناميكية |
| `login_flow_captured_values.json` | قيم مرجعية من الالتقاط |

---

## `error_code: 31` (رفض المنطق / البصمة)

يظهر أحياناً على `check_login_name_registered` أو خطوات passport الأخرى. يعني غالباً أن **الخادم رفض سياق الجهاز** (risk): جلسة غير مسجّلة، تعارض بين `User-Agent` وحقول الجهاز في الـ URL، مفاتيح **guard** غير مرتبطة بـ `device_id` الحقيقي، أو قناة التوزيع (`channel`) لا تطابق بناء التطبيق.

**ماذا تفعل:**

1. شغّل اختبار وهمي: `python3 fake_login_probe.py` (يستخدم افتراضياً `device_emulator_mitm_44315.json` — محاكي Android 16 يطابق التقاط MITM).
2. سجّل الجهاز عبر `device_register.py` وحدّث الملف بـ `device_id` / `iid` و **`guard_keys`** الناتجة عن التسجيل الفعلي.
3. تأكد أن **`channel`** في JSON (`beta` / `googleplay` / …) يطابق ما يظهر في الـ query؛ داخل **`compute_argus`** يجب أن يُمرَّر نفس الـ `channel` الموجود في الـ URL (تم إصلاح ذلك في `signing_engine.py`).

---

## أدوات اختبار

```bash
cd tiktok_final
python3 fake_login_probe.py --verbose
python3 fake_login_probe.py --device device_v44_3_1.json
```

### بروكسي `proxsy.txt` (Geonode)

سطور بالشكل `host:port:user:pass` حيث **اسم المستخدم قد يحتوي على `:`** (مثل `...-session-xyz`). الدالة `_proxy_line_to_url` تتعامل مع ذلك: آخر جزء بعد آخر `:` هو كلمة المرور.

- `fake_login_probe.py` يحمّل تلقائياً `tiktok_final/proxsy.txt` إن وُجد (ما لم تستخدم `--no-proxy`).
- `flow.py` / `login_client.py` / `device_register.py`: `--proxy-file proxsy.txt`

### مجلد اعتراض api-proxy (`Raw_....folder`)

ملفات الطلبات بنفس شكل: `[id] Request - host_path.txt`.

```bash
# قائمة ملفات passport/login داخل المجلد
python3 mitm_raw.py /path/to/api-proxy/Raw_03-23-2026-14-39-43.folder

# استخراج patch مقترح لملف جهاز من طلب واحد (مثال من نسخة موجودة في المستودع)
python3 mitm_raw.py /path/to/folder --suggest "/path/to/[2913] Request - ..._passport_user_login_.txt"
```

ضع مجلد `Raw_03-23-2026-14-39-43.folder` تحت جذر المستودع في `api-proxy/` أو مرّر المسار الكامل لـ `--mitm-folder`.

إن لم يُعثر عليه تلقائياً، يبحث السكربت أيضاً تحت `~/Desktop`, `~/Downloads`, `~/Documents` (مع أو بدون `api-proxy/`).  
أو حدّد مساراً مطلقاً: `export TIKTOK_MITM_FOLDER="/path/to/Raw_03-23-2026-14-39-43.folder"`.
