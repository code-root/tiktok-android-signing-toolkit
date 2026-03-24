# TikTok Android Signing Toolkit — أدوات v44.x (توقيع، تسجيل جهاز، لوجن)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-tiktok--android--signing--toolkit-181717?logo=github)](https://github.com/code-root/tiktok-android-signing-toolkit)
[![Tests](https://img.shields.io/badge/tests-test__all.py-lightgrey.svg)](tests/test_all.py)

**اسم مقترح للمستودع على GitHub:** `tiktok-android-signing-toolkit` — راجع [دليل النشر](docs/GITHUB_SETUP.md) للوصف، التاقات، والريليز.

**اللغات:** [English (افتراضي المستودع)](README.md) | **العربية (هذا الملف)**

مجموعة **للأغراض التعليمية والبحث العكسي (reverse engineering)** مبنية على تحليل تطبيق TikTok الرسمي على Android وملفات اعتراض (MITM) حقيقية.  
الهدف: فهم كيف تُبنى طلبات الـ API (التوقيعات، الهيدرز، تسجيل الجهاز، تدفق اللوجن) — **وليس** تجاوز الخدمة أو إساءة الاستخدام.

> **تنبيه:** استخدام هذه الأدوات ضد خوادم TikTok أو حسابات الغير قد ينتهك شروط الخدمة والقوانين المحلية. أنت المسؤول عن الاستخدام.

**مصدر البيانات المرجعية (مثال من المشروع):** مجلد التقاط `Raw_03-17-2026-03-58-36.folder`  
**تطبيق:** `com.zhiliaoapp.musically` — إصدارات مطابقة لـ v44.3.x (مثل 440301 / 440315) · Android

---

## جدول المحتويات 📑

1. [متطلبات التشغيل](#متطلبات-التشغيل)
2. [التثبيت](#التثبيت)
3. [هيكل المشروع](#هيكل-المشروع)
4. [من أين تشغّل الأوامر؟](#من-أين-تشغّل-الأوامر)
5. [البدء السريع](#البدء-السريع)
6. [أدوات سطر الأوامر (تفصيلي)](#أدوات-سطر-الأوامر-تفصيلي)
7. [متغيرات البيئة](#متغيرات-البيئة)
8. [استخدام المكتبة من بايثون](#استخدام-المكتبة-من-بايثون)
9. [ترميز كلمة المرور في جسم الطلب](#ترميز-كلمة-المرور-في-جسم-الطلب)
10. [هيدرز التوقيع](#هيدرز-التوقيع)
11. [طريقة التوقيع — مسار `sign()`](#signing-pipeline) (يشمل [الشرح الموسّع خطوة بخطوة](#signing-extended-walkthrough))
12. [معرّفات الجهاز](#معرّفات-الجهاز)
13. [تدفق اللوجن (مبسّط)](#تدفق-اللوجن-مبسط)
14. [رموز الأخطاء الشائعة](#رموز-الأخطاء-الشائعة)
15. [الاختبارات](#الاختبارات)
16. [مجلد `tools/`](#مجلد-tools)
17. [الوثائق في `docs/`](#الوثائق-في-docs)
18. [الملفات الحساسة و`.gitignore`](#الملفات-الحساسة-وgitignore)
19. [مشروع مرتبط: TikTokDeviceGenerator](#related-project-tiktokdevicegenerator)
20. [مراجع تقنية](#مراجع-تقنية)
21. [المطوّر والشركة والتواصل](#maintainer-company--contact)
22. [دعم المشروع](#support-this-project)

---

## متطلبات التشغيل 📋

- **Python 3.10+** (يُنصح بآخر إصدار مستقر)
- مكتبة **`pycryptodome`** (لـ X-Argus — AES-CBC داخل المحرك)

---

## التثبيت ⚙️

```bash
cd tiktok_final
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

محتوى `requirements.txt` الحالي:

```
pycryptodome>=3.20.0
```

بعض الميزات الاختيارية (مثل تحقيقات إضافية في الاختبارات) قد تحتاج حزمًا أخرى؛ راجع رسائل الاستيراد في `tests/test_all.py` إن وُجدت.

---

## هيكل المشروع 🗂️

| المسار | الوصف |
|--------|--------|
| **`ttk/`** | حزمة بايثون الرئيسية: التوقيع، اللوجن، تسجيل الجهاز، تدفق MITM، إلخ. |
| **`ttk/paths.py`** | يحدد `PROJECT_ROOT`، `FIXTURES_DIR`، `WORKSPACE_ROOT`، ودالة **`resolve_data_path()`** لحل المسارات النسبية (جذر المشروع ثم `fixtures/`). |
| **`fixtures/`** | ملفات JSON جاهزة للجهاز: `device_v44_3_1.json`، أمثلة (`*.example.json`)، `devices_001.json`، إلخ. |
| **`tests/`** | `test_all.py` — مجموعة اختبارات شاملة. |
| **`docs/`** | توثيق تدفق اللوجن، تحليلات، خطط تنفيذ. |
| **`tools/`** | سكربتات مساعدة: Frida، JADX، Ghidra، APK/sig، مقارنة dumps. |
| **جذر المشروع** | ملفات رفيعة **`login_client.py`**, **`device_register.py`**, **`flow.py`**, **`mitm_raw.py`**, **`feed_api_client.py`**, **`fake_login_probe.py`** — كلها تستدعي الوحدة الحقيقية عبر `python3 -m ttk.<اسم>`. |

### وحدات `ttk/` (ملخص)

| الوحدة | الدور |
|--------|--------|
| `signing_engine.py` | توليد `X-Gorgon`, `X-Khronos`, `X-Argus`, `X-Ladon`, `X-SS-STUB` محليًا. |
| `login_client.py` | عميل لوجن كامل (خطوات متعددة، كابتشا/تحقق حيث ينطبق). |
| `device_register.py` | تسجيل جهاز جديد عبر واجهة TikTok (`device_register`). |
| `flow.py` | تسجيل جهاز ثم لوجن في مسار واحد. |
| `mitm_raw.py` | قراءة مجلدات اعتراض Raw واستخراج/مقارنة الطلبات. |
| `fake_login_probe.py` | اختبار «جاف» بدون إرسال كلمة مرور حقيقية (فحص هيدرز/استجابة). |
| `feed_api_client.py` | مثال طلب فيد (Feed) مع التوقيع. |
| `device_guard.py` | بيانات حماية التذاكر (guard) عند توفر المفاتيح. |
| `virtual_devices.py` | توليد بروفايلات أجهزة افتراضية ديناميكية + تخزين JSON اختياري في `fixtures/virtual_devices.json`. |
| `rapidapi_signer.py` | توقيع عبر واجهة RapidAPI (بديل عن المحرك المحلي). |
| `tiktok_apk_sig.py` | استخراج/دمج `sig_hash` من APK مع قالب الجهاز. |

---

## من أين تشغّل الأوامر؟ 📍

**شغّل كل الأوامر من مجلد `tiktok_final/`** (جذر المشروع الذي يحتوي على مجلد `ttk/`) حتى يعمل `import ttk` بشكل صحيح.

يمكنك استخدام إما:

- **`python3 login_client.py ...`** (الملف في الجذر = غلاف)، أو  
- **`python3 -m ttk.login_client ...`** (مباشرة على الحزمة).

---

## البدء السريع 🚀

### أ) لوجن بجهاز جاهز من `fixtures/`

```bash
python3 login_client.py --username USER --password "YourPassword"
```

الافتراضي: **`fixtures/device_v44_3_1.json`** (ما لم تمرّر `--device`).

### ب) خطوة واحدة فقط (تحقق من اسم المستخدم)

```bash
python3 login_client.py --username USER --step1
```

### ج) تسجيل جهاز جديد ثم حفظ الملف

```bash
python3 device_register.py --out my_device.json --verbose
python3 login_client.py --device my_device.json --username USER --password "PASS"
```

لو أردت **واجهة رسومية** وتسجيل **دفعات** من الأجهزة عبر **Java + unidbg** (حمولة ثنائية ثم `device_register`)، راجع المستودع المرتبط **[TikTokDeviceGenerator](https://github.com/code-root/TikTokDeviceGenerator)** — يكمّل أداة **`device_register.py`** البحتة بايثون في هذا المشروع.

### د) مسار كامل: تسجيل + لوجن

```bash
python3 flow.py --username USER --password "PASS"
```

### هـ) توقيع طلب يدويًا (محرك محلي)

```bash
python3 -m ttk.signing_engine --url 'https://...?' --method POST --body 'a=b' --cookie '...'
```

---

## أدوات سطر الأوامر (تفصيلي) 🖥️

### 1) `login_client` — عميل اللوجن

| الخيار | الوصف |
|--------|--------|
| `--username` | مطلوب. اسم المستخدم. |
| `--password` | كلمة المرور نصية (تُرمَّز تلقائيًا). |
| `--password-hex` | كلمة مرور مرمّزة مسبقًا (hex). |
| `--device` | مسار JSON للجهاز (افتراضيًا: قالب `fixtures`). |
| `--proxy` | بروكسي HTTP/HTTPS، مثل `http://user:pass@host:port`. |
| `--proxy-file` | أول سطر صالح `host:port:user:pass` يُستخدم كبروكسي. |
| `--no-proxy` | تجاهل الملفات ومتغيرات البيئة للبروكسي. |
| `--step1` | فقط `check_login_name` / التحقق من التسجيل. |
| `--step2` | فقط `pre_check`. |
| `--skip-check` | تخطي الخطوة 1. |
| `--region-email` | بريد لحساب `hashed_id` في مسارات المنطقة (بدل الاعتماد على `device_id` فقط حيث ينطبق). |
| `--devices-batch` | ملف JSON بأسلوب `devices_001.json` (قائمة `.devices[]` مع `.record`) لدمج كل صف مع قاعدة `--device`. |
| `--batch-offset` / `--batch-limit` | تقطيع الدفعة. |
| `--proxy-rotate-file` | مع الدفعة: بروكسي مختلف لكل صف من ملف أسطر. |
| `--batch-summary-out` | كتابة ملخص JSON بعد الدفعة. |
| `--verbose` | طباعة الطلبات/الاستجابات بالتفصيل. |
| `--sign-backend local\|rapidapi` | محلي (افتراضي) أو RapidAPI. |
| `--rapidapi-key` | مفتاح RapidAPI (أو عبر `RAPIDAPI_KEY`). |

**مثال دفعة:**

```bash
python3 login_client.py --username U --step1 --devices-batch fixtures/devices_001.json
```

---

### 2) `device_register` — تسجيل جهاز

| الخيار | الوصف |
|--------|--------|
| `--base` | قالب جهاز (افتراضيًا يُحلّ إلى `fixtures/device_v44_3_1.json` عبر `resolve_data_path`). |
| `--apk` | مسار APK لاستخراج `sig_hash` ودمجه في القالب قبل الطلب. |
| `--extract-sig-only` | مع `--apk` و `--out`: تحديث JSON بالتوقيع فقط دون استدعاء الخادم. |
| `--virtual REGION` | بناء القاعدة من `virtual_devices.generate_device_profile` (يتجاوز `--base`). |
| `--out` | ملف الإخراج (افتراضيًا `device_<timestamp>.json` في جذر المشروع). |
| `--proxy` / `--proxy-file` | بروكسي. |
| `--verbose` | تفاصيل الطلبات. |
| `--allow-local-fallback` | عند فشل/صفر من الخادم: الاستمرار بمعرّفات محلية عشوائية (**ليس** تسجيلًا حقيقيًا على الخادم). |
| `--dump-golden DIR` | حفظ لقطات طلب/استجابة لكل محاولة (مقارنة مع MITM). |
| `--golden-only DIR` | تشغيل محاولة واحدة وتسجيل «golden» ثم الخروج. |

---

### 3) `flow` — تسجيل + لوجن

| الخيار | الوصف |
|--------|--------|
| `--username` / `--password` / `--password-hex` | بيانات الدخول. |
| `--device` | استخدام جهاز موجود (تخطّي التسجيل). |
| `--skip-register` | استخدام القالب الافتراضي من `fixtures` بدون تسجيل جديد. |
| `--save-device` | مسار حفظ الجهاز بعد تسجيل ناجح. |
| `--proxy` / `--proxy-file` | بروكسي للتسجيل واللوجن. |
| `--verbose` | تفاصيل. |
| `--region-email` | كما في `login_client`. |
| `--allow-local-fallback` | كما في `device_register`. |

بعد التسجيل يستدعي التدفيق **`get_domains`** لتسخين الجلسة (cookies) حيث ينطبق المنطق في الكود.

---

### 4) `mitm_raw` — مجلدات الاعتراض

الوسيط الأول: **مسار مجلد** `Raw_MM-DD-YYYY....folder`.

| الخيار | الوصف |
|--------|--------|
| `--list` | قائمة ملفات متعلقة بـ passport/login. |
| `--dump FILE` | تحليل ملف طلب واحد → JSON. |
| `--suggest FILE` | اقتراح patch لملف الجهاز من طلب. |
| `--flow-diff` | مقارنة ترتيب الطلبات مع مرجع `login_client`. |
| `--export-device OUT.json` | دمج بصمة MITM في قالب JSON. |
| `--template BASE.json` | قالب الجهاز (مثلاً `fixtures/device_v44_3_1.json` أو مسار يُحلّ تلقائيًا). |
| `--from-file FILE` | ملف طلب محدد بدل الاكتشاف التلقائي. |

---

### 5) `fake_login_probe` — فحص بدون لوجن حقيقي

| الخيار | الوصف |
|--------|--------|
| `--device` | ملف جهاز (افتراضي محلي في الجذر إن وُجد). |
| `--username` | اسم ثابت؛ وإلا اسم عشوائي `probe_*`. |
| `--proxy` / `--proxy-file` / `--no-proxy` | بروكسي. |
| `--mitm-folder` / `--mitm-only` / `--mitm-list-repo` | استكشاف مجلدات Raw في المستودع المجاور. |
| `--verbose` | تفاصيل. |
| `--skip-region` | تخطي سلسلة nonce/region. |
| `--only-sign` | طباعة التوقيعات محليًا فقط. |
| `--step1-only` | التوقف بعد أول خطوة تحقق. |

---

### 6) `feed_api_client`

سكربت يجلب الفيد عند توفر ملف جهاز مسجّل محليًا (افتراضيًا يبحث عن `device_emulator_registered.json` في **جذر المشروع**). راجع الكود لمتطلبات البروفايل.

---

### 7) `signing_engine` (CLI)

| الخيار | الوصف |
|--------|--------|
| `--url` | عنوان كامل مع query. |
| `--method` | GET/POST/… |
| `--body` | جسم الطلب (نص). |
| `--cookie` | قيمة رأس Cookie. |
| `--ts` | طابع زمني Unix (افتراضي: الآن). |

---

## متغيرات البيئة 🔧

| المتغير | الاستخدام |
|----------|-----------|
| `RAPIDAPI_KEY` / `X_RAPIDAPI_KEY` | مفتاح RapidAPI عند `--sign-backend rapidapi`. |
| `TIKTOK_SIGN_BACKEND` | `local` أو `rapidapi`. |
| `TIKTOK_PROXY_FILE` | مسار ملف بروكسي (سطر تنسيق `host:port:user:pass`). |
| `TIKTOK_PROXY` / `HTTP_PROXY` / `HTTPS_PROXY` | بروكسي للطلبات (حسب منطق `login_client`). |
| `TIKTOK_MITM_FOLDER` | مجلد اعتراض افتراضي لبعض مسارات الاستكشاف في `fake_login_probe`. |

---

## استخدام المكتبة من بايثون 🐍

```python
from ttk.signing_engine import sign, compute_stub

sig = sign(
    url="https://api16-normal-c-alisg.tiktokv.com/passport/user/login/?aid=1233&ts=1234567890",
    method="POST",
    body=b"username=test&password=test",
    cookie="store-idc=useast5; ...",
)
# sig → X-Gorgon, X-Khronos, X-Argus, X-Ladon, X-SS-STUB (حسب الطلب)
```

```python
from ttk.login_client import TikTokLoginClient, encode_password
from ttk.paths import FIXTURES_DIR, PROJECT_ROOT, resolve_data_path

client = TikTokLoginClient(device_path=None, verbose=True)
# encode_password("secret")  # XOR افتراضي 0x05 (إصدارات حديثة)
```

```python
from ttk.device_register import TikTokDeviceRegister

dr = TikTokDeviceRegister(verbose=True)
reg = dr.register()
```

```python
from ttk.rapidapi_signer import sign_via_rapidapi  # يتطلب RAPIDAPI_KEY في البيئة
```

---

## ترميز كلمة المرور في جسم الطلب 🔑

التطبيق يرسل حقول مثل اسم المستخدم وكلمة المرور في الـ body بعد XOR ثم تمثيل hex لكل بايت.

- **الإصدارات الحديثة (مطابقة v44.3.15 في الكود):** XOR بمفتاح **`0x05`** (الثابت `LOGIN_BODY_XOR_KEY` في `login_client`).
- **إصدارات أقدم (ملاحظات 44.3.1):** قد تحتاج **`xor_key=0x17`**:

```python
from ttk.login_client import encode_password

encode_password("MyPassword123")           # افتراضي 0x05
encode_password("MyPassword123", xor_key=0x17)  # أسلوب أقدم
```

---

## هيدرز التوقيع 🔐

| الهيدر | فكرة الخوارزمية | مدخلات رئيسية |
|--------|-----------------|---------------|
| `X-SS-STUB` | MD5 للجسم (أحرف كبيرة) | بايتات الجسم الخام |
| `X-Khronos` | وقت Unix | `ts` |
| `X-Gorgon` | طبقة RC4-like + تبديل nibbles | معاملات URL، STUB، cookie، الزمن |
| `X-Ladon` | SIMON-128/ECB + padding | `{ts}-{license_id}-{aid}` |
| `X-Argus` | Protobuf + تشفير متعدد الطبقات | معاملات الجهاز والزمن |

التفاصيل الرياضية والثوابت مضمنة في `ttk/signing_engine.py` (وباقي الوثائق في `docs/`).

---

<a id="signing-pipeline"></a>

## طريقة التوقيع — مسار `sign()` ✍️

كل التوقيع المحلي يمر عبر **`ttk.signing_engine.sign()`**. فهم المدخلات والترتيب ضروري لأن أي اختلاف في **نفس الـ URL (query)** أو **نفس بايتات الجسم** أو **نفس الـ Cookie** أو **نفس الطابع الزمني `ts`** يغيّر الهيدرز.

### المدخلات

| المعامل | الدور |
|---------|--------|
| `url` | الرابط **كاملًا** بما فيه **query string** (`?aid=…&device_id=…`) — يُستخرج منه الجزء بعد `?` فقط للتوقيع. |
| `method` | `"GET"` أو `"POST"` (أو أخرى بحروف كبيرة). يؤثر على **`X-SS-STUB`**. |
| `body` | **`bytes` أو `str`** — يُحوَّل داخليًا إلى بايتات UTF-8 إن كان نصًا. يجب أن تطابق **بالضبط** ما يُرسل على السلك لحساب الـ STUB (انظر ملاحظة الـ gzip أدناه). |
| `cookie` | قيمة هيدر **`Cookie`** كسلسة واحدة (كما في الطلب الفعلي). |
| `ts` | وقت Unix (`int`). الافتراضي: `int(time.time())`. يُستخدم في **Gorgon** و**Ladon** و**Argus**. |

### ترتيب التنفيذ داخل `sign()` (ملخص)

1. **`ts`** ← الوقت الحالي إن لم يُمرَّر.
2. **`query_string`** ← `urlparse(url).query`.
3. **`body_bytes`** ← ترميز الجسم إلى بايتات.
4. **`X-SS-STUB`** ← إن وُجد جسم **و** الطريقة ليست `GET`: `MD5(body_bytes).hexdigest().upper()`؛ وإلا يُترك الهيدر غير مُضاف في القاموس.
5. **`compute_gorgon(query_string, stub, cookie, ts)`** ← يُرجع **`X-Gorgon`** و **`X-Khronos`** (الخronos هنا نص الرقم `str(ts)` كما في المخرجات).
6. **`compute_argus(query_string, stub, ts)`** ← يعتمد على **pycryptodome**؛ بدون المكتبة يعيد سلسلة فارغة.
7. **`compute_ladon(ts)`** ← يولّد **`X-Ladon`** (عشوائية 4 بايتات داخل المخرج في كل استدعاء ما لم تُثبَّت).
8. دمج القاموس النهائي: `X-Khronos`, `X-Gorgon`, `X-Ladon`, `X-Argus`، و`X-SS-STUB` عند وجود STUB.

```mermaid
flowchart LR
  subgraph inputs [مدخلات]
    U[url]
    M[method]
    B[body]
    C[cookie]
    T[ts]
  end
  subgraph sign_fn [sign]
    ST[compute_stub]
    GO[compute_gorgon]
    AR[compute_argus]
    LA[compute_ladon]
    OUT[dict الهيدرز]
  end
  U --> GO
  U --> AR
  B --> ST
  M --> ST
  ST --> GO
  ST --> AR
  C --> GO
  T --> GO
  T --> AR
  T --> LA
  GO --> OUT
  AR --> OUT
  LA --> OUT
  ST --> OUT
```

### كيف يُبنى `X-Gorgon` (فكرة الخوارزمية)

1. **`url_md5`** = MD5 لسلسلة **query فقط** (UTF-8)، أخذ أول 4 بايتات كأرقام.
2. **`stub`** = 4 بايتات من الـ hex الـ 32 حرفًا لـ `X-SS-STUB`، أو أصفار إن لم يكن هناك STUB.
3. **`cookie_md5`** = MD5 لسلسلة الـ Cookie كاملة، أول 4 بايتات؛ أو أصفار بدون Cookie.
4. **4 بايتات صفر** ثم **4 بايتات** من تمثيل hex لـ `ts` (8 hex أرقام).
5. الناتج **20 بايتًا** يُمرَّر عبر جدول تبديل يشبه **RC4 (KSA + PRGA)** ثم دالة **`_gorgon_handle`**: تبديل نصف بايتات (nibbles)، عكس بتات، XOR ثابت، إلخ.
6. البادئة: إصدار مثل **`8404`** + ثوابت مأخوذة من جدول الإصدار + **40 حرف hex** من الـ 20 بايت النهائية → طول شائع **52 حرفًا** لـ `8404…`.

> **ملاحظة:** مطابقة **بايت-ببايت** مع التطبيق قد تعتمد على مفاتيح/ثوابت داخل الثنائي؛ المحرك يحقق **الشكل والتبعيات** (query / stub / cookie / ts) كما في التحليل المرجعي.

### كيف يُبنى `X-Ladon`

1. نص واضح: **`{ts}-{license_id}-{aid}`** (افتراضيًا `license_id` و`aid` كما في `compute_ladon`).
2. **`rand`** = 4 بايتات عشوائية (`os.urandom`).
3. من **`rand + str(aid)`** يُشتق جدول مفاتيح عبر **MD5** ثم تشفير كتلي يعتمد على **SIMON-128** مع **PKCS7** على النص أعلاه.
4. المخرج: **`base64(rand ‖ ciphertext)`**.

### كيف يُبنى `X-Argus`

1. تفكيك **query** إلى حقول (`device_id`, `version_name`, `channel`, `os_version`, …).
2. **`body_hash`** = أول 6 بايت من **SM3** على بايتات الـ STUB (16 بايت من hex الـ STUB)، و**`query_hash`** من SM3 على سلسلة الـ query.
3. تجميع **حقول في هيكل Protobuf مخصص** (رقم الحقول كما في الكود) يشمل `channel` المطابق للـ query.
4. ترميز Protobuf → حشو PKCS7 → **تشفير SIMON** → طبقة **XOR + عكس** ثم بادئات ثابتة.
5. **AES-CBC** بمفتاح و IV مشتقّان من **`MD5`** على أجزاء من **`_ARGUS_SIGN_KEY`**.
6. المخرج: **Base64** مع بادئة بايتية داخل الترميز (`\xf2\x81` + نص مشفّر) كما في التطبيق.

### `X-SS-STUB` والجسم المضغوط (gzip)

- في **`sign()`** الافتراضي: الـ STUB = **MD5 لبايتات الجسم كما تمرّرها** (عادة **JSON أو form غير مضغوط**).
- في مسارات **`device_register`** الواقعية، قد يُرسل الجسم **مضغوطًا gzip** على السلك؛ فرع **`java_gzip_sig`** في الكود يوضح أن الـ STUB قد يُحسب من **MD5 بايتات الـ gzip** وليس النص الظاهر فقط. عند محاكاة ذلك يجب تمرير **`body`** إلى `sign()` بنفس البايتات التي تُحسب عليها الـ MD5 في الخادم/التطبيق.

### بديل: التوقيع عبر RapidAPI

إن اخترت **`--sign-backend rapidapi`** في `login_client`، فإن **`X-Gorgon` / `X-Ladon` / `X-Argus` / `X-Khronos`** تُجلب من خدمة خارجية، بينما **`X-SS-STUB`** يُحسب محليًا (`compute_stub`) عند وجود جسم. راجع `ttk/rapidapi_signer.py` ومتغير **`RAPIDAPI_KEY`**.

### المرجع في الكود

- الواجهة الموحدة: **`sign()`** ≈ السطور 559–603 في `ttk/signing_engine.py`.
- دوال منفصلة للاختبار: **`compute_stub`**, **`compute_gorgon`**, **`compute_ladon`**, **`compute_argus`**.

---

<a id="signing-extended-walkthrough"></a>

### شرح موسّع تقني (خطوة بخطوة)

ما يلي يطابق تنفيذ **`ttk/signing_engine.py`**: مكتبة قياسية فقط، مع **`pycryptodome`** لـ **AES-CBC** داخل Argus فقط.

#### البنى التشفيرية في الملف

| البنية | الدور |
|--------|--------|
| **MD5** | سلاسل query/cookie (UTF-8)؛ بايتات جسم الـ STUB؛ مادة مفتاح/IV لـ Argus (`MD5` على أجزاء `_ARGUS_SIGN_KEY`). |
| **SM3** (معيار صيني GB/T 32905-2016) | تنفيذ بايثون `_SM3`؛ `body_hash` / `query_hash` في Argus (أول 6 بايتات لكلٍ منهما)؛ `_ARGUS_SM3_OUTPUT` لتغذية مفاتيح SIMON في Argus. |
| **SIMON-128/128** | 72 جولة (`simon_enc`)؛ تشفير كتل protobuf في Argus؛ مسار Ladon يستخدم جدول جولات مخصصًا لكل كتلة 16 بايت. |
| **AES-128-CBC** | غلاف Argus النهائي (`Crypto.Cipher.AES`). |
| **Protobuf مبسّط** | `_ProtoBuf`: `int` → varint، `str`/`bytes` → حقل بطول، `dict` → رسالة فرعية. |
| **PKCS#7** | حشو لمضاعفات 16 بايت قبل SIMON/AES. |

#### `X-SS-STUB` — خطوات مرقّمة

1. داخل **`sign()`**: إذا **`method.upper() == "GET"`** أو **الجسم فارغ** → **لا** تُضاف مفتاح **`X-SS-STUB`** في القاموس المُرجَع.
2. تطبيع **`body`**: `str` → ترميز **`utf-8`**؛ `bytes` كما هي.
3. **`stub_lower = MD5(body_bytes).hexdigest()`** (32 حرف hex بأحرف صغيرة من hashlib).
4. الهيدر: **`X-SS-STUB = stub_lower.upper()`** (32 حرف **hex كبير**).
5. **الاستخدام اللاحق:** **`compute_gorgon`** يأخذ ذلك السلسلة **الكبيرة** ويقرأ **أول 8 أزواج hex** كبايتات **4–7** من حالة Gorgon. **`compute_argus`** يحوّل الـ stub بـ **`bytes.fromhex(stub)`** إن وُجد؛ وإلا **16 بايت صفر** لمدخل SM3.

#### `X-Khronos`

- **`X-Khronos = str(ts)`** — نفس الطابع **`ts`** المُضمَّن في بايتات **16–19** لحالة Gorgon.
- عند إعادة التقاط، ثبّت **`ts`** في **`sign(..., ts=)`** ليتطابق مع **`X-Khronos`** في اللقطة.

#### `X-Gorgon` — خطوات مرقّمة

1. اختر إصدار Gorgon (افتراضي **`8404`**). جدول **`_GORGON_HEX_STR`** يعطي 8 أعدادًا تُخلط في KSA؛ **`8404`** → أصفار؛ **`0404`** → ثوابت قديمة غير صفرية.
2. **`khronos_hex = hex(ts)[2:].zfill(8)`** — **8** أرقام hex بالضبط.
3. **`MD5(query_string UTF-8).hexdigest()`** — خذ **أول 8 أحرف hex** → **4 بايتات** → مواضع **0–3**.
4. **4–7:** من **`X-SS-STUB`** (أول 8 أحرف hex من الـ stub الكبير) أو أصفار.
5. **8–11:** أول 4 بايت من **`MD5(cookie UTF-8)`** أو أصفار.
6. **12–15:** **أربعة أصفار** ثابتة.
7. **16–19:** من **8** أرقام hex لـ **`khronos_hex`** (زوجان hex لكل بايت).
8. **`_gorgon_ksa(hex_str)`** → جدول تبديل 256 بايت (KSA يشبه RC4؛ حالة خاصة عند القيمة **85**).
9. **`_gorgon_prga`**: 20 تكرارًا، كل واحد يحدّث `inp[i]` بـ XOR مستمد من الجدول.
10. **`_gorgon_handle`**: لكل `i`: تبديل نصفيّة البايت (nibbles)؛ XOR مع البايت **التالي** (دوري 20)؛ **عكس بتات** الناتج؛ XOR **20**؛ **`~`** ثم قناع **`0xFF`**.
11. **`sig`**: الـ **20** بايت النهائية كـ **40** حرف hex **صغير**.
12. السلسلة النهائية: **`version`** + أربعة أوكتات hex من فهارس ثابتة في **`hex_str`** (`[7],[3],[1],[6]` كـ `02x`) + **`sig`**. مع **`8404`** والجدول صفري غالبًا **`840400000000` + 40 حرفًا** ≈ **52** حرفًا.

#### `X-Ladon` — خطوات مرقّمة

1. **`ts`**, **`license_id`** (افتراضي **1611921764**), **`aid`** (افتراضي **1233**).
2. نص UTF-8: **`"{ts}-{license_id}-{aid}"`**.
3. **`rand = os.urandom(4)`** ما لم تُمرَّر **`rand=`** إلى **`compute_ladon`** (استدعاء **`sign()`** العادي لا يثبّتها → كل مرة مختلفة).
4. **`keygen = rand ‖ str(aid)`** (بايتات).
5. **`md5hex = MD5(keygen).hexdigest()`** كسلسلة ASCII (32 حرفًا).
6. PKCS7 على النص حتى مضاعف **16**.
7. **`_ladon_keyschedule`**: يوسّع `md5hex` إلى جدول مفاتيح (حلقة خارجية **`0x22`**).
8. لكل **كتلة 16 بايت**: **`0x22`** جولة Feistel على نصفي 64 بت ( endian صغير) كما في **`_ladon_encrypt_data`**.
9. **`base64(rand ‖ ciphertext)`** → **`X-Ladon`**.

#### `X-Argus` — خطوات مرقّمة

**بدون pycryptodome → سلسلة فارغة.**

1. **`parse_qs`** على query؛ **`_qp`** يأخذ **أول** قيمة لكل مفتاح.
2. **`channel`** من الاستعلام أو افتراضي **`googleplay`** — يجب أن يطابق التطبيق.
3. **`stub_bytes`**: **`fromhex(stub)`** أو **16 بايت صفر**.
4. **`body_hash = SM3(stub_bytes)[:6]`**.
5. **`query_hash = SM3(query_string.encode() if query_string else bytes(16))[:6]`**.
6. املأ **`bean`**: الحقول **1,2,3,4,5,6,7,8,9,10,11,12,13,14,20,23** واختياري **16** — منها **12:** `ts << 1`، **13/14:** 6 بايتات، **23:** فرعي فيه `device_type`, `os_version`, `channel`, **`_argus_calculate_constant(os_version)`** (جمع مرجّح لأرقام من `os_version`).
7. **`_ProtoBuf(bean).to_bytes()`** → PKCS7 → تشفير **SIMON** لكل 16 بايت بمفتاح من **`_ARGUS_SM3_OUTPUT[:32]`**.
8. **`_argus_xor_reverse`**: بادئة 8 بايت `\xf2\xf7…`، XOR للبايتات من الموضع 8، **عكس** المصفوفة كلها.
9. إحاطة: **`b"\xa6n\xad\x9fw\x01\xd0\x0c\x18" + … + b"ao"`**.
10. PKCS7 مرة أخرى، ثم **AES-CBC**: **`MD5(_ARGUS_SIGN_KEY[:16])`** و **`MD5(_ARGUS_SIGN_KEY[16:])`** كمفتاح و IV.
11. **`Base64(b"\xf2\x81" + ciphertext)`**.

#### مصفوفة الارتباط (ما يشترك مع ما)

| الهيدر | query | جسم/STUB | cookie | `ts` | عشوائية |
|--------|-------|----------|--------|------|---------|
| `X-SS-STUB` | — | نعم | — | — | — |
| `X-Khronos` | — | — | — | نعم | — |
| `X-Gorgon` | نعم | نعم | نعم | نعم | — |
| `X-Ladon` | — | — | — | نعم | نعم (4 بايت) |
| `X-Argus` | نعم | نعم | — | نعم | نعم (حقل 3) |

#### قائمة تحقق لمطابقة الالتقاط

1. نفس **query** حرفًا بحرف (ترميز، **`channel`**, `version_name`, `device_id`, …).
2. نفس سلسلة **`Cookie`** كاملة لـ Gorgon.
3. نفس **بايتات الجسم** التي يحسب عليها التطبيق الـ STUB (انتبه لـ **gzip**).
4. **`ts`** مطابق لـ **`X-Khronos`** في اللقطة عند المقارنة الصارمة.
5. حقول Argus الافتراضية (`sdk_version`, `sdk_version_int`, …) مطابقة لبروفايل الجهاز.
6. **Ladon** يتغيّر بين التشغيلات ما لم تُثبَّت `rand` في الكود.

#### تحقق محلي

- **`python3 -m ttk.signing_engine --url '...' --body '...' --cookie '...' --ts …`**
- **`python3 tests/test_all.py`** — اختبارات STUB/Khronos وشكل Gorgon/Argus.

#### حقل protobuf **23** في Argus — رسالة متداخلة (مخطط بايتات)

في **`compute_argus`**، **`bean[23]`** قاموس **متداخل**. المُرمّز **`_ProtoBuf`** في **`signing_engine.py`** يعامل أي قيمة **`dict`** كـ **رسالة فرعية بطول** (نفس فكرة protobuf **wire type 2** في هذا المُرمّز): الحقل **23** في الأب، وحقله هو **`_ProtoBuf(الداخل).to_bytes()`**.

الحقول الداخلية (منطقيًا):

| رقم الحقل الداخلي | مصدر القيمة في بايثون | نوع السلك في `_ProtoBuf` |
|-------------------|------------------------|---------------------------|
| **1** | `_qp("device_type")` | **string** → وسوم `(1<<3)|2`، طول varint، بايتات UTF-8 |
| **2** | `_qp("os_version")` | **string** → `(2<<3)|2`، طول، UTF-8 |
| **3** | `channel` (من الاستعلام أو `"googleplay"`) | **string** → `(3<<3)|2`، طول، UTF-8 |
| **4** | `_argus_calculate_constant(os_version)` **int** | **varint** → `(4<<3)|0`، جسم varint |

مخطط تداخل مفاهيمي:

```text
[حقول الرسالة الجذر 1،2،…،22،23،…]
        │
        └── الحقل 23 (بطول محدد) ──► بايتات متداخلة:
                ├── الحقل 1  (بطول)  device_type   مثال: sdk_gphone64_arm64
                ├── الحقل 2  (بطول)  os_version    مثال: "16"
                ├── الحقل 3  (بطول)  channel       مثال: samsung_store
                └── الحقل 4  (varint) f(os_version) مثال: 32768 لـ "16" مع الأوزان الافتراضية
```

**`_argus_calculate_constant`:** يأخذ سلسلة **`os_version`**، يبقي الأرقام فقط، **يصفّ إلى 6 أرقام**، يضرب كل رقم في **`[20480, 2048, 20971520, 2097152, 1342177280, 134217728]`** ويجمع — يُستخدم فقط داخل **23.4**.

**استعلام فارغ:** `query_hash = SM3(bytes(16))[:6]` — أي **SM3 على 16 بايت صفر** وليس مدخلًا فارغًا. أول **6 بايتات** من الملخص (hex): **`106E34A2B8C7`**.

#### قيم hex مرجعية من `tests/test_all.py` (**CAP_2913**، **CAP_2820**)

الثوابت في بداية **`tests/test_all.py`**. تُستخدم لإعادة إنتاج **STUB** و**Khronos** وشرائح **SM3** لـ Argus.

**`CAP_2913`** — POST `/passport/user/login/` (التقاط **[2913]**)

| العنصر | القيمة (مختصرة أو كاملة) |
|--------|---------------------------|
| **`X-SS-STUB`** | `2334A127910BFD04C800293D423DEFA7` |
| **`X-Khronos`** (مع `ts=1773712689`) | `1773712689` |
| **`ts` الممرَّر إلى `sign()`** | `1773712689` |
| **`X-Gorgon` الملتقط (مرجع فقط)** | `8404c01c000098c0cd010cdc36e96ebb4a7782bd8189fcda33c8` — الاختبارات تذكر أن المطابقة **الكاملة** غير متوقعة مع المحرك المفتوح (مادة مفتاح داخل التطبيق)؛ الشكل **52** حرفًا، بادئة **`8404`**. |
| **أول 6 بايت من `SM3(stub_bytes)`** (`stub_bytes` = 16 بايت من hex الـ STUB) | **`0AD0A7F0A1F7`** |
| **أول 6 بايت من `SM3(query_utf8)`** لسلسلة استعلام CAP_2913 | **`414D4CED13BA`** |

**`CAP_2820`** — جسم POST `pre_check` (التقاط **[2820]**)

| العنصر | القيمة |
|--------|--------|
| **بداية الجسم** | `account_sdk_source=app&multi_login=1&mix_mode=1&username=76716a7760627637` |
| **`X-SS-STUB`** | `AFAB3892DC07AA8D95D49D68B9FF63CA` |

**`CAP_2817`** — GET `check_login_name_registered`: **لا** جسم → **لا** `X-SS-STUB` في مخرجات `sign()`؛ خانة STUB في Gorgon **أصفار**.

**مثال — إعادة التحقق من STUB و Khronos**

```python
from ttk.signing_engine import sign, compute_stub
from tests.test_all import CAP_2913

assert compute_stub(CAP_2913["body"].encode()) == CAP_2913["X-SS-STUB"]
sig = sign(
    url=CAP_2913["url"],
    method="POST",
    body=CAP_2913["body"],
    cookie=CAP_2913["cookie"],
    ts=CAP_2913["ts"],
)
assert sig["X-Khronos"] == CAP_2913["X-Khronos"]
assert sig["X-SS-STUB"] == CAP_2913["X-SS-STUB"]
```

---

## معرّفات الجهاز 📱

| الحقل | شكل تقريبي | توليد مرجعي في المشروع |
|--------|------------|-------------------------|
| `device_id` | رقم طويل (~19 رقمًا) | عشوائي آمن عند التسجيل |
| `iid` (install_id) | مماثل | عشوائي آمن |
| `openudid` | hex 16 حرفًا | عشوائي |
| `cdid` | UUID | عشوائي |

المرجع في الكود مستمد من JADX مثل `DeviceRegisterManager` وملفات مشابهة (انظر تعليقات `device_register.py`).

---

## تدفق اللوجن (مبسّط) 🚪

```
Client                              خوادم TikTok
  │                                       │
  │──[1] GET check_login_name ───────────▶ aggr16-normal.tiktokv.us
  │◀──────── is_registered / … ───────────│
  │                                       │
  │──[2] POST login/pre_check ───────────▶ api16-normal-c-alisg.tiktokv.com
  │◀──────── error_code: 0 … ───────────│
  │                                       │
  │──[3] POST login ─────────────────────▶ api16-normal-c-alisg.tiktokv.com
  │◀──────── session_key, uid, … ───────│
```

التدفق **الكامل** في التطبيق أطول (منطقة، كابتشا، تحقق، …) — راجع **[docs/LOGIN_FLOW.md](docs/LOGIN_FLOW.md)** و **[docs/LOGIN_FLOW_V44_3_15.md](docs/LOGIN_FLOW_V44_3_15.md)**.

---

## رموز الأخطاء الشائعة ⚠️

| `error_code` | المعنى تقريبًا | ماذا تفعل |
|--------------|----------------|-----------|
| `0` | نجاح | — |
| `7` | حد معدل / تقييد | جهاز/بروكسي/توقيت آخر |
| `1105` | كابتشا | حل الكابتشا أو اتباع مسار التطبيق |
| `2046` | كلمة مرور خاطئة | تحقق من الترميز والحساب |
| `2048` | حساب غير موجود | تحقق من اسم المستخدم |

---

## الاختبارات 🧪

من جذر `tiktok_final/`:

```bash
python3 tests/test_all.py
```

- تغطي التوقيع، اللوجن، تسجيل الجهاز، المخطط JSON، وغيرها.
- إن وُجد **`login_sessions.json`** في الجذر، تُشغَّل اختبارات إضافية؛ وإلا تُتخطى تلقائيًا (مناسب للمستودع العام).

---

## مجلد `tools/` 🛠️

| أداة | وظيفة |
|------|--------|
| `frida_controller.py` + `frida_hook_tiktok.js` | اعتراض/تسجيل من الجهاز عبر Frida. |
| `jadx_analyzer.py` | مسح مخرجات JADX ومقارنة ثوابت مع `ttk/signing_engine.py`. |
| `ghidra_analyze.py` | تحليل ثنائي (يتطلب بيئة Ghidra/pyghidra). |
| `apk_sig_hash.py` | تجزئة توقيع APK. |
| `android_sig_bruteforce.py` / `prepare_bruteforce.py` | أدوات بحث/تحضير متعلقة بالتوقيع. |
| `compare_device_register_dump.py` | مقارنة ملفات golden / dumps. |

تشغيل معظمها من داخل **`tools/`** أو بمسارات صريحة كما في docstring كل ملف.

---

## الوثائق في `docs/` 📚

| الملف | المحتوى |
|-------|---------|
| [LOGIN_FLOW.md](docs/LOGIN_FLOW.md) | معاملات وتفاصيل تدفق اللوجن. |
| [LOGIN_FLOW_V44_3_15.md](docs/LOGIN_FLOW_V44_3_15.md) | ملاحظات إصدار 44.3.15 وMITM. |
| [ANALYSIS_REPORT.md](docs/ANALYSIS_REPORT.md) | تقرير تحليل. |
| [implementation_plan.md](docs/implementation_plan.md) | خطة تنفيذ (سياق تاريخي). |
| [plan_tiktok_signer.md](docs/plan_tiktok_signer.md) | خطة موحّد التوقيع (سياق تاريخي). |

---

## الملفات الحساسة و`.gitignore` 🔒

لا ترفع إلى Git:

- جلسات حقيقية، بروكسيات، مفاتيح، مخرجات اعتراض كاملة.
- ملفات مثل `login_sessions.json`, `proxsy.txt`, `golden_out/` (حسب إعدادات المشروع)، أجهزة MITM/محلية، إلخ.

راجع **`.gitignore`** للقائمة الحالية.

---

<a id="related-project-tiktokdevicegenerator"></a>

## مشروع مرتبط: TikTokDeviceGenerator 🔗

**[github.com/code-root/TikTokDeviceGenerator](https://github.com/code-root/TikTokDeviceGenerator)** — أداة تركّز على **إنشاء وتسجيل أجهزة** (واحد أو دفعات):

| | |
|--|--|
| **ما هي** | تطبيق سطح مكتب **Tkinter**؛ يبني حمولات التسجيل عبر **Java** و**unidbg** (محاكاة أصلية)، يرسل **POST** إلى نقطة **`device_register`** لدى TikTok (`log-va.tiktokv.com/service/2/device_register/`)، ويحفظ **`device_id` / IID** وبيانات وصفية بصيغة **JSON**. |
| **ميزات** | وضع **دفعة (batch)** مع **threads**، بروكسي **HTTP/SOCKS** اختياري، مخرجات مجزأة تحت `Device/` وملخصات تحت `generated_devices/`. |
| **التوثيق** | [README.md](https://github.com/code-root/TikTokDeviceGenerator/blob/main/README.md) (إنجليزي) و [README.ar.md](https://github.com/code-root/TikTokDeviceGenerator/blob/main/README.ar.md) (عربي). |
| **الترخيص** | MIT (راجع المستودع الأصلي). |

مشروع **tiktok_final** هنا مرتكز على **التوقيع بايثون (`ttk/signing_engine`)** و**`login_client`** ومسار **`device_register`** الموثّق. **TikTokDeviceGenerator** خيار عملي عندما تريد **GUI + unidbg** لتوليد أجهزة بالجملة؛ يمكن دمج مخرجات JSON مع **`login_client --device …`** هنا إذا تطابقت الحقول (راجع التوافق قبل الاستخدام الجاد).

> استخدم أي أداة خارجية وفق القوانين وشروط خدمة TikTok.

---

## مراجع تقنية 📖

- [Hex-Rays FLIRT user guide](https://docs.hex-rays.com/user-guide/signatures/flirt) — توقيعات مكتبات في IDA/Ghidra البيئات.

---

<a id="maintainer-company--contact"></a>

## المطوّر والشركة والتواصل 👤

| | |
|---|---|
| **المطوّر** | مصطفى الباجوري (Mostafa Al-Bagouri) |
| **الشركة** | **[Storage TE](http://storage-te.com/)** |
| **واتساب** | [+20 100 199 5914](https://wa.me/201001995914) |

---

<a id="support-this-project"></a>

## دعم المشروع ☕

إذا كانت هذه الأدوات مفيدة لك، يمكنك دعم الصيانة والتطوير اختياريًا. اختر الطريقة الأنسب لك.

| القناة | كيفية الدعم |
|--------|-------------|
| **PayPal** | [paypal.me/sofaapi](https://paypal.me/sofaapi) |
| **Binance Pay / المعرف** | **1138751298** — الإرسال من تطبيق Binance (Pay / تحويل داخلي عند توفره). |
| **إيداع عبر الويب (Binance)** | [إيداع عملات (Binance)](https://www.binance.com/en/my/wallet/account/main/deposit/crypto) — سجّل الدخول، اختر الأصل، ثم **BSC (BEP20)**. |
| **عنوان BSC (للنسخ)** | `0x94c5005229784d9b7df4e7a7a0c3b25a08fd57bc` |

> **الشبكة:** استخدم **BSC (BEP-20)** فقط. هذا العنوان لـ **USDT (BEP-20)** و**BTC على BSC** (Binance-Peg / «BTC» على BSC في التطبيق). **لا** ترسل **بتكوين أصلي على السلسلة**، أو **ERC-20**، أو **NFTs** إلى هذا العنوان.

### رموز الإيداع QR (امسحها من Binance أو أي محفظة BSC)

| USDT · BSC | BTC · BSC |
|------------|-----------|
| ![رمز إيداع USDT — BSC](assets/deposit-usdt-bsc.png) | ![رمز إيداع BTC على BSC](assets/deposit-btc-bsc.png) |

---

**النسخة الإنجليزية (الافتراضية على GitHub):** [README.md](README.md)

**إخلاء مسؤولية:** للتعليم والبحث؛ احترم شروط خدمة TikTok والقوانين المعمول بها.
