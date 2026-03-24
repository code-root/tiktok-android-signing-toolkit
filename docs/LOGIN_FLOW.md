# TikTok v44.3.1 — Login Flow Analysis

Source: 100% extracted from real Android device captures (`Raw_03-17-2026-03-58-36.folder`)
App: `com.zhiliaoapp.musically` v44.3.1 (440301) · Android 16 · sdk_gphone64_arm64

---

## Login Sequence Diagram

```
Client                              TikTok Servers
  │                                       │
  │──[Step 1] GET check_login_name_registered──▶ aggr16-normal.tiktokv.us
  │◀──────────────── {is_registered: true} ──────
  │                                       │
  │──[Step 2] POST login/pre_check ───────▶ api16-normal-c-alisg.tiktokv.com
  │◀──────────────── {error_code: 0 / ok} ───────
  │                                       │
  │──[Step 3] POST login ─────────────────▶ api16-normal-c-alisg.tiktokv.com
  │◀──────────────── {session_key / error} ───────
```

---

## Endpoints

| # | Method | Host | Path |
|---|--------|------|------|
| 1 | GET  | `aggr16-normal.tiktokv.us` | `/passport/user/check_login_name_registered/` |
| 2 | POST | `api16-normal-c-alisg.tiktokv.com` | `/passport/user/login/pre_check/` |
| 3 | POST | `api16-normal-c-alisg.tiktokv.com` | `/passport/user/login/` |

---

## Step 1 — Check Username

**Purpose:** Verify the username exists before attempting login.

### Request

```
GET https://aggr16-normal.tiktokv.us/passport/user/check_login_name_registered/
    ?login_name=<USERNAME>
    &scene=3
    &multi_login=1
    &account_sdk_source=app
    &<common_params>
```

### Step 1 Query Params (extra, prepended before common params)

| Parameter | Value | Notes |
|---|---|---|
| `login_name` | `storegs2` | Username to check |
| `scene` | `3` | Login scene (always 3) |
| `multi_login` | `1` | Multi-account mode |
| `account_sdk_source` | `app` | SDK source |

### Signing Headers (from capture [2817])

| Header | Captured Value |
|---|---|
| `X-Gorgon` | `840430db0000ceba7aedd264e005d8aac3fde79c464584211255` |
| `X-Khronos` | `1773712636` |
| `X-Argus` | `thIghzp753q+PUxAoEukdSxP1S70MZf7...` |
| `X-Ladon` | `Uj9eLsN9QaCTo2SXMqdAUlBHBLXGGO1JFVXHw/9Z6DrW3quC` |

> No `X-SS-STUB` on GET requests.

### Response

```json
{
  "data": {
    "is_registered": true
  },
  "message": "success"
}
```

---

## Step 2 — Pre-Check

**Purpose:** Pre-login validation, captcha check, rate limit check.

### Request

```
POST https://api16-normal-c-alisg.tiktokv.com/passport/user/login/pre_check/
     ?<common_params>

Body (URL-encoded):
  account_sdk_source=app&multi_login=1&mix_mode=1&username=<USERNAME>
```

### Body Parameters

| Parameter | Value | Notes |
|---|---|---|
| `account_sdk_source` | `app` | Always "app" |
| `multi_login` | `1` | Multi-account mode |
| `mix_mode` | `1` | Mixed login mode |
| `username` | `76716a7760627637` | Hex-encoded username |

### Signing Headers (from capture [2820])

| Header | Captured Value |
|---|---|
| `X-Gorgon` | `8404e0d10000288a2e88cd22ebccccacdbe28c0a29c251c1b2a8` |
| `X-Khronos` | `1773712637` |
| `X-Argus` | `+OrXx286nZJhFL99oYWQCM3...` |
| `X-Ladon` | `oRBlTUg54m+2U3dBtSmAGodESyeo+maayMBdGBxUWpTkZOAX` |
| `X-SS-STUB` | `AFAB3892DC07AA8D95D49D68B9FF63CA` |

### Response (success)

```json
{
  "data": {
    "error_code": 0,
    "verify_ticket": ""
  },
  "message": "success"
}
```

---

## Step 3 — Login

**Purpose:** Actual authentication with username + password.

### Request

```
POST https://api16-normal-c-alisg.tiktokv.com/passport/user/login/
     ?<common_params>

Body (URL-encoded):
  password=<PASSWORD_HEX>&account_sdk_source=app&multi_login=1&mix_mode=1&username=<USERNAME>
```

### Body Parameters

| Parameter | Value | Notes |
|---|---|---|
| `password` | `4576716a776462602b60622b3437363123` | Password in TikTok hex encoding |
| `account_sdk_source` | `app` | Always "app" |
| `multi_login` | `1` | Multi-account mode |
| `mix_mode` | `1` | Mixed login mode |
| `username` | `76716a7760627637` | Hex-encoded username |

### Password Encoding

TikTok encodes passwords: `hex(ord(char) ^ 0x17)` per character.

```python
def encode_password(plain: str) -> str:
    return "".join(f"{ord(c) ^ 0x17:02x}" for c in plain)

# Example:
encode_password("MyPassword123") → "5a4b617..."
```

### Signing Headers (from capture [2913])

| Header | Captured Value |
|---|---|
| `X-Gorgon` | `8404c01c000098c0cd010cdc36e96ebb4a7782bd8189fcda33c8` |
| `X-Khronos` | `1773712689` |
| `X-Argus` | `A3WFd0xLIN1q6H57YRjbCOBpbn/qv9dBSDLKf...` |
| `X-Ladon` | `gD4DceQsc43OVDGml9n2Gp9atCHmjwbiPP0yKjNio8ArXgSG` |
| `X-SS-STUB` | `2334A127910BFD04C800293D423DEFA7` |

### X-SS-STUB Verification

```
Body = "password=4576716a776462602b60622b3437363123&account_sdk_source=app&multi_login=1&mix_mode=1&username=76716a7760627637"
MD5(Body).upper() = 2334A127910BFD04C800293D423DEFA7  ✅ verified
```

### Response (success)

```json
{
  "data": {
    "session_key": "...",
    "uid": "...",
    "username": "...",
    "sec_uid": "..."
  },
  "message": "success"
}
```

### Response (error)

```json
{
  "data": {
    "captcha": "",
    "description": "Maximum number of attempts reached. Try again later.",
    "error_code": 7
  },
  "message": "error"
}
```

---

## Common Query Parameters

Every request includes these parameters (from device profile):

| Parameter | Captured Value | Notes |
|---|---|---|
| `passport-sdk-version` | `1` | SDK version |
| `device_platform` | `android` | Platform |
| `os` | `android` | OS |
| `ssmix` | `a` | Mixing flag |
| `_rticket` | `1773712679767` | `ts * 1000 + random` |
| `cdid` | `addc1d0d-46c6-4468-b012-f887859e6328` | Device UUID |
| `channel` | `samsung_store` | Distribution channel |
| `aid` | `1233` | App ID |
| `app_name` | `musical_ly` | App name |
| `version_code` | `440301` | v44.3.1 |
| `version_name` | `44.3.1` | Version string |
| `manifest_version_code` | `2024403010` | |
| `resolution` | `1440*3120` | Screen resolution |
| `dpi` | `560` | Screen DPI |
| `device_type` | `sdk_gphone64_arm64` | Device model |
| `device_brand` | `google` | |
| `language` | `en` | |
| `os_api` | `36` | Android API level |
| `os_version` | `16` | Android 16 |
| `ac` | `mobile` | Connection type |
| `ac2` | `5g` | Network subtype |
| `is_pad` | `0` | Not tablet |
| `app_type` | `normal` | |
| `sys_region` | `US` | |
| `mcc_mnc` | `310260` | T-Mobile US |
| `timezone_name` | `Africa%2FCairo` | URL-encoded |
| `timezone_offset` | `7200` | +2:00 UTC |
| `carrier_region` | `US` | |
| `carrier_region_v2` | `310` | |
| `app_language` | `en` | |
| `locale` | `en` | |
| `host_abi` | `arm64-v8a` | CPU arch |
| `uoo` | `0` | |
| `op_region` | `US` | |
| `build_number` | `44.3.1` | |
| `ts` | `1773712679` | Unix timestamp |
| `iid` | `7617618076322989837` | Install ID |
| `device_id` | `7617232110762329614` | Device ID |
| `openudid` | `412e52917b4dfe42` | Open UDID |
| `support_webview` | `1` | |

---

## Guard Headers

All login requests include these device guard headers:

| Header | Value |
|---|---|
| `tt-ticket-guard-public-key` | `BCIPe+RoQfU8nwKpNozVwA43QdZpY...` |
| `sdk-version` | `2` |
| `tt-ticket-guard-iteration-version` | `0` |
| `tt-ticket-guard-version` | `3` |
| `passport-sdk-settings` | `x-tt-token` |
| `passport-sdk-sign` | `x-tt-token` |
| `passport-sdk-version` | `1` |
| `x-tt-bypass-dp` | `1` |
| `x-vc-bdturing-sdk-version` | `2.4.1.i18n` |
| `tt-device-guard-iteration-version` | `1` |
| `tt-device-guard-client-data` | `eyJkZXZpY2VfdG9rZW4iOiIx...` (base64 device token) |

### tt-device-guard-client-data Decoded

```json
{
  "device_token": "1|{\"aid\":1233,\"av\":\"44.3.1\",\"did\":\"7617232110762329614\",\"iid\":\"7617618076322989837\",\"fit\":\"1773525157\",\"s\":1,\"idc\":\"useast5\",\"ts\":\"1773712616\"}",
  "timestamp": 1773712680,
  "req_content": "device_token,path,timestamp",
  "dtoken_sign": "ts.1.MEUCIAUtJCG32unlUKb5i/kropMmhGjPEm7ghUxxkaWZVTUWAiEAvpP/bz7SEmwbRH1KptlHMeMCK8E4R+afj2N85LgCygY=",
  "dreq_sign": "MEUCIQCChj9VeyZyHY9DVpc2k/pFH69RY6eS5v0opT4q5HmvTdgIgeX/XalpQjXwH//xtzkEm5wRc2nfty/p1P+h91H1ME+I18="
}
```

---

## Signing Headers — How They're Generated

| Header | Algorithm | Input |
|---|---|---|
| `X-SS-STUB` | `MD5(body).upper()` | Raw body bytes (before gzip) |
| `X-Khronos` | `str(int(time.time()))` | Current Unix timestamp |
| `X-Gorgon` | RC4-like KSA + PRGA + nibble-swap | MD5(url_params) + STUB + MD5(cookie) + timestamp |
| `X-Ladon` | SIMON-128/128 ECB + PKCS7 | `{ts}-{license_id}-{aid}` encrypted |
| `X-Argus` | Protobuf + SIMON-128 + AES-CBC | Device params + hashes + timestamp |

All generated locally via `signing_engine.py` — no external service needed.

---

## Error Codes

| error_code | Meaning | Action |
|---|---|---|
| `0` | Success | Proceed |
| `7` | Rate limited (max attempts) | Wait / change device |
| `1105` | Captcha required | Solve captcha |
| `2046` | Wrong password | Check credentials |
| `2048` | Account not found | Check username |
| `1000` | Server error | Retry |

---

## Quick Start

```python
from login_client import TikTokLoginClient, encode_password

client = TikTokLoginClient(verbose=True)

# Full flow
result = client.login(
    username="myusername",
    password_hex=encode_password("MyPassword123"),
)

# Or step by step
r1 = client.step1_check_username("myusername")
r2 = client.step2_pre_check("myusername")
r3 = client.step3_login("myusername", encode_password("MyPassword123"))
```

```bash
# CLI
python3 login_client.py --username myuser --step1
python3 login_client.py --username myuser --password "MyPass123"
python3 login_client.py --username myuser --password-hex 4576716a... --verbose
```
