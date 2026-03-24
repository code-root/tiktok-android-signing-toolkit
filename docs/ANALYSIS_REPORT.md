# TikTok v44.3.1 Security Analysis Report
**Date:** 2026-03-23
**Target:** Android emulator (sdk_gphone64_arm64, Android 16 API 36)
**Device ID:** 7617232110762329614

---

## Step 1: HTTP/2 Header Capture (COMPLETED ✓)

### Method
- Blocked QUIC (UDP 443) via `iptables -A OUTPUT -p udp --dport 443 -j DROP`
- Forced HTTP/2 over TLS fallback
- Hooked `SSL_write`/`SSL_read` in `libttboringssl.so`
- Decoded HTTP/2 HPACK headers using Python `hpack` library
- Spawned TikTok with Frida for clean HPACK decoder state

### Results
Captured **complete header set** for 129+ API requests including:
- `POST /aweme/v2/feed/` (feed API)
- `GET /get_domains/v5/` (domain resolution)
- `GET /webcast/user/` (user API)
- `GET /tfe/api/request_combine/v1/` (combined requests)
- `POST /service/2/app_log/` (telemetry)

### Key Headers Discovered
| Header | Value | Purpose |
|--------|-------|---------|
| `x-common-params-v2` | URL-encoded device params | All device info in single header |
| `x-tt-dm-status` | `login=0;ct=1;rt=6` | Device mode status |
| `x-tt-ttnet-origin-host` | `api16-core-useast5.tiktokv.us` | Real origin host |
| `x-ss-dp` | `1233` | App ID (data plan) |
| `x-bd-content-encoding` | `gzip` | Body encoding |
| `oec-cs-sdk-version` | `v10.02.02.01-bugfix-ov-android_V31` | OEC SDK version |
| `x-vc-bdturing-sdk-version` | `2.4.1.i18n` | Turing SDK version |
| `sdk-version` / `passport-sdk-version` | `2` / `1` | SDK versions |
| `rpc-persist-pns-region-*` | `US\|6252001` | GeoIP persist headers |

### New Cookies
- `ttreq=1$068d5dd613c0729d309868b811116c830477d20b` (device token hash)
- `tt-target-idc=useast5` (target IDC)
- `msToken=OX6JjNJ0s1Fu-3_NcVY6P2L...` (session token)

### Feed API: **WORKING** (HTTP 200, 12 videos per request)

---

## Step 2: Metasec/Ghidra Analysis (COMPLETED ✓)

### libmetasec_ov.so (1.9MB) - ByteDance Pitaya MSSDK

**Architecture:**
- Only export: `JNI_OnLoad` (all other methods registered via JWP bridge)
- 1.3MB `.text` section (heavily obfuscated)
- 144 `init_array` constructors (anti-tamper setup)

**PTY API (39+ internal functions):**
- Data: `PTYCreate{Bool,Int,Float,String,Dict,List}`
- Access: `PTYDict{Get,Set}Value`, `PTYList{Get,Set,Append}Value`
- Control: `PTYIsReady`, `PTYIsHostReady`, `PTYEndCall`
- Network: `PTYDownloadPackage`
- JSON: `PTYObjectFromJSON`

**MSSDK Namespace (from .rodata):**
```
lt.risk_inspect.http_reqsign.secdeviceid.setting
```
- `risk_inspect` - Risk analysis/inspection
- `http_reqsign` - Request signing (X-Argus/X-Gorgon/X-Ladon/X-Khronos)
- `secdeviceid` - Secure device ID generation
- `setting` - SDK configuration

**DISPATCH-64 VM:**
- Custom bytecode interpreter
- `INVALID_OPCODE`, `UNSUPPORT_OPCODE` error handling
- Session tracking: `vm_session_count`, `vm_call_time_cost`

**Behavioral Biometrics:**
- `msmodel_captcha.touch` / `touch_count` - Touch pattern ML model
- `msmodel_captcha.motion` / `motion_count` - Motion sensor ML model
- `msmodel_captcha.text_edit` / `text_edit_count` - Text input ML model
- `msmodel_captcha.app_status` - App state tracking

**Anti-Analysis:**
- Imports: `ptrace`, `fork` (anti-debugging)
- Strings: `env_hook` (hook detection), `env_root` (root detection)
- `__system_property_find` (device property verification)

### libttmverify.so (18KB) - SSL Certificate Pinning

**Core function:** `vcn_custom_verify_2`
- Registered via `tt_set_verify_callback` on libsscronet.so
- Uses Cronet's `Cronet_CertVerify_DoVerifyV2` for custom cert validation
- Checks: OCSP stapling, Certificate Transparency (SCT), known roots

### Signing Integration
- `Cronet_ClientOpaqueData_do_sign_set` registers the signing callback
- Signing function lives inside `libmetasec_ov.so` (called via PTY API)
- Called for each outgoing Cronet request

---

## Step 3: Device as Proxy (ANALYZED ✓)

### Approach
Hook `Cronet_ClientOpaqueData_do_sign_set/get` to intercept the signing callback:
- `do_sign_set` @ `libsscronet.so+0x24dfc4` registers the signer
- `do_sign_get` @ `libsscronet.so+0x24e05c` retrieves it
- The signing function lives in `libmetasec_ov.so`

### Current Status
Not needed because the offline signing engine + complete header set already produces working API calls. The proxy approach would be useful as a fallback if the signing engine stops working.

### How to Implement (if needed)
1. Hook `Cronet_ClientOpaqueData_do_sign_set` during app init to capture signer pointer
2. Create Frida RPC to invoke the signer with custom URL/method/body
3. Extract returned headers (X-Argus, X-Gorgon, X-Khronos, X-Ladon)
4. Requires Java bridge (unavailable on API 36) OR direct native function call

---

## Files Created

| File | Description |
|------|-------------|
| `feed_api_client.py` | Working feed API client with full header set |
| `captured_feed_request.json` | Complete request template from H2 capture |
| `captured_headers.json` | All discovered headers/cookies |
| `device_emulator_registered.json` | Updated device profile with new cookies |
| `signing_engine.py` | X-Argus/X-Gorgon/X-Ladon/X-Khronos generator |
