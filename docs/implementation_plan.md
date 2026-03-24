Design a Python implementation plan for a TikTok API signing module. Here's the full context:

## Project Context
- Directory: /Users/mo/Documents/tik-api copy/tik-api-1/
- 1,838 captured HTTP request/response files (txt format) from TikTok v44.3.1 on Android
- Binary analysis done on TikTokCore.framework (539MB, arm64) from v44.2.0 IPA
- Goal: Create a Python signer that generates X-Gorgon, X-Khronos, X-SS-STUB from scratch, and extracts X-Argus/X-Ladon from captured sessions

## Signing Headers Required
1. **X-Gorgon** (48 hex chars, starts with 8404): Custom algorithm, reverse-engineered
   - Example: `840470d0000072339b0fd1dfa854727cccd396542a697ed3b51c`
   - Example: `840440380000de6a0c6ea3e8e9f3600725684ffd8a885c38643f`
   - Format: `8404` + flags_bytes + XOR_signature
   
2. **X-Khronos** (10-digit Unix timestamp): Simply current time in seconds
   - Example: `1773712680`

3. **X-SS-STUB** (32 hex chars uppercase): MD5 of uncompressed request body
   - Example: `2334A127910BFD04C800293D423DEFA7`
   - IMPORTANT: When body is gzip-compressed (x-bd-content-encoding: gzip), X-SS-STUB = MD5 of ORIGINAL (pre-compression) body

4. **X-Argus** (large base64, ~800 chars): Native SDK signature, session-specific
   - Example: `nMSgNI2TxGwvU/6oyJuBgVKDsI9iHdxfYksd2dutZJyjdpegYdj1...`
   - Cannot be computed locally without native binary
   
5. **X-Ladon** (short base64, ~43 chars): Native SDK, session-specific
   - Example: `SHzFGnNrNpmaSnaP3smegyJ9z15ZvxkVZnnUIOi7MBB9oIO7`

## Captured Request File Format
Each .txt file starts like:
```
POST /passport/user/login/?device_platform=android&...&ts=1773712679&iid=7617618076322989837&device_id=7617232110762329614&... HTTP/1.1
Host: api16-normal-c-alisg.tiktokv.com
Content-Length: 117
Cookie: store-idc=useast5; msToken=...
X-SS-STUB: 2334A127910BFD04C800293D423DEFA7
X-Argus: nMSgNI2TxGwvU/6oyJuBgVKDsI9iHdxfYksd2dutZJyjdpegYdj1...
X-Gorgon: 840470d0000072339b0fd1dfa854727cccd396542a697ed3b51c
X-Khronos: 1773712680
X-Ladon: SHzFGnNrNpmaSnaP3smegyJ9z15ZvxkVZnnUIOi7MBB9oIO7

[body here]
```

## Known X-Gorgon Algorithm (from binary reverse engineering)
The algorithm based on analysis of binary strings `ArgusGorgc` and `Tt--X-Ss-TTX-UPpLadonKhrosArguGorg-IdBy-DpDm-StubBd-KmsvneDb_dpmixed`:

X-Gorgon takes:
- params_md5 = MD5(url_query_string) or "0"*32 if empty
- body_md5 = MD5(body) or "0"*32 if empty  
- stub_md5 = X-SS-STUB or "0"*32 if no body
- khronos = current Unix timestamp

Then applies a known XOR cipher to produce the 48-char hex output.

The first 4 bytes are `8404` followed by flag bytes, then the XOR'd signature.

## What the Python module should do:
1. Parse captured .txt request files to extract: device_id, iid, openudid, cdid, cookies, X-Argus, X-Ladon, User-Agent, device params
2. Generate X-Gorgon from url params + body using the known algorithm
3. Generate X-Khronos as current timestamp
4. Generate X-SS-STUB as MD5 of body
5. Provide X-Argus and X-Ladon from captured session (with matching device_id)
6. Export a function: sign_request(url, method, body, session) → headers dict

## Additional Context
- The binary had obfuscated string: `Tt--X-Ss-TTX-UPpLadonKhrosArguGorg-IdBy-DpDm-StubBd-KmsvneDb_dpmixed`
- X-Argus and X-Ladon are device+time bound in a session window
- Body encoding: gzip for most POST requests, X-SS-STUB is pre-compression MD5
- App ID (aid): 1233, version: 44.3.1, version_code: 440301

## Requirements
Design a Python implementation plan with:
1. File: `tiktok_signer.py` - main signing module
2. What classes/functions to create
3. How to implement X-Gorgon algorithm specifically
4. How to parse captured request files
5. How to structure the session/device state
6. What the public API looks like

Be specific about the X-Gorgon algorithm implementation - provide the actual algorithm steps since this is the core of the signer.