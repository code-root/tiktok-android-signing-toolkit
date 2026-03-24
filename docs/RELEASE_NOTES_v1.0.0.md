## Highlights

- **Signing:** Local `sign()` pipeline — X-Gorgon, X-Khronos, X-Argus, X-Ladon, X-SS-STUB (`ttk/signing_engine.py`).
- **Flows:** Device registration, multi-step login client, combined register+login (`ttk/device_register.py`, `ttk/login_client.py`, `ttk/flow.py`).
- **Research tools:** MITM Raw folder parsing, feed example, APK `sig_hash` helper (`ttk/mitm_raw.py`, `ttk/feed_api_client.py`, `ttk/tiktok_apk_sig.py`).
- **Quality:** Comprehensive tests (`tests/test_all.py`), fixtures under `fixtures/`, bilingual documentation (`README.md`, `README.ar.md`).

## Requirements

- Python 3.10+
- Dependencies: see `requirements.txt`

## Legal notice

This software is provided for **research and educational** purposes. Using it against production services may violate platform Terms of Service and applicable laws. You are solely responsible for your use.
