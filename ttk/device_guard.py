#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
device_guard.py — TikTok v44.3.15 Device/Ticket Guard Header Builder

Computes tt-device-guard-client-data (pre-login) and tt-ticket-guard-client-data
(post-login) using ECDSA P-256 signing with the device's EC key pair.

Signing format — from traffic capture analysis (2026-03-23):

  tt-device-guard-client-data (base64-encoded JSON):
    {
      "device_token": "1|{aid,av,did,iid,fit,s,idc,ts}",
      "timestamp":    <unix_seconds>,
      "req_content":  "device_token,path,timestamp",
      "dtoken_sign":  "ts.1.<base64(DER(ECDSA(SHA256(device_token))))>",
      "dreq_sign":    "<base64(DER(ECDSA(SHA256(device_token + path + str(ts)))))>"
    }

  tt-ticket-guard-client-data (base64-encoded JSON, post-login only):
    {
      "req_content": "ticket,path,timestamp",
      "req_sign":    "<base64(DER(ECDSA(SHA256(ticket + path + str(ts)))))>",
      "timestamp":   <unix_seconds>,
      "ts_sign":     "ts.1.<hex(P1363_r||s(ECDSA(SHA256(str(ts)))))>"
    }

Signature formats:
  DER format   → standard ASN.1 DER for ECDSA (30 45 02 21 ... 02 20 ...)
  P1363 format → raw r||s (64 bytes), used only for ts_sign

Requires: cryptography >= 3.0 (pip install cryptography)
"""

import base64
import json
import time as _time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ── Internal signing helpers ──────────────────────────────────────────────────

def _load_private_key(pem: str):
    """Load EC private key from PEM string."""
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography package not installed: pip install cryptography")
    raw = pem.encode() if isinstance(pem, str) else pem
    return serialization.load_pem_private_key(raw, password=None)


def _sign_der(private_key, message: bytes) -> bytes:
    """ECDSA P-256 SHA-256 — returns DER-encoded signature."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def _sign_p1363(private_key, message: bytes) -> bytes:
    """ECDSA P-256 SHA-256 — returns raw r||s (64 bytes, IEEE P1363)."""
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ── Public API ────────────────────────────────────────────────────────────────

def build_device_guard_client_data(
    profile: dict,
    path: str,
    private_pem: str,
    ts: int = None,
) -> str:
    """
    Build tt-device-guard-client-data header value.

    Args:
        profile     : device profile dict
        path        : URL path of the current request (e.g. '/passport/auth/get_nonce/')
        private_pem : EC P-256 private key in PEM format
        ts          : unix timestamp (defaults to now)

    Returns:
        base64-encoded JSON string ready for the header
    """
    private_key = _load_private_key(private_pem)
    if ts is None:
        ts = int(_time.time())

    d   = profile["device"]
    a   = profile["app"]
    m   = profile["meta"]

    # idc comes from tt-target-idc cookie
    idc = "useast8"
    for seg in (profile.get("session", {}).get("cookie", "")).split(";"):
        seg = seg.strip()
        if seg.startswith("tt-target-idc="):
            idc = seg.split("=", 1)[1].strip()
            break

    fit = str(int(profile.get("session", {}).get("last_install_time", ts)))

    # Build device_token: "1|<compact JSON>"
    inner = json.dumps({
        "aid": int(a["aid"]),
        "av":  m["version"],
        "did": d["device_id"],
        "iid": d["iid"],
        "fit": fit,
        "s":   1,
        "idc": idc,
        "ts":  str(ts),
    }, separators=(",", ":"))
    device_token = f"1|{inner}"

    # dtoken_sign: sign the device_token string → "ts.1.<base64(DER)>"
    dtoken_der  = _sign_der(private_key, device_token.encode())
    dtoken_sign = "ts.1." + base64.b64encode(dtoken_der).decode()

    # dreq_sign: sign device_token + path + str(ts) → "<base64(DER)>"
    dreq_msg  = (device_token + path + str(ts)).encode()
    dreq_der  = _sign_der(private_key, dreq_msg)
    dreq_sign = base64.b64encode(dreq_der).decode()

    payload = {
        "device_token": device_token,
        "timestamp":    ts,
        "req_content":  "device_token,path,timestamp",
        "dtoken_sign":  dtoken_sign,
        "dreq_sign":    dreq_sign,
    }
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    ).decode()


def build_ticket_guard_client_data(
    ticket: str,
    path: str,
    private_pem: str,
    ts: int = None,
) -> str:
    """
    Build tt-ticket-guard-client-data header value (post-login only).

    Args:
        ticket      : session ticket/token (x_tt_token or session_key)
        path        : URL path of the current request
        private_pem : EC P-256 private key in PEM format
        ts          : unix timestamp (defaults to now)

    Returns:
        base64-encoded JSON string ready for the header
    """
    private_key = _load_private_key(private_pem)
    if ts is None:
        ts = int(_time.time())

    # req_sign: sign ticket + path + str(ts) → "<base64(DER)>"
    req_msg  = (ticket + path + str(ts)).encode()
    req_der  = _sign_der(private_key, req_msg)
    req_sign = base64.b64encode(req_der).decode()

    # ts_sign: sign str(ts) → "ts.1.<hex(raw r||s)>"
    ts_p1363 = _sign_p1363(private_key, str(ts).encode())
    ts_sign  = "ts.1." + ts_p1363.hex()

    payload = {
        "req_content": "ticket,path,timestamp",
        "req_sign":    req_sign,
        "timestamp":   ts,
        "ts_sign":     ts_sign,
    }
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    ).decode()


def get_public_key_header(public_pem: str) -> str:
    """
    Convert PEM public key → uncompressed EC point base64
    (used as tt-ticket-guard-public-key header value).

    Example output: 'BCL2e3QzeZKG...'
    """
    if not _HAS_CRYPTO:
        return ""
    raw = public_pem.encode() if isinstance(public_pem, str) else public_pem
    pub = serialization.load_pem_public_key(raw)
    point = pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return base64.b64encode(point).decode()


# ── Convenience: build all guard headers for a request ───────────────────────

def build_guard_headers(
    profile: dict,
    path: str,
    private_pem: str,
    public_key_b64: str,
    login_state: int = 0,
    ts: int = None,
) -> dict:
    """
    Build all device/ticket guard headers for a request.

    Args:
        profile        : device profile dict
        path           : URL path (e.g. '/passport/user/login/')
        private_pem    : EC P-256 private key PEM string
        public_key_b64 : uncompressed EC point base64 (tt-ticket-guard-public-key)
        login_state    : 0 = pre-login, 1 = post-login (adds ticket guard)
        ts             : unix timestamp (defaults to now)

    Returns:
        dict of headers to merge into the request
    """
    if ts is None:
        ts = int(_time.time())

    headers = {
        "tt-ticket-guard-version":           "3",
        "tt-ticket-guard-public-key":         public_key_b64,
        "tt-ticket-guard-iteration-version":  "0",
        "tt-device-guard-iteration-version":  "1",
        "tt-device-guard-client-data": build_device_guard_client_data(
            profile, path, private_pem, ts
        ),
    }

    # Post-login: also include tt-ticket-guard-client-data
    if login_state == 1:
        ticket = profile.get("session", {}).get("x_tt_token", "") or \
                 profile.get("session", {}).get("session_key", "")
        if ticket:
            headers["tt-ticket-guard-client-data"] = build_ticket_guard_client_data(
                ticket, path, private_pem, ts
            )

    return headers
