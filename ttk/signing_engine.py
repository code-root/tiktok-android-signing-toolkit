#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signing_engine.py — محرك توقيع TikTok الشامل (ملف واحد مستقل)

يحتوي على جميع خوارزميات التوقيع دون أي imports خارجية (stdlib فقط + pycryptodome):
  - X-SS-STUB  : MD5(body).upper()
  - X-Khronos  : Unix timestamp
  - X-Gorgon   : RC4-like (KSA + PRGA + handle)
  - X-Ladon    : SIMON-128/128 ECB + PKCS7
  - X-Argus    : Protobuf + SIMON-128 + AES-CBC

الاستخدام السريع:
    from signing_engine import sign

    headers = sign(
        url="https://api16-normal-c-alisg.tiktokv.com/passport/user/login/?device_id=...&ts=...",
        method="POST",
        body="username=foo&password=bar",
        cookie="store-idc=useast5; ...",
    )
    # headers = {"X-Gorgon": "...", "X-Khronos": "...", "X-Argus": "...", "X-Ladon": "...", "X-SS-STUB": "..."}
"""

# ══════════════════════════════════════════════════════════════════════════════
# stdlib imports فقط (+ pycryptodome لـ AES)
# ══════════════════════════════════════════════════════════════════════════════
import base64
import ctypes
import gzip as _gzip
import hashlib
import time
import struct
from copy import deepcopy
from enum import IntEnum, unique
from os import urandom
from random import randint
from struct import unpack
from urllib.parse import parse_qs, urlparse

# pycryptodome — الوحيد خارج stdlib (مطلوب لـ X-Argus فقط)
try:
    from Crypto.Cipher.AES import MODE_CBC, block_size, new as aes_new
    from Crypto.Util.Padding import pad as aes_pad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ══════════════════════════════════════════════════════════════════════════════
# PKCS7 Padding
# ══════════════════════════════════════════════════════════════════════════════

def _pkcs7_pad_buffer(buf: bytearray, data_len: int, buf_size: int, mod: int) -> int:
    pad = mod - (data_len % mod)
    if data_len + pad > buf_size:
        return -pad
    for i in range(pad):
        buf[data_len + i] = pad
    return pad


def _pkcs7_padded_size(size: int) -> int:
    mod = size % 16
    return size + (16 - mod) if mod else size


# ══════════════════════════════════════════════════════════════════════════════
# SM3 Hash (Chinese national standard GB/T 32905-2016)
# ══════════════════════════════════════════════════════════════════════════════

class _SM3:
    _IV = [1937774191, 1226093241, 388252375, 3666478592,
           2842636476, 372324522, 3817729613, 2969243214]
    _TJ = [2043430169] * 16 + [2055708042] * 48

    def _rl(self, a, k):
        k %= 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    def _FF(self, X, Y, Z, j):
        return X ^ Y ^ Z if j < 16 else (X & Y) | (X & Z) | (Y & Z)

    def _GG(self, X, Y, Z, j):
        return X ^ Y ^ Z if j < 16 else (X & Y) | ((~X) & Z)

    def _P0(self, X): return X ^ self._rl(X, 9) ^ self._rl(X, 17)
    def _P1(self, X): return X ^ self._rl(X, 15) ^ self._rl(X, 23)

    def _CF(self, Vi, Bi):
        W = []
        for i in range(16):
            d = 0
            w = 0x1000000
            for k in range(i * 4, (i + 1) * 4):
                d += Bi[k] * w
                w //= 0x100
            W.append(d)
        for j in range(16, 68):
            W.append(self._P1(W[j-16] ^ W[j-9] ^ self._rl(W[j-3], 15))
                     ^ self._rl(W[j-13], 7) ^ W[j-6])
        W1 = [W[j] ^ W[j+4] for j in range(64)]
        A, B, C, D, E, F, G, H = Vi
        for j in range(64):
            SS1 = self._rl((self._rl(A, 12) + E + self._rl(self._TJ[j], j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ self._rl(A, 12)
            TT1 = (self._FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (self._GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D, C, B, A = C, self._rl(B, 9), A, TT1
            H, G, F, E = G, self._rl(F, 19), E, self._P0(TT2)
        return [x & 0xFFFFFFFF ^ y for x, y in zip([A,B,C,D,E,F,G,H], Vi)]

    def hash(self, msg: bytes) -> bytes:
        msg = bytearray(msg)
        L = len(msg)
        msg.append(0x80)
        r = (L % 64) + 1
        end = 56 + (64 if r > 56 else 0)
        msg.extend(b'\x00' * (end - r))
        bl = L * 8
        for _ in range(8):
            msg.append(bl % 0x100)
            bl //= 0x100
        msg[-8:] = bytes(reversed(msg[-8:]))
        V = [self._IV[:]]
        for i in range(len(msg) // 64):
            V.append(self._CF(V[i], msg[i*64:(i+1)*64]))
        res = b""
        for x in V[-1]:
            res += int(x).to_bytes(4, "big")
        return res


def sm3(data: bytes) -> bytes:
    """SM3 hash → 32 bytes"""
    return _SM3().hash(data)


# ══════════════════════════════════════════════════════════════════════════════
# Protobuf (minimal encoder/decoder)
# ══════════════════════════════════════════════════════════════════════════════

@unique
class _PFT(IntEnum):
    VARINT = 0; INT64 = 1; STRING = 2; GROUPSTART = 3; GROUPEND = 4; INT32 = 5


class _ProtoBuf:
    def __init__(self, data=None):
        self.fields = []
        if data is None:
            return
        if isinstance(data, bytes) and data:
            self._parse_bytes(data)
        elif isinstance(data, dict) and data:
            self._parse_dict(data)

    def _parse_bytes(self, raw):
        pos = 0
        while pos < len(raw):
            vint, pos = self._read_varint(raw, pos)
            ft = _PFT(vint & 7)
            fi = vint >> 3
            if fi == 0: break
            if ft == _PFT.INT32:
                v = int.from_bytes(raw[pos:pos+4], 'little'); pos += 4
            elif ft == _PFT.INT64:
                v = int.from_bytes(raw[pos:pos+8], 'little'); pos += 8
            elif ft == _PFT.VARINT:
                v, pos = self._read_varint(raw, pos)
            elif ft == _PFT.STRING:
                L, pos = self._read_varint(raw, pos)
                v = raw[pos:pos+L]; pos += L
            else:
                break
            self.fields.append((fi, ft, v))

    def _parse_dict(self, d):
        for k, v in d.items():
            if isinstance(v, int):
                self.fields.append((k, _PFT.VARINT, v))
            elif isinstance(v, str):
                self.fields.append((k, _PFT.STRING, v.encode('utf-8')))
            elif isinstance(v, bytes):
                self.fields.append((k, _PFT.STRING, v))
            elif isinstance(v, dict):
                self.fields.append((k, _PFT.STRING, _ProtoBuf(v).to_bytes()))

    @staticmethod
    def _read_varint(data, pos):
        v = n = 0
        while True:
            b = data[pos]; pos += 1
            v |= (b & 0x7F) << (7 * n)
            if b < 0x80: break
            n += 1
        return v, pos

    @staticmethod
    def _write_varint(v):
        v &= 0xFFFFFFFF
        out = bytearray()
        while v > 0x7F:
            out.append((v & 0x7F) | 0x80)
            v >>= 7
        out.append(v & 0x7F)
        return bytes(out)

    def to_bytes(self) -> bytes:
        out = bytearray()
        for fi, ft, v in self.fields:
            key = (fi << 3) | (ft & 7)
            out += self._write_varint(key)
            if ft == _PFT.INT32:
                out += v.to_bytes(4, 'little')
            elif ft == _PFT.INT64:
                out += v.to_bytes(8, 'little')
            elif ft == _PFT.VARINT:
                out += self._write_varint(v)
            elif ft == _PFT.STRING:
                out += self._write_varint(len(v)) + v
        return bytes(out)


# ══════════════════════════════════════════════════════════════════════════════
# SIMON-128/128 Block Cipher
# ══════════════════════════════════════════════════════════════════════════════

def _rl64(v, n):
    return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _rr64(v, n):
    return ((v << (64 - n)) | (v >> n)) & 0xFFFFFFFFFFFFFFFF

def _simon_expand(k):
    key = list(k) + [0] * 68
    for i in range(4, 72):
        tmp = _rr64(key[i-1], 3) ^ key[i-3]
        tmp ^= _rr64(tmp, 1)
        key[i] = (~key[i-4] & 0xFFFFFFFFFFFFFFFF) ^ tmp ^ ((0x3DC94C3A046D678B >> ((i-4) % 62)) & 1) ^ 3
    return key

def simon_enc(pt, k):
    """SIMON-128/128 encrypt one block. pt=[x,y] uint64, k=4 uint64 → [x,y]"""
    ks = _simon_expand(k)
    x, y = pt
    for i in range(72):
        tmp = y
        f = _rl64(y, 1) & _rl64(y, 8)
        y = x ^ f ^ _rl64(y, 2) ^ ks[i]
        x = tmp
    return [x, y]


# ══════════════════════════════════════════════════════════════════════════════
# X-SS-STUB
# ══════════════════════════════════════════════════════════════════════════════

def compute_stub(body) -> str:
    """X-SS-STUB = MD5(body_before_gzip).upper(). Empty body → empty string."""
    if not body:
        return ""
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    return hashlib.md5(raw).hexdigest().upper()


# ══════════════════════════════════════════════════════════════════════════════
# X-Gorgon  (RC4-like KSA + PRGA + nibble-swap/bit-reverse)
# ══════════════════════════════════════════════════════════════════════════════

_GORGON_HEX_STR = {
    "0404": [30, 64, 224, 217, 147, 69, 0, 180],
    "8404": [0, 0, 0, 0, 0, 0, 0, 0],
}

def _gorgon_ksa(hex_str):
    """RC4-like KSA — builds 256-element permutation table."""
    table = list(range(256))
    tmp = ''
    for i in range(256):
        A = 0 if i == 0 else (tmp if tmp else table[i - 1])
        B = hex_str[i % 8]
        if A == 85 and i != 1 and tmp != 85:
            A = 0
        C = (A + i + B) % 256
        tmp = C if C < i else ''
        table[i] = table[C]
    return table

def _gorgon_prga(inp, table):
    """RC4-like PRGA — XOR stream cipher over 20-byte input."""
    tmp_add = []
    tmp_copy = table.copy()
    for i in range(20):
        B = 0 if not tmp_add else tmp_add[-1]
        C = (table[i + 1] + B) % 256
        tmp_add.append(C)
        D = tmp_copy[C]
        tmp_copy[i + 1] = D
        E = (D + D) % 256
        F = tmp_copy[E]
        inp[i] ^= F
    return inp

def _gorgon_handle(inp):
    """Nibble-swap + bit-reverse + XOR transform over 20 bytes."""
    for i in range(20):
        A = inp[i]
        h = hex(A)[2:].zfill(2)
        B = int(h[1] + h[0], 16)           # swap nibbles
        C = inp[(i + 1) % 20]
        D = B ^ C
        E = int(bin(D)[2:].zfill(8)[::-1], 2)  # reverse bits
        F = E ^ 20
        G = (~F) & 0xFF
        inp[i] = G
    return inp

def compute_gorgon(query_string: str, stub: str = "", cookie: str = "",
                   ts: int = None, version: str = "8404") -> dict:
    """
    Compute X-Gorgon + X-Khronos.
    Returns {"X-Gorgon": "8404...", "X-Khronos": "1773712078"}
    """
    if ts is None:
        ts = int(time.time())

    hex_str = _GORGON_HEX_STR.get(version, _GORGON_HEX_STR["8404"])
    khronos_hex = hex(ts)[2:].zfill(8)

    url_md5 = hashlib.md5(query_string.encode("utf-8")).hexdigest()
    inp = [int(url_md5[2*i:2*i+2], 16) for i in range(4)]

    if stub:
        for i in range(4):
            inp.append(int(stub[2*i:2*i+2], 16))
    else:
        inp += [0, 0, 0, 0]

    if cookie:
        ck_md5 = hashlib.md5(cookie.encode("utf-8")).hexdigest()
        for i in range(4):
            inp.append(int(ck_md5[2*i:2*i+2], 16))
    else:
        inp += [0, 0, 0, 0]

    inp += [0, 0, 0, 0]

    for i in range(4):
        inp.append(int(khronos_hex[2*i:2*i+2], 16))

    table  = _gorgon_ksa(hex_str)
    result = _gorgon_handle(_gorgon_prga(inp, table))

    sig = "".join(f"{b:02x}" for b in result)
    gorgon = (f"{version}"
              f"{hex_str[7]:02x}{hex_str[3]:02x}"
              f"{hex_str[1]:02x}{hex_str[6]:02x}"
              f"{sig}")

    return {"X-Gorgon": gorgon, "X-Khronos": str(ts)}


# ══════════════════════════════════════════════════════════════════════════════
# X-Ladon  (SIMON-128/128 ECB + PKCS7)
# ══════════════════════════════════════════════════════════════════════════════

def _ladon_encrypt_block(ks_table: bytes, data: bytes) -> bytes:
    d0 = int.from_bytes(data[:8], 'little')
    d1 = int.from_bytes(data[8:], 'little')
    for i in range(0x22):
        k = int.from_bytes(ks_table[i*8:(i+1)*8], 'little')
        d1 = (k ^ (d0 + _rr64(d1, 8))) & 0xFFFFFFFFFFFFFFFF
        d0 = (d1 ^ (_rr64(d0, 3) | (_rl64(d0, 61)))) & 0xFFFFFFFFFFFFFFFF
        # actual formula matches XLadon.py:
        # data1 = key ^ (data0 + ROR(data1,8))
        # data0 = data1 ^ ROR(data0,61) — reuse new data1
    return d0.to_bytes(8, 'little') + d1.to_bytes(8, 'little')

def _ladon_keyschedule(md5hex_bytes: bytes) -> bytearray:
    ht = bytearray(272 + 16)
    ht[:32] = md5hex_bytes
    temp = [int.from_bytes(ht[i*8:(i+1)*8], 'little') for i in range(4)]
    b0, b8 = temp[0], temp[1]
    temp = temp[2:]
    for i in range(0x22):
        x9 = b0
        x8 = b8
        x8 = _rr64(x8, 8)
        x8 = (x8 + x9) & 0xFFFFFFFFFFFFFFFF
        x8 ^= i
        temp.append(x8)
        x8 ^= _rr64(x9, 61)
        ht[(i+1)*8:(i+2)*8] = x8.to_bytes(8, 'little')
        b0 = x8
        b8 = temp.pop(0)
    return ht

def _ladon_encrypt_data(md5hex_bytes: bytes, data: bytes) -> bytes:
    ht = _ladon_keyschedule(md5hex_bytes)
    new_size = _pkcs7_padded_size(len(data))
    buf = bytearray(new_size)
    buf[:len(data)] = data
    _pkcs7_pad_buffer(buf, len(data), new_size, 16)
    out = bytearray(new_size)
    for i in range(new_size // 16):
        blk = buf[i*16:(i+1)*16]
        d0 = int.from_bytes(blk[:8], 'little')
        d1 = int.from_bytes(blk[8:], 'little')
        for j in range(0x22):
            k = int.from_bytes(ht[(j+1)*8:(j+2)*8], 'little')
            tmp_d1 = (k ^ (d0 + _rr64(d1, 8))) & 0xFFFFFFFFFFFFFFFF
            tmp_d0 = (tmp_d1 ^ _rr64(d0, 61)) & 0xFFFFFFFFFFFFFFFF
            d0, d1 = tmp_d0, tmp_d1
        out[i*16:i*16+8]   = d0.to_bytes(8, 'little')
        out[i*16+8:i*16+16] = d1.to_bytes(8, 'little')
    return bytes(out)

def compute_ladon(ts: int = None, license_id: int = 1611921764,
                  aid: int = 1233, rand: bytes = None) -> str:
    """X-Ladon = base64( rand[4] + SIMON_encrypt('{ts}-{license_id}-{aid}') )"""
    if ts is None:
        ts = int(time.time())
    if rand is None:
        rand = urandom(4)
    data    = f"{ts}-{license_id}-{aid}".encode()
    keygen  = rand + str(aid).encode()
    md5hex  = hashlib.md5(keygen).hexdigest().encode()
    enc     = _ladon_encrypt_data(md5hex, data)
    out     = bytes(rand) + enc
    return base64.b64encode(out).decode()


# ══════════════════════════════════════════════════════════════════════════════
# X-Argus  (Protobuf → SIMON-128 → XOR/reverse → AES-CBC)
# ══════════════════════════════════════════════════════════════════════════════

# ثابتات مُستخرجة من TikTokCore.framework
_ARGUS_SIGN_KEY = (
    b"\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8"
    b"\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c"
)
_ARGUS_SM3_OUTPUT = (
    b"\xfcx\xe0\xa9ez\x0ct\x8c\xe5\x15Y\x90<\xcf\x03"
    b"Q\x0eQ\xd3\xcf\xf22\xd7\x13C\xe8\x8a2\x1cS\x04"
)  # = sm3(sign_key + b'\xf2\x81ao' + sign_key)

def _argus_simon_key_list():
    key = _ARGUS_SM3_OUTPUT[:32]
    kl = []
    for _ in range(2):
        kl += list(unpack("<QQ", key[_*16:_*16+16]))
    return kl

def _argus_encrypt_protobuf(protobuf_padded: bytes) -> bytes:
    kl = _argus_simon_key_list()
    n = len(protobuf_padded)
    enc = bytearray(n)
    for i in range(n // 16):
        pt = list(unpack("<QQ", protobuf_padded[i*16:(i+1)*16]))
        ct = simon_enc(pt, kl)
        enc[i*16:i*16+8]   = ct[0].to_bytes(8, 'little')
        enc[i*16+8:i*16+16] = ct[1].to_bytes(8, 'little')
    return bytes(enc)

def _argus_xor_reverse(enc_pb: bytes) -> bytes:
    data = list(b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff") + list(enc_pb)
    L = len(data)
    xor_head = data[:8]
    for i in range(8, L):
        data[i] ^= xor_head[i % 8]
    return bytes(data[::-1])

def _argus_calculate_constant(os_version: str) -> int:
    parts = [int(d) for d in os_version.replace(".", "").zfill(6)]
    weights = [20480, 2048, 20971520, 2097152, 1342177280, 134217728]
    return sum(p * w for p, w in zip(parts, weights))

def compute_argus(query_string: str, stub: str = None, ts: int = None,
                  aid: int = 1233, license_id: int = 1611921764,
                  platform: int = 0,
                  sec_device_id: str = None,
                  sdk_version: str = "v04.04.05-ov-android",
                  sdk_version_int: int = 134744640) -> str:
    """
    Compute X-Argus.
    Requires pycryptodome (Crypto.Cipher.AES). Returns empty string if not installed.
    """
    if not _HAS_CRYPTO:
        return ""

    if ts is None:
        ts = int(time.time())

    params_dict = parse_qs(query_string)

    def _qp(k, default=""):
        v = params_dict.get(k)
        return v[0] if v else default

    # Channel must match query (e.g. beta / samsung_store) — was hardcoded googleplay.
    ch = _qp("channel") or "googleplay"

    # bodyHash & queryHash via SM3
    stub_bytes  = bytes.fromhex(stub) if stub else bytes(16)
    body_hash   = sm3(stub_bytes)[:6]
    query_hash  = sm3(query_string.encode() if query_string else bytes(16))[:6]

    bean = {
        1:  0x20200929 << 1,
        2:  2,
        3:  randint(0, 0x7FFFFFFF),
        4:  str(aid),
        5:  _qp("device_id"),
        6:  str(license_id),
        7:  _qp("version_name"),
        8:  sdk_version,
        9:  sdk_version_int,
        10: bytes(8),
        11: platform,
        12: ts << 1,
        13: body_hash,
        14: query_hash,
        20: 738,
        23: {
            1: _qp("device_type"),
            2: _qp("os_version"),
            3: ch,
            4: _argus_calculate_constant(_qp("os_version", "10")),
        },
    }
    if sec_device_id:
        bean[16] = sec_device_id

    # Protobuf → PKCS7 pad
    pb_raw     = _ProtoBuf(bean).to_bytes()
    pb_padded  = aes_pad(pb_raw, block_size)

    # SIMON encrypt protobuf
    enc_pb = _argus_encrypt_protobuf(pb_padded)

    # XOR + reverse
    b_buf = _argus_xor_reverse(enc_pb)
    b_buf = b"\xa6n\xad\x9fw\x01\xd0\x0c\x18" + b_buf + b"ao"

    # AES-CBC
    aes_key = hashlib.md5(_ARGUS_SIGN_KEY[:16]).digest()
    aes_iv  = hashlib.md5(_ARGUS_SIGN_KEY[16:]).digest()
    cipher  = aes_new(aes_key, MODE_CBC, aes_iv)
    ct      = cipher.encrypt(aes_pad(b_buf, block_size))

    return base64.b64encode(b"\xf2\x81" + ct).decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# الواجهة الرئيسية
# ══════════════════════════════════════════════════════════════════════════════

def sign(url: str, method: str = "POST", body=b"",
         cookie: str = "", ts: int = None) -> dict:
    """
    توليد جميع هيدرز التوقيع لطلب TikTok.

    المعاملات:
        url     : الرابط الكامل (مع query string)
        method  : "GET" أو "POST"
        body    : الجسم (bytes أو str) — مطلوب لـ POST
        cookie  : قيمة هيدر Cookie (اختياري)
        ts      : Unix timestamp (اختياري — الافتراضي: الوقت الحالي)

    المخرجات:
        dict يحتوي:
            X-SS-STUB, X-Khronos, X-Gorgon, X-Ladon, X-Argus
    """
    if ts is None:
        ts = int(time.time())

    parsed      = urlparse(url)
    qs          = parsed.query

    body_bytes  = body.encode("utf-8") if isinstance(body, str) else (body or b"")
    stub        = compute_stub(body_bytes) if body_bytes and method.upper() != "GET" else ""

    gorgon_data = compute_gorgon(
        query_string=qs,
        stub=stub,
        cookie=cookie,
        ts=ts,
    )

    argus = compute_argus(query_string=qs, stub=stub or None, ts=ts)
    ladon = compute_ladon(ts=ts)

    result = {
        "X-Khronos": gorgon_data["X-Khronos"],
        "X-Gorgon":  gorgon_data["X-Gorgon"],
        "X-Ladon":   ladon,
        "X-Argus":   argus,
    }
    if stub:
        result["X-SS-STUB"] = stub

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="TikTok Signing Engine")
    p.add_argument("--url",    required=True,  help="Full URL with query string")
    p.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    p.add_argument("--body",   default="",     help="Request body")
    p.add_argument("--cookie", default="",     help="Cookie header value")
    p.add_argument("--ts",     type=int,       help="Unix timestamp (default: now)")
    args = p.parse_args()

    headers = sign(
        url=args.url,
        method=args.method,
        body=args.body,
        cookie=args.cookie,
        ts=args.ts,
    )
    print(json.dumps(headers, indent=2, ensure_ascii=False))
