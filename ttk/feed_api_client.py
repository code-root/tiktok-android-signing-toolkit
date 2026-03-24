#!/usr/bin/env python3
"""
TikTok Feed API Client - Working implementation with complete header set.
Uses the emulator device profile + signing engine to fetch real feed data.

Captured via HTTP/2 HPACK decoding of TikTok v44.3.1 (QUIC blocked to force TLS).
"""
import sys
import os
import json
import time
import gzip
import hashlib
import urllib.request
import urllib.error
import ssl
from urllib.parse import urlencode

# Auto-resolve path
from .paths import PROJECT_ROOT

from .signing_engine import sign


def load_profile(profile_path=None):
    """Load device profile."""
    if profile_path is None:
        profile_path = os.path.join(PROJECT_ROOT, "device_emulator_registered.json")
    with open(profile_path) as f:
        return json.load(f)


def build_common_params(profile):
    """Build x-common-params-v2 header value."""
    d = profile['device']
    m = profile['meta']
    a = profile['app']
    l = profile['locale']
    n = profile['network']

    params = {
        'ab_version': m['ab_version'],
        'ac': n['ac'],
        'ac2': n['ac2'],
        'aid': a['aid'],
        'app_language': l['app_language'],
        'app_name': a['app_name'],
        'app_type': a['app_type'],
        'build_number': m['build_number'],
        'carrier_region': n['carrier_region'],
        'carrier_region_v2': n['carrier_region_v2'],
        'channel': a['channel'],
        'current_region': l['region'],
        'device_brand': d['device_brand'],
        'device_id': d['device_id'],
        'device_platform': 'android',
        'device_type': d['device_type'],
        'dpi': d['dpi'],
        'iid': d['iid'],
        'language': l['language'],
        'locale': l['locale'],
        'manifest_version_code': m['manifest_version_code'],
        'mcc_mnc': n['mcc_mnc'],
        'op_region': l['op_region'],
        'os_api': d['os_api'],
        'os_version': d['os_version'],
        'region': l['region'],
        'residence': l['region'],
        'resolution': d['resolution'],
        'ssmix': a['ssmix'],
        'sys_region': l['sys_region'],
        'timezone_name': l['timezone_name'],
        'timezone_offset': l['timezone_offset'],
        'uoo': l['uoo'],
        'update_version_code': m['update_version_code'],
        'version_code': m['version_code'],
        'version_name': m['version'],
    }
    return urlencode(params)


def build_headers(profile, url, method, body, ts=None, _rticket=None):
    """Build complete header set matching TikTok's real requests."""
    if ts is None:
        ts = int(time.time())
    if _rticket is None:
        _rticket = int(time.time() * 1000)

    cookie = profile['session']['cookie']

    # Sign the request
    sig = sign(url=url, method=method, body=body, cookie=cookie, ts=ts)

    # MD5 stub for POST body
    stub = hashlib.md5(body).hexdigest().upper() if body and method.upper() != 'GET' else ''

    headers = {
        # Standard
        'User-Agent': profile['user_agent'],
        'Accept-Encoding': 'gzip, deflate, br',
        'Cookie': cookie,

        # Security signatures
        'X-Argus': sig['X-Argus'],
        'X-Gorgon': sig['X-Gorgon'],
        'X-Khronos': str(sig['X-Khronos']),
        'X-Ladon': sig['X-Ladon'],

        # Required TikTok headers
        'x-tt-pba-enable': '1',
        'x-tt-dm-status': 'login=0;ct=1;rt=6',
        'X-SS-REQ-TICKET': str(_rticket),
        'sdk-version': '2',
        'passport-sdk-version': '1',
        'oec-cs-si-a': '2',
        'oec-cs-sdk-version': 'v10.02.02.01-bugfix-ov-android_V31',
        'x-vc-bdturing-sdk-version': '2.4.1.i18n',
        'oec-vc-sdk-version': '3.2.1.i18n',
        'rpc-persist-pns-region-1': 'US|6252001',
        'rpc-persist-pns-region-2': 'US|6252001',
        'rpc-persist-pns-region-3': 'US|6252001',
        'x-tt-request-tag': 'n=0;nr=011;bg=0;rs=100;s=-1;p=0',
        'x-tt-store-region': 'us',
        'x-tt-store-region-src': 'did',
        'rpc-persist-pyxis-policy-state-law-is-ca': '0',
        'rpc-persist-pyxis-policy-v-tnc': '1',
        'x-tt-ttnet-origin-host': 'api16-core-useast5.tiktokv.us',
        'x-ss-dp': profile['app']['aid'],
        'x-common-params-v2': build_common_params(profile),
        'x-tt-trace-id': f'00-{format(ts, "08x")}1069b5d83f35b0060ea904d1-{format(ts, "08x")}1069b5d8-01',
    }

    if stub:
        headers['X-SS-STUB'] = stub
        headers['x-bd-content-encoding'] = 'gzip'

    return headers


def fetch_feed(profile=None, count=6, cursor=0):
    """Fetch TikTok For You feed."""
    if profile is None:
        profile = load_profile()

    ts = int(time.time())
    _rticket = int(time.time() * 1000)

    query = {
        'os': 'android',
        '_rticket': str(_rticket),
        'is_pad': profile['device']['is_pad'],
        'last_install_time': profile['session']['last_install_time'],
        'host_abi': profile['device']['host_abi'],
        'ts': str(ts),
        'effect_sdk_version': '21.0.0',
        'req_from': 'enter_auto',
        'pull_type': '0',
        'app_version': profile['meta']['update_version_code'],
        'is_non_personalized': '0',
    }

    url = 'https://api16-core-useast5.tiktokv.us/aweme/v2/feed/?' + urlencode(query)

    body_json = json.dumps({
        'count': count, 'cursor': cursor, 'type': 0, 'is_cold_start': 1
    }, separators=(',', ':')).encode()
    body_gzip = gzip.compress(body_json)

    headers = build_headers(profile, url, 'POST', body_gzip, ts, _rticket)
    headers['Content-Type'] = 'application/json'

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=body_gzip, headers=headers, method='POST')
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        body = resp.read()
        if resp.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        return body, resp.status, dict(resp.headers)


def parse_feed_proto(data):
    """Basic protobuf wire format decoder for feed response."""
    from google.protobuf.internal.decoder import _DecodeVarint

    def decode_wire(data, start=0, end=None):
        if end is None:
            end = len(data)
        pos = start
        fields = {}
        while pos < end:
            try:
                tag, pos = _DecodeVarint(data, pos)
            except:
                break
            fn = tag >> 3
            wt = tag & 0x07
            if wt == 0:
                val, pos = _DecodeVarint(data, pos)
                fields.setdefault(fn, []).append(val)
            elif wt == 1:
                val = int.from_bytes(data[pos:pos+8], 'little')
                pos += 8
                fields.setdefault(fn, []).append(val)
            elif wt == 2:
                length, pos = _DecodeVarint(data, pos)
                if pos + length > end:
                    break
                raw = data[pos:pos+length]
                pos += length
                try:
                    fields.setdefault(fn, []).append(raw.decode('utf-8'))
                except:
                    try:
                        nested = decode_wire(raw)
                        fields.setdefault(fn, []).append(nested)
                    except:
                        fields.setdefault(fn, []).append(raw)
            elif wt == 5:
                pos += 4
            else:
                break
        return fields

    top = decode_wire(data)
    videos = []

    # Field 5 contains the video items
    for item in top.get(5, []):
        if not isinstance(item, dict):
            continue
        vid = {
            'id': item.get(1, [None])[0],
            'desc': item.get(2, [''])[0],
        }
        # Author info (field 4)
        author = item.get(4, [{}])[0]
        if isinstance(author, dict):
            vid['author_nickname'] = author.get(4, [''])[0] if 4 in author else ''
            vid['author_unique_id'] = author.get(3, [''])[0] if 3 in author else ''

        videos.append(vid)

    return {
        'status_code': top.get(1, [None])[0],
        'has_more': top.get(4, [0])[0],
        'video_count': len(videos),
        'videos': videos,
    }


if __name__ == '__main__':
    print("Fetching TikTok feed...", flush=True)
    data, status, headers = fetch_feed()
    print(f"Status: {status}")
    print(f"Response size: {len(data)} bytes")

    result = parse_feed_proto(data)
    print(f"Videos: {result['video_count']}")
    print(f"Has more: {result['has_more']}")
    print()

    for i, v in enumerate(result['videos'], 1):
        print(f"  {i}. [{v['id']}] {v.get('desc', '')[:80]}")
        if v.get('author_unique_id') or v.get('author_nickname'):
            print(f"     @{v.get('author_unique_id', '?')} ({v.get('author_nickname', '?')})")
