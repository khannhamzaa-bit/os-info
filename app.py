from flask import Flask, request, jsonify, g
import json, os, time, base64, requests, threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== CONFIG ====================
JWT_API = "https://os-jwt-access.vercel.app/jwt?uid={uid}&password={password}"
CREDIT = "https://t.me/os_codex"
VERSION = "3.0"

# ==================== ACCOUNTS ====================
JWT_ACCOUNTS = {
    "IND": [
        {"uid": "4712787314", "password": "A3C9F7C0F8FEED9C9C0E7714BF14F8E5C26D0502687F4548394C1905C1728293"},
        {"uid": "4296688743", "password": "83D7FB3512DDEC7E50223F08F2CDC6CE0ED51C584EBB0749C4770290379FB7EF"},
    ],
    "ID": [
        {"uid": "7642857250", "password": "HAMZA-_8CO7"},
        {"uid": "7642857264", "password": "HAMZA-_42D2"},
    ],
    "SAC": [
        {"uid": "7642825639", "password": "HAMZA-_X4TE"},
        {"uid": "7642825643", "password": "HAMZA-_3NUX"},
    ],
    "NA": [
        {"uid": "7642807933", "password": "HAMZA-_ODSJ"},
        {"uid": "7642807944", "password": "HAMZA-_R3IJ"},
    ],
    "BR": [
        {"uid": "7642795484", "password": "HAMZA-_SLGG"},
        {"uid": "7642795487", "password": "HAMZA-_2PLV"},
    ],
    "PK": [
        {"uid": "7642765148", "password": "HAMZA-_3NKO"},
        {"uid": "7642765146", "password": "HAMZA-_WVRX"},
    ],
    "BD": [
        {"uid": "7642744055", "password": "HAMZA-_PQ9A"},
        {"uid": "7642744040", "password": "HAMZA-_FDW7"},
    ],
}

# ==================== AES ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ==================== Region → Host ====================
REGION_HOSTS = {
    "IND": "https://client.ind.freefiremobile.com",
    "ID":  "https://clientbp.ggpolarbear.com",
    "SAC": "https://client.us.freefiremobile.com",
    "NA":  "https://client.us.freefiremobile.com",
    "BR":  "https://client.us.freefiremobile.com",
    "PK":  "https://clientbp.ggpolarbear.com",
    "BD":  "https://clientbp.ggblueshark.com",
    "US":  "https://client.us.freefiremobile.com",
    "SG":  "https://clientbp.ggpolarbear.com",
    "TH":  "https://clientbp.ggpolarbear.com",
    "VN":  "https://clientbp.ggpolarbear.com",
    "ME":  "https://clientbp.ggpolarbear.com",
    "MY":  "https://clientbp.ggpolarbear.com",
    "PH":  "https://clientbp.ggpolarbear.com",
    "RU":  "https://clientbp.ggpolarbear.com",
}
DEFAULT_HOST = "https://client.ind.freefiremobile.com"

# ==================== Session ====================
SESSION = requests.Session()
SESSION.verify = False
_adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
SESSION.mount("http://", _adapter)
SESSION.mount("https://", _adapter)
TIMEOUT = 6
WORKERS = 15

# ==================== Caches ====================
_TOKEN_CACHE = {}
_TOKEN_LOCK = threading.Lock()
_TOKEN_TTL = 600

_RESPONSE_CACHE = {}
_RESPONSE_LOCK = threading.Lock()
_RESPONSE_TTL = 1800

_METRICS = {"total": 0, "success": 0, "fail": 0, "cache_hit": 0, "time": 0.0}


def log(tag, msg):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


# ==================== Crypto ====================
def enc(d):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(d, AES.block_size))


def dec(d):
    return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(d), AES.block_size)


# ==================== Protobuf ====================
def vi(n):
    o = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)


def fi(f, n):
    return vi((f << 3) | 0) + vi(int(n))


def rv(d, o):
    r = 0; s = 0
    while True:
        b = d[o]; r |= (b & 0x7F) << s; o += 1
        if not (b & 0x80): break
        s += 7
    return r, o


def pp(d, depth=0):
    if depth > 8: return None
    r = {}; o = 0
    while o < len(d):
        try: t, o = rv(d, o)
        except IndexError: break
        f = t >> 3; w = t & 7
        if w == 0:
            v, o = rv(d, o); r[f] = v
        elif w == 2:
            ln, o = rv(d, o)
            if o + ln > len(d): break
            v = d[o:o+ln]; o += ln
            try:
                x = v.decode('utf-8')
                if all(32 <= ord(c) < 127 or ord(c) > 127 for c in x):
                    r[f] = x; continue
            except: pass
            try:
                n = pp(v, depth + 1)
                r[f] = n if n else v.hex()
            except: r[f] = v.hex()
        else: break
    return r


def parse_resp(raw):
    try: return json.loads(raw)
    except: pass
    try: return pp(dec(raw))
    except: pass
    try: return pp(raw)
    except: return {}


# ==================== JWT ====================
def decode_jwt(j):
    try:
        s = j.split('.')[1]; s += '=' * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except: return {}


def jwt_exp(j):
    return int(decode_jwt(j).get('exp') or 0)


# ==================== Token Fetch (parallel) ====================
def fetch_jwt(uid, password):
    try:
        r = SESSION.get(JWT_API.format(uid=uid, password=password), timeout=TIMEOUT)
        if r.status_code != 200: return None
        data = r.json()
        for k in ("jwt", "token", "jwt_token", "access_token"):
            v = data.get(k)
            if isinstance(v, str) and v.startswith("eyJ"): return v
        return None
    except: return None


def fetch_region_token(region, accounts):
    for acc in accounts:
        tok = fetch_jwt(acc["uid"], acc["password"])
        if tok:
            exp = jwt_exp(tok)
            return region, {
                "uid": acc["uid"], "token": tok, "region": region,
                "exp": exp, "remaining_min": (exp - int(time.time())) // 60,
            }
    return region, None


def get_tokens():
    with _TOKEN_LOCK:
        now = time.time()
        if _TOKEN_CACHE and (now - _TOKEN_CACHE.get("_loaded_at", 0)) < _TOKEN_TTL:
            return {k: v for k, v in _TOKEN_CACHE.items() if k != "_loaded_at"}

    log("TOKEN", "fetching parallel...")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(fetch_region_token, r, JWT_ACCOUNTS[r]): r
                for r in JWT_ACCOUNTS}
        results = {}
        for f in as_completed(futs):
            region, entry = f.result()
            if entry:
                results[region] = entry
                log("TOKEN", f"✅ {region}")

    with _TOKEN_LOCK:
        for r, e in results.items():
            _TOKEN_CACHE[r] = e
        _TOKEN_CACHE["_loaded_at"] = time.time()

    return results


def invalidate_token(region):
    with _TOKEN_LOCK:
        _TOKEN_CACHE.pop(region, None)


# ==================== Fetch ====================
def build_body(aid):
    return enc(fi(1, aid) + fi(2, 1) + fi(3, 1) + fi(4, 1))


def try_token(token, aid, region):
    host = REGION_HOSTS.get(region, DEFAULT_HOST)
    body = build_body(aid)
    h = {
        "Authorization": f"Bearer {token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-Unity-Version": "2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
    }
    try:
        r = SESSION.post(f"{host}/GetWorkshopAuthorInfo",
                         headers=h, data=body, timeout=TIMEOUT)
        if r.status_code == 200:
            return parse_resp(r.content)
        if r.status_code == 401:
            invalidate_token(region)
        return None
    except: return None


def _find_name(o, depth=0):
    if depth > 6: return None
    if isinstance(o, dict):
        for k in ('6', 6, '3', 3):
            v = o.get(k)
            if isinstance(v, str) and v and not v.isdigit() and len(v) < 60:
                return v
        for v in o.values():
            r = _find_name(v, depth + 1)
            if r: return r
    elif isinstance(o, list):
        for v in o:
            r = _find_name(v, depth + 1)
            if r: return r
    return None


def extract(resp):
    info = {"account_id": None, "account_name": None, "bio": None,
            "followers": None, "points": None}
    top4 = resp.get('4') or resp.get(4)
    if isinstance(top4, int): info["account_id"] = top4

    f1 = resp.get('1') or resp.get(1)
    if isinstance(f1, dict):
        f1_4 = f1.get('4') or f1.get(4)
        if isinstance(f1_4, dict):
            if info["account_id"] is None:
                aid = f1_4.get('2') or f1_4.get(2)
                if isinstance(aid, int): info["account_id"] = aid
            nick = f1_4.get('6') or f1_4.get(6)
            if isinstance(nick, str) and nick: info["account_name"] = nick

    f7 = resp.get('7') or resp.get(7)
    if isinstance(f7, dict):
        if info["account_id"] is None:
            aid = f7.get('1') or f7.get(1)
            if isinstance(aid, int): info["account_id"] = aid
        foll = f7.get('2') or f7.get(2)
        pts  = f7.get('3') or f7.get(3)
        bio  = f7.get('6') or f7.get(6)
        if isinstance(foll, int): info["followers"] = foll
        if isinstance(pts, int):  info["points"]    = pts
        if isinstance(bio, str):  info["bio"]       = bio

    if not info["account_name"]:
        n = _find_name(resp)
        if n: info["account_name"] = n

    return info


def fetch_parallel(target):
    cache = get_tokens()
    if not cache:
        return None, None, None, "no tokens"

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {
            pool.submit(try_token, e["token"], target, r): (r, e["uid"])
            for r, e in cache.items()
        }
        for f in as_completed(futs):
            region, uid = futs[f]
            try:
                resp = f.result()
                if resp:
                    return extract(resp), region, uid, None
            except: continue

    return None, None, None, "all failed"


def get_cached_response(uid):
    with _RESPONSE_LOCK:
        e = _RESPONSE_CACHE.get(uid)
        if e and (time.time() - e["ts"]) < _RESPONSE_TTL:
            return e
    return None


def set_cached_response(uid, data, region, used_uid):
    with _RESPONSE_LOCK:
        _RESPONSE_CACHE[uid] = {
            "data": data, "region": region,
            "used_uid": used_uid, "ts": time.time(),
        }
        if len(_RESPONSE_CACHE) > 500:
            oldest = sorted(_RESPONSE_CACHE.items(), key=lambda x: x[1]["ts"])[:100]
            for k, _ in oldest:
                _RESPONSE_CACHE.pop(k, None)


# ==================== Hooks ====================
@app.before_request
def _start(): g.start = time.time()


@app.after_request
def _log(response):
    elapsed = time.time() - g.start
    _METRICS["total"] += 1
    _METRICS["time"] += elapsed
    if response.status_code == 200:
        _METRICS["success"] += 1
    else:
        _METRICS["fail"] += 1
    return response


# ==================== Endpoints ====================
@app.route('/get', methods=['GET'])
@app.route('/followers', methods=['GET'])
def get_info():
    uid_in = (request.args.get('follower')
              or request.args.get('uid')
              or request.args.get('info')
              or '').strip()

    if not uid_in or not uid_in.isdigit():
        return jsonify({"success": False, "error": "uid required",
                        "credit": CREDIT}), 400

    target = int(uid_in)
    t0 = time.time()

    cached = get_cached_response(target)
    if cached:
        _METRICS["cache_hit"] += 1
        return jsonify({
            "success": True,
            "region": cached["region"],
            "used_uid": cached["used_uid"],
            "token_source": "cache",
            "time_sec": round(time.time() - t0, 3),
            "data": cached["data"],
            "credit": CREDIT,
        })

    info, region, used_uid, err = fetch_parallel(target)
    elapsed = round(time.time() - t0, 3)

    if not info:
        return jsonify({
            "success": False,
            "error": "workshop_fetch_failed",
            "detail": err,
            "time_sec": elapsed,
            "credit": CREDIT,
        }), 502

    data = {
        "account_id": info["account_id"],
        "account_name": info["account_name"],
        "bio": info["bio"],
        "followers": info["followers"],
        "points": info["points"],
    }

    set_cached_response(target, data, region, used_uid)

    return jsonify({
        "success": True,
        "region": region,
        "used_uid": used_uid,
        "token_source": "parallel",
        "time_sec": elapsed,
        "data": data,
        "credit": CREDIT,
    })


@app.route('/token/refresh', methods=['GET'])
def refresh_tokens():
    with _TOKEN_LOCK:
        _TOKEN_CACHE.clear()
    cache = get_tokens()
    return jsonify({
        "success": True,
        "refreshed": len(cache),
        "tokens": [{"uid": e["uid"], "region": r, "expires_in_min": e["remaining_min"]}
                   for r, e in cache.items()],
        "credit": CREDIT,
    })


@app.route('/token/status', methods=['GET'])
def token_status():
    cache = get_tokens()
    return jsonify({
        "success": True,
        "total_regions": len(JWT_ACCOUNTS),
        "cached_regions": len(cache),
        "missing": [r for r in JWT_ACCOUNTS if r not in cache],
        "tokens": [{"uid": e["uid"], "region": r, "expires_in_min": e["remaining_min"]}
                   for r, e in cache.items()],
        "response_cache_size": len(_RESPONSE_CACHE),
        "credit": CREDIT,
    })


@app.route('/token/clear', methods=['GET'])
def clear_tokens():
    with _TOKEN_LOCK: _TOKEN_CACHE.clear()
    with _RESPONSE_LOCK: _RESPONSE_CACHE.clear()
    return jsonify({"success": True, "message": "cleared", "credit": CREDIT})


@app.route('/metrics', methods=['GET'])
def metrics():
    t = _METRICS["total"]
    return jsonify({
        "success": True,
        "metrics": {
            "total": t,
            "success": _METRICS["success"],
            "fail": _METRICS["fail"],
            "cache_hits": _METRICS["cache_hit"],
            "cache_hit_rate": f"{(_METRICS['cache_hit'] / t * 100):.1f}%" if t else "0%",
            "avg_time_sec": round(_METRICS["time"] / t, 3) if t else 0,
        },
        "credit": CREDIT,
    })


@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "name": "Ultra-Fast Workshop API",
        "version": VERSION,
        "endpoints": {
            "/get?follower={uid}": "Get followers + info",
            "/followers?uid={uid}": "Alias",
            "/token/refresh": "Refresh tokens",
            "/token/status": "Cache status",
            "/token/clear": "Clear cache",
            "/metrics": "Server metrics",
        },
        "credit": CREDIT,
    })


if __name__ == '__main__':
    print(f"\n⚡ Ultra-Fast Workshop API v{VERSION}\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
