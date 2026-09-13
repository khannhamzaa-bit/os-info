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
TOKEN_FILE = os.environ.get("TOKEN_FILE", "token.json")
CREDIT = "https://t.me/os_codex"
VERSION = "5.0"

# ==================== ACCOUNTS (fallback if token.json missing) ====================
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
TIMEOUT = 5
WORKERS = 20

# ==================== Module-Level Caches ====================
_TOKENS = None
_TOKENS_LOADED_AT = 0
_TOKENS_LOCK = threading.Lock()
_TOKENS_TTL = 300

_RESPONSES = {}
_RESPONSES_LOCK = threading.Lock()
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
        elif w == 5:
            r[f] = int.from_bytes(d[o:o+4], 'little'); o += 4
        elif w == 1:
            r[f] = int.from_bytes(d[o:o+8], 'little'); o += 8
        else: break
    return r


def parse_resp(raw):
    try: return json.loads(raw)
    except: pass
    try: return pp(dec(raw))
    except: pass
    try: return pp(raw)
    except: return {}


# ==================== JWT Helpers ====================
def decode_jwt(j):
    try:
        s = j.split('.')[1]; s += '=' * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except: return {}


def jwt_exp(j):
    return int(decode_jwt(j).get('exp') or 0)


def jwt_region(j):
    p = decode_jwt(j)
    return (p.get('noti_region') or p.get('country_code')
            or p.get('lock_region') or 'IND').upper()


# ==================== Token File Loader ====================
def find_token_file():
    """Try multiple paths to locate token.json."""
    paths = [
        os.environ.get("TOKEN_FILE", ""),
        "token.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "token.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "token.json"),
        os.path.join(os.getcwd(), "token.json"),
        "/var/task/token.json",
        "/tmp/token.json",
    ]
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def load_tokens_from_file():
    """Load tokens from token.json. Returns {region: entry} dict."""
    path = find_token_file()
    if not path:
        log("TOKEN", "no token.json found")
        return {}

    try:
        with open(path) as f:
            data = json.load(f)
    except Exception as e:
        log("TOKEN", f"parse error: {e}")
        return {}

    entries = data if isinstance(data, list) else [data]
    now = int(time.time())
    tokens = {}

    for e in entries:
        if not isinstance(e, dict): continue
        tok = e.get("token")
        if not tok: continue

        exp = jwt_exp(tok) or int(e.get("expires_at") or 0)
        if not exp or now >= (exp - 300):
            continue

        region = (e.get("region") or jwt_region(tok)).upper()
        tokens[region] = {
            "uid": e.get("uid"),
            "token": tok,
            "region": region,
            "exp": exp,
            "remaining_min": (exp - now) // 60,
        }

    log("TOKEN", f"loaded {len(tokens)} tokens from {path}")
    return tokens


def fetch_token_fallback(uid, password):
    """Fallback: fetch JWT directly from API."""
    try:
        r = SESSION.get(JWT_API.format(uid=uid, password=password), timeout=TIMEOUT)
        if r.status_code != 200: return None
        data = r.json()
        for k in ("jwt", "token", "jwt_token", "access_token"):
            v = data.get(k)
            if isinstance(v, str) and v.startswith("eyJ"): return v
        return None
    except: return None


def fetch_all_fallback():
    """Fetch all tokens from JWT API in parallel (only if file missing)."""
    def fetch_region(region, accounts):
        for acc in accounts:
            tok = fetch_token_fallback(acc["uid"], acc["password"])
            if tok:
                exp = jwt_exp(tok)
                return region, {
                    "uid": acc["uid"], "token": tok, "region": region,
                    "exp": exp, "remaining_min": (exp - int(time.time())) // 60,
                }
        return region, None

    log("TOKEN", "fetching from JWT API (no file)")
    results = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(fetch_region, r, JWT_ACCOUNTS[r]): r for r in JWT_ACCOUNTS}
        for f in as_completed(futs):
            region, entry = f.result()
            if entry:
                results[region] = entry
    return results


def get_tokens():
    """Return tokens — from file cache, or fetch fresh."""
    global _TOKENS, _TOKENS_LOADED_AT

    now = time.time()
    with _TOKENS_LOCK:
        if _TOKENS and (now - _TOKENS_LOADED_AT) < _TOKENS_TTL:
            return _TOKENS

    tokens = load_tokens_from_file()
    if not tokens:
        tokens = fetch_all_fallback()

    with _TOKENS_LOCK:
        _TOKENS = tokens
        _TOKENS_LOADED_AT = now

    return tokens


def invalidate_token(region):
    global _TOKENS
    with _TOKENS_LOCK:
        if _TOKENS:
            _TOKENS.pop(region, None)


# ==================== Fetch Player ====================
def build_body(aid):
    return enc(fi(1, aid) + fi(2, 1))


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
        r = SESSION.post(f"{host}/GetPlayerPersonalShow",
                         headers=h, data=body, timeout=TIMEOUT)
        if r.status_code == 200:
            return parse_resp(r.content)
        if r.status_code == 401:
            invalidate_token(region)
        return None
    except: return None


# ==================== Extractors ====================
BR_RANKS = [(0,"Bronze I"),(100,"Bronze II"),(200,"Bronze III"),
    (300,"Silver I"),(400,"Silver II"),(500,"Silver III"),
    (600,"Gold I"),(700,"Gold II"),(800,"Gold III"),
    (900,"Platinum I"),(1000,"Platinum II"),(1100,"Platinum III"),
    (1200,"Diamond I"),(1300,"Diamond II"),(1400,"Diamond III"),
    (1500,"Diamond IV"),(1700,"Heroic"),(2000,"Elite Heroic"),
    (2300,"Master"),(2600,"Elite Master"),(2900,"Grandmaster")]


def br_rank_name(p):
    n = "Bronze I"
    for t, x in BR_RANKS:
        if p >= t: n = x
        else: break
    return n


def cs_rank_name(p):
    for t, n in [(2900,"Grandmaster"),(2600,"Elite Master"),(2300,"Master"),
                 (2000,"Elite Heroic"),(1700,"Heroic"),(1500,"Diamond IV"),
                 (1400,"Diamond III"),(1300,"Diamond II"),(1200,"Diamond I"),
                 (1100,"Platinum III"),(1000,"Platinum II"),(900,"Platinum I"),
                 (800,"Gold III"),(700,"Gold II"),(600,"Gold I")]:
        if p >= t: return n
    return "Bronze"


PET_NAMES = {
    1300000001:"Kitty", 1300000002:"Ottero", 1300000003:"Mr. Waggor",
    1300000004:"Falco", 1300000005:"Robby", 1300000006:"Shiba",
    1300000007:"Sensei Tig", 1300000008:"Agent Hop", 1300000009:"Beaston",
}


def pet_name(pid):
    return PET_NAMES.get(pid, f"Pet {pid}")


def decode_hex(h):
    if not isinstance(h, str) or not h: return ""
    try: return bytes.fromhex(h).decode('utf-8', 'ignore').strip()
    except: return ""


def fmt_ts(ts):
    if not ts or not isinstance(ts, int): return "N/A"
    try:
        return time.strftime("%d %B %Y at %I:%M:%S %p (IST)",
                             time.gmtime(ts + 5*3600 + 30*60))
    except: return str(ts)


def g(d, k, default=None):
    if not isinstance(d, dict): return default
    v = d.get(str(k), d.get(k, default))
    if isinstance(v, dict) and 'data' in v: return v['data']
    return v if v is not None else default


def extract_info(resp):
    p = g(resp, 1) or {}
    uid    = g(p, 1)
    name   = g(p, 3, "Unknown")
    region = g(p, 5, "?")
    level  = g(p, 6, 0)
    exp    = g(p, 7, 0)
    likes  = g(p, 21, 0)
    prime  = g(p, 14, 0)
    banner = g(p, 11, 0)
    avatar = g(p, 12, 0)
    badge  = g(p, 19, 0)
    br_points = g(p, 15, 0)
    bp_badges = g(p, 18, 0)
    season = g(p, 50, "?")
    created = g(p, 24, 0)
    last_login = g(p, 44, 0)

    bio_hex = g(g(g(p, 9, {}), 9, {}), 12, "")
    bio = decode_hex(bio_hex) or "(empty)"

    honor_blk = g(resp, 11, {})
    honor_score = g(honor_blk, 1, 0) if isinstance(honor_blk, dict) else 0

    cs_blk = g(g(p, 61, {}), 3, {})
    cs_pts = cs_blk.get('3', 0) if isinstance(cs_blk, dict) else 0

    bp_t = g(g(p, 63, {}), 1, {})
    bp_type = bp_t.get('1', 0) if isinstance(bp_t, dict) else 0
    bp_label = {1: "Free", 2: "Premium", 9: "Basic"}.get(bp_type, "Basic")

    pet_out = None
    pet_blk = g(resp, 8, {})
    if isinstance(pet_blk, dict) and pet_blk:
        pid = pet_blk.get('1') or pet_blk.get(1)
        pet_out = {
            "id": pid, "name": pet_name(pid),
            "level": pet_blk.get('3') or pet_blk.get(3),
            "exp": pet_blk.get('4') or pet_blk.get(4),
        }

    clan_out = None
    c = g(resp, 6, {})
    L = g(resp, 7, {})
    if isinstance(c, dict) and c:
        clan_out = {
            "id": c.get('1') or c.get(1),
            "name": c.get('2') or c.get(2),
            "level": c.get('4') or c.get(4),
            "members_current": c.get('6') or c.get(6),
            "members_max": c.get('5') or c.get(5),
        }
        if isinstance(L, dict) and L:
            clan_out["leader"] = {
                "name": L.get('3') or L.get(3),
                "uid": L.get('1') or L.get(1),
                "level": L.get('6') or L.get(6),
            }

    return {
        "account_id": uid,
        "account_name": name,
        "region": region,
        "level": level,
        "experience": exp,
        "prime_level": prime,
        "likes": likes,
        "honor_score": honor_score,
        "created_at": fmt_ts(last_login),
        "last_login": fmt_ts(created),
        "season": season,
        "signature": bio,
        "ranks": {
            "br_points": br_points,
            "br_rank": br_rank_name(br_points),
            "cs_points": cs_pts,
            "cs_rank": cs_rank_name(cs_pts),
        },
        "cosmetics": {
            "banner_id": banner,
            "avatar_id": avatar,
            "badge_id": badge,
            "bp_badges": bp_badges,
            "bp_type": bp_label,
        },
        "pet": pet_out,
        "clan": clan_out,
    }


def fetch_parallel(target):
    """Try ALL tokens in parallel. First 200 wins."""
    cache = get_tokens()
    if not cache:
        return None, None, None, "no tokens"

    with ThreadPoolExecutor(max_workers=min(WORKERS, len(cache))) as pool:
        futs = {
            pool.submit(try_token, e["token"], target, r): (r, e["uid"])
            for r, e in cache.items()
        }
        for f in as_completed(futs):
            region, uid = futs[f]
            try:
                resp = f.result()
                if resp:
                    return extract_info(resp), region, uid, None
            except: continue

    return None, None, None, "all failed"


def get_cached_response(uid):
    with _RESPONSES_LOCK:
        e = _RESPONSES.get(uid)
        if e and (time.time() - e["ts"]) < _RESPONSE_TTL:
            return e
    return None


def set_cached_response(uid, data, region, used_uid):
    with _RESPONSES_LOCK:
        _RESPONSES[uid] = {
            "data": data, "region": region,
            "used_uid": used_uid, "ts": time.time(),
        }
        if len(_RESPONSES) > 1000:
            oldest = sorted(_RESPONSES.items(), key=lambda x: x[1]["ts"])[:200]
            for k, _ in oldest:
                _RESPONSES.pop(k, None)


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


# ==================== ENDPOINTS ====================
@app.route('/get', methods=['GET'])
@app.route('/info', methods=['GET'])
def get_info():
    uid_in = (request.args.get('info')
              or request.args.get('uid')
              or request.args.get('follower')
              or '').strip()

    if not uid_in or not uid_in.isdigit():
        return jsonify({"success": False, "error": "uid required",
                        "example": "/get?info=1901614992",
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
            "token_source": "response_cache",
            "time_sec": round(time.time() - t0, 3),
            "data": cached["data"],
            "credit": CREDIT,
        })

    info, region, used_uid, err = fetch_parallel(target)
    elapsed = round(time.time() - t0, 3)

    if not info:
        return jsonify({
            "success": False,
            "error": "player_fetch_failed",
            "detail": err,
            "time_sec": elapsed,
            "credit": CREDIT,
        }), 502

    set_cached_response(target, info, region, used_uid)

    return jsonify({
        "success": True,
        "region": region,
        "used_uid": used_uid,
        "token_source": "parallel",
        "time_sec": elapsed,
        "data": info,
        "credit": CREDIT,
    })


@app.route('/tokens/reload', methods=['GET'])
def reload_tokens():
    """Force reload tokens from token.json."""
    global _TOKENS, _TOKENS_LOADED_AT
    with _TOKENS_LOCK:
        _TOKENS = None
        _TOKENS_LOADED_AT = 0
    cache = get_tokens()
    return jsonify({
        "success": True,
        "reloaded": len(cache),
        "tokens": [{"uid": e["uid"], "region": r, "expires_in_min": e["remaining_min"]}
                   for r, e in cache.items()],
        "credit": CREDIT,
    })


@app.route('/tokens/status', methods=['GET'])
def token_status():
    cache = get_tokens()
    path = find_token_file()
    return jsonify({
        "success": True,
        "token_file": path or "(not found)",
        "cached_regions": len(cache),
        "tokens": [{"uid": e["uid"], "region": r, "expires_in_min": e["remaining_min"]}
                   for r, e in cache.items()],
        "response_cache_size": len(_RESPONSES),
        "credit": CREDIT,
    })


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
    cache = get_tokens()
    return jsonify({
        "name": "Ultra-Fast Info API",
        "version": VERSION,
        "token_file": find_token_file() or "(missing)",
        "cached_tokens": len(cache),
        "endpoints": {
            "/get?info={uid}": "Get full player info",
            "/info?uid={uid}": "Alias",
            "/tokens/reload": "Reload token.json",
            "/tokens/status": "Token cache status",
            "/metrics": "Server metrics",
        },
        "credit": CREDIT,
    })


# ==================== Startup ====================
print(f"\n⚡ Ultra-Fast Info API v{VERSION}")
print(f"   Token file: {find_token_file() or '(not found)'}\n")
try:
    initial = get_tokens()
    print(f"   ✅ Loaded {len(initial)} tokens\n")
except Exception as e:
    print(f"   ⚠️  Initial load: {e}\n")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
