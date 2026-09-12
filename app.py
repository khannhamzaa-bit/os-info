from flask import Flask, request, jsonify
import json, os, time, base64, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== CONFIG ====================
JWT_API = "https://os-jwt-access.vercel.app/jwt?uid={uid}&password={password}"
ACCOUNTS_FILE = "accounts.json"
TOKEN_FILE = os.environ.get("TOKEN_FILE", "token.json")
CREDIT = "https://t.me/os_codex"
MAX_CACHE_ENTRIES = 200


def load_accounts():
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[INIT] failed to load {ACCOUNTS_FILE}: {e}")
        return {}


ACCOUNTS = load_accounts()

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

# ==================== REAL HOST MAPPING (from working code) ====================
REGION_ENDPOINTS = {
    "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
    "BR":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "US":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "NA":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "BD":  "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
    "ID":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "PK":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "VN":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "ME":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "TH":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "SG":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "MY":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "PH":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "RU":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
}

# Fallback hosts to try in order
FALLBACK_HOSTS = [
    "https://client.ind.freefiremobile.com",
    "https://clientbp.ggblueshark.com",
    "https://clientbp.ggpolarbear.com",
    "https://client.us.freefiremobile.com",
]

SESSION = requests.Session()
SESSION.verify = False
SESSION.mount("http://", requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100))
SESSION.mount("https://", requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100))
TIMEOUT = 10


def log(tag, msg):
    print(f"[{time.strftime('%H:%M:%S')}] [{tag}] {msg}", flush=True)


def enc(d):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(d, AES.block_size))


def dec(d):
    return unpad(AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(d), AES.block_size)


def vi(n):
    o = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        o.append(b)
        if not n:
            break
    return bytes(o)


def fi(f, n):
    return vi((f << 3) | 0) + vi(int(n))


def rv(d, o):
    r = 0
    s = 0
    while True:
        b = d[o]
        r |= (b & 0x7F) << s
        o += 1
        if not (b & 0x80):
            break
        s += 7
    return r, o


def pp(d):
    r = {}
    o = 0
    while o < len(d):
        try:
            t, o = rv(d, o)
        except Exception:
            break
        f = t >> 3
        w = t & 7
        if w == 0:
            v, o = rv(d, o)
            r[f] = v
        elif w == 2:
            l, o = rv(d, o)
            v = d[o:o+l]
            o += l
            try:
                x = v.decode('utf-8')
                if all(32 <= ord(c) < 127 or ord(c) > 127 for c in x):
                    r[f] = x
                else:
                    raise ValueError
            except Exception:
                try:
                    n = pp(v)
                    r[f] = n if n else v.hex()
                except Exception:
                    r[f] = v.hex()
        elif w == 5:
            r[f] = int.from_bytes(d[o:o+4], 'little')
            o += 4
        elif w == 1:
            r[f] = int.from_bytes(d[o:o+8], 'little')
            o += 8
        else:
            break
    return r


def parse_resp(raw):
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        return pp(dec(raw))
    except Exception:
        pass
    try:
        return pp(raw)
    except Exception:
        return {}


def decode_jwt(j):
    try:
        s = j.split('.')[1]
        s += '=' * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return {}


def jwt_exp(j):
    return int(decode_jwt(j).get('exp') or 0)


def jwt_region(j):
    p = decode_jwt(j)
    return (p.get('noti_region') or p.get('country_code')
            or p.get('lock_region') or 'IND').upper()


# ==================== CACHE ====================
def load_cache():
    if not os.path.exists(TOKEN_FILE):
        return []
    try:
        with open(TOKEN_FILE) as f:
            data = json.load(f)
    except Exception:
        return []
    entries = data if isinstance(data, list) else [data]
    now = int(time.time())
    valid = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        tok = e.get('token')
        if not tok:
            continue
        exp = jwt_exp(tok) or int(e.get('expires_at') or 0)
        if exp and now < (exp - 300):
            valid.append({
                "token": tok,
                "region": (e.get('region') or jwt_region(tok)).upper(),
                "uid": e.get('uid'),
                "remaining_min": (exp - now) // 60,
            })
    return valid


def save_cache(tok, region, uid):
    try:
        e = {
            "token": tok,
            "region": region,
            "uid": uid,
            "saved_at": int(time.time()),
            "expires_at": jwt_exp(tok),
        }
        ex = []
        if os.path.exists(TOKEN_FILE):
            try:
                with open(TOKEN_FILE) as f:
                    d = json.load(f)
                ex = d if isinstance(d, list) else [d]
            except Exception:
                ex = []
        ex = [x for x in ex if isinstance(x, dict) and x.get('uid') != uid]
        ex.append(e)
        if len(ex) > MAX_CACHE_ENTRIES:
            ex = ex[-MAX_CACHE_ENTRIES:]
        with open(TOKEN_FILE, 'w') as f:
            json.dump(ex, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def remove_cache(uid):
    if not os.path.exists(TOKEN_FILE):
        return
    try:
        with open(TOKEN_FILE) as f:
            d = json.load(f)
        ex = d if isinstance(d, list) else [d]
        ex = [x for x in ex if isinstance(x, dict) and x.get('uid') != uid]
        with open(TOKEN_FILE, 'w') as f:
            json.dump(ex, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ==================== JWT FETCH (YOUR API) ====================
def fetch_token(acc):
    """Fetch JWT from os-jwt-access.vercel.app."""
    url = JWT_API.format(uid=acc['uid'], password=acc['password'])
    try:
        r = requests.get(url, timeout=15, verify=False)
        if r.status_code != 200:
            return None, None, f"HTTP {r.status_code}"

        data = r.json()

        # Try multiple response field names
        token = None
        if isinstance(data, dict):
            for key in ("jwt", "jwt_token", "token", "access_token"):
                v = data.get(key)
                if isinstance(v, str) and v.startswith("eyJ"):
                    token = v
                    break

        if not token:
            return None, None, f"no token: {str(data)[:80]}"

        region = (data.get("region") or jwt_region(token)).upper()
        save_cache(token, region, acc['uid'])
        return token, region, None

    except Exception as e:
        return None, None, str(e)[:60]


def get_all_tokens():
    cached = load_cache()
    if cached:
        log("TOKEN", f"using {len(cached)} cached tokens")
        return cached, "cache"

    log("TOKEN", "cache empty — fetching fresh")
    tokens = []
    all_accs = []
    for region, pool in ACCOUNTS.items():
        for acc in pool:
            all_accs.append(acc)

    for acc in all_accs:
        tok, reg, err = fetch_token(acc)
        if tok:
            tokens.append({
                "token": tok,
                "region": reg,
                "uid": acc['uid'],
                "remaining_min": (jwt_exp(tok) - int(time.time())) // 60,
            })

    log("TOKEN", f"fetched {len(tokens)} tokens")
    return tokens, "api"


# ==================== FETCH PLAYER ====================
def fetch_player_any_token(aid, region):
    """Try every token. Use region endpoint first, then fallback hosts."""
    tokens, source = get_all_tokens()
    if not tokens:
        return None, None, None, "no tokens available"

    try:
        body = enc(fi(1, aid) + fi(2, 1))
    except Exception as e:
        return None, None, None, f"body error: {str(e)[:60]}"

    h_base = {
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-Unity-Version": "2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
    }

    # Build hosts list — region-specific first, then fallbacks
    region_up = (region or "IND").upper()
    primary = REGION_ENDPOINTS.get(region_up, REGION_ENDPOINTS["default"])
    hosts = [primary]
    for h in FALLBACK_HOSTS:
        url = f"{h}/GetPlayerPersonalShow"
        if url not in hosts:
            hosts.append(url)

    last_err = "no response"
    attempted = 0

    for tok_entry in tokens:
        jwt = tok_entry["token"]
        uid = tok_entry.get("uid")
        h = h_base.copy()
        h["Authorization"] = f"Bearer {jwt}"

        for host_url in hosts:
            attempted += 1
            try:
                r = SESSION.post(host_url, headers=h, data=body,
                                 timeout=TIMEOUT, verify=False)

                if r.status_code == 200:
                    log("FETCH", f"✅ uid={uid} host={host_url.split('//')[1].split('/')[0][:25]}")
                    return parse_resp(r.content), uid, tok_entry.get("region"), None

                last_err = f"HTTP {r.status_code} @ {host_url.split('//')[1].split('/')[0][:20]}"

            except Exception as e:
                last_err = str(e)[:50]

        if '401' in last_err:
            remove_cache(uid)

    return None, None, None, f"tried {len(tokens)} tokens × {len(hosts)} hosts ({attempted} calls), last: {last_err}"


# ==================== RANK TABLES ====================
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
        if p >= t:
            n = x
        else:
            break
    return n


def cs_rank_name(p):
    for t, n in [(2900,"Grandmaster"),(2600,"Elite Master"),(2300,"Master"),
                 (2000,"Elite Heroic"),(1700,"Heroic"),(1500,"Diamond IV"),
                 (1400,"Diamond III"),(1300,"Diamond II"),(1200,"Diamond I"),
                 (1100,"Platinum III"),(1000,"Platinum II"),(900,"Platinum I"),
                 (800,"Gold III"),(700,"Gold II"),(600,"Gold I")]:
        if p >= t:
            return n
    return "Bronze"


PET_NAMES = {
    1300000001:"Kitty", 1300000002:"Ottero", 1300000003:"Mr. Waggor",
    1300000004:"Falco", 1300000005:"Robby", 1300000006:"Shiba",
    1300000007:"Sensei Tig", 1300000008:"Agent Hop", 1300000009:"Beaston",
}


def pet_name(pid):
    return PET_NAMES.get(pid, f"Pet {pid}")


def g(d, k, default=None):
    if not isinstance(d, dict):
        return default
    v = d.get(str(k), d.get(k, default))
    if isinstance(v, dict) and 'data' in v:
        return v['data']
    return v if v is not None else default


def decode_hex(h):
    if not isinstance(h, str) or not h:
        return ""
    try:
        return bytes.fromhex(h).decode('utf-8', 'ignore').strip()
    except Exception:
        return ""


def fmt_ts(ts):
    if not ts or not isinstance(ts, int):
        return "N/A"
    try:
        return time.strftime("%d %B %Y at %I:%M:%S %p (IST)",
                             time.gmtime(ts + 5 * 3600 + 30 * 60))
    except Exception:
        return str(ts)


def build_report(resp):
    p = g(resp, 1) or {}

    uid    = g(p, 1)
    name   = g(p, 3, "Unknown")
    region = g(p, 5, "?")
    level  = g(p, 6, 0)
    exp    = g(p, 7, 0)
    likes  = g(p, 21, 0)
    prime  = g(p, 14, 0)

    honor = g(resp, 11, {})
    honor_score = g(honor, 1, 0) if isinstance(honor, dict) else 0

    bio_hex = g(g(g(p, 9, {}), 9, {}), 12, "")
    bio = decode_hex(bio_hex) or "(empty)"

    gender_map = {1: "Confidential", 2: "Male", 3: "Female"}
    gender = gender_map.get(g(p, 23, 1), "Confidential")

    ob = g(p, 50, "?")
    bp_t = g(g(p, 63, {}), 1, {})
    bp_type = bp_t.get('1', 0) if isinstance(bp_t, dict) else 0
    bp_badges = g(p, 18, 0)
    br_points = g(p, 15, 0)

    cs_blk = g(g(p, 61, {}), 3, {})
    cs_pts = cs_blk.get('3', 0) if isinstance(cs_blk, dict) else 0
    cs_stars = cs_blk.get('4', 0) if isinstance(cs_blk, dict) else 0

    created = g(p, 24, 0)
    last_login = g(p, 44, 0)
    show_rank = g(p, 23, 1)
    show_br = g(g(p, 49, {}), 2, 0) if g(p, 49) else 0
    show_cs = g(g(p, 49, {}), 3, 0) if g(p, 49) else 0

    bp_label = {1: "Free", 2: "Premium", 9: "Basic"}.get(bp_type, "Basic")
    show_rank_str = {1: "CsRanked", 2: "BrRanked"}.get(show_rank, "None")

    pet_out = None
    pet_blk = g(resp, 8, {})
    if isinstance(pet_blk, dict) and pet_blk:
        pid = pet_blk.get('1') or pet_blk.get(1)
        pet_out = {
            "equipped": True, "id": pid, "name": pet_name(pid),
            "type": pet_name(pid),
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

    craftland = None
    try:
        f41 = g(p, 41, {})
        if isinstance(f41, dict):
            f9 = f41.get('9') or f41.get(9)
            if isinstance(f9, dict):
                craftland = f9.get('25') or f9.get(25)
    except Exception:
        pass

    return {
        "basic": {
            "prime_level": prime, "name": name, "uid": uid,
            "level": level, "exp": exp, "region": region, "likes": likes,
            "honor_score": honor_score, "celebrity": False,
            "title": g(p, 75, "") or "Not Found",
            "signature": bio, "gender": gender,
        },
        "activity": {
            "ob": ob, "bp": bp_label, "bp_badges": bp_badges,
            "br_points": br_points, "br_rank": br_rank_name(br_points),
            "cs_points": cs_pts, "cs_rank": cs_rank_name(cs_pts),
            "cs_stars": cs_stars, "show_rank": show_rank_str,
            "show_br": bool(show_br), "show_cs": bool(show_cs),
            "created_at": fmt_ts(created), "last_login": fmt_ts(last_login),
        },
        "overview": {
            "avatar_id": g(p, 12, 0), "banner_id": g(p, 11, 0),
            "pin": "Not Found", "language": "English",
        },
        "pet": pet_out,
        "clan": clan_out,
        "craftland": craftland,
    }


# ==================== ROUTES ====================
@app.route('/get', methods=['GET'])
def get_info():
    uid_in = request.args.get('info', '').strip()
    region_in = (request.args.get('region', 'IND') or 'IND').strip().upper()

    if not uid_in or not uid_in.isdigit():
        return jsonify({
            "success": False,
            "error": "info (numeric account_id) required",
            "example": "/get?info=7033908403&region=IND",
            "premium": {"credit": CREDIT, "message": "Premium API by @os_codex"}
        }), 400

    aid = int(uid_in)
    log("GET", f"uid={aid} region={region_in}")

    resp, used_uid, used_region, err = fetch_player_any_token(aid, region_in)

    if not resp:
        return jsonify({
            "success": False,
            "error": "player_fetch_failed",
            "detail": err,
            "premium": {"credit": CREDIT, "message": "Premium API by @os_codex"}
        }), 502

    report = build_report(resp)

    return jsonify({
        "success": True,
        "region": used_region or region_in,
        "used_uid": used_uid,
        "token_source": "any",
        "data": report,
        "premium": {
            "credit": CREDIT,
            "message": "💎 Premium API by @os_codex",
            "telegram": CREDIT,
        }
    })


@app.route('/token/refresh', methods=['GET'])
def refresh_all():
    if os.path.exists(TOKEN_FILE):
        try:
            os.remove(TOKEN_FILE)
        except Exception:
            pass
    results = {}
    for region, pool in ACCOUNTS.items():
        for acc in pool:
            tok, reg, err = fetch_token(acc)
            if tok:
                results.setdefault(region, []).append(acc['uid'])
    return jsonify({"success": True, "regions": results, "credit": CREDIT})


@app.route('/regions', methods=['GET'])
def regions_info():
    out = {}
    for r, pool in ACCOUNTS.items():
        cached = [c for c in load_cache() if c['region'] == r]
        out[r] = {"accounts": len(pool), "cached_tokens": len(cached)}
    return jsonify({
        "success": True,
        "regions": out,
        "endpoint": "/get?info={uid}&region={region}",
        "credit": CREDIT,
    })


@app.route('/')
def home():
    return jsonify({
        "name": "Advanced Player Info API",
        "regions": list(ACCOUNTS.keys()),
        "endpoint": "/get?info={account_id}&region={region}",
        "example": "/get?info=7033908403&region=IND",
        "premium": {"credit": CREDIT, "message": "💎 Premium API by @os_codex"},
    })


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("   ADVANCED PLAYER INFO API")
    print("=" * 60)
    total = sum(len(v) for v in ACCOUNTS.values())
    print(f"   Regions   : {len(ACCOUNTS)}")
    print(f"   Accounts  : {total}")
    print(f"   JWT API   : {JWT_API[:60]}")
    print(f"   Credit    : {CREDIT}")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
