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
    "CIS": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "TW":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    "EUROPE": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
}

ALL_HOSTS = [
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


def fetch_token(acc):
    url = JWT_API.format(uid=acc['uid'], password=acc['password'])
    try:
        r = requests.get(url, timeout=15, verify=False)
        if r.status_code != 200:
            return None, None, f"HTTP {r.status_code}"

        data = r.json()
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


def fetch_player_auto(aid):
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

    last_err = "no response"
    attempted = 0

    for tok_entry in tokens:
        jwt = tok_entry["token"]
        uid = tok_entry.get("uid")
        tok_region = (tok_entry.get("region") or jwt_region(jwt)).upper()

        primary = REGION_ENDPOINTS.get(tok_region, REGION_ENDPOINTS["default"])
        hosts = [primary]
        for h in ALL_HOSTS:
            url = f"{h}/GetPlayerPersonalShow"
            if url not in hosts:
                hosts.append(url)

        h = h_base.copy()
        h["Authorization"] = f"Bearer {jwt}"

        for host_url in hosts:
            attempted += 1
            try:
                r = SESSION.post(host_url, headers=h, data=body,
                                 timeout=TIMEOUT, verify=False)
                if r.status_code == 200:
                    log("FETCH", f"✅ uid={uid} region={tok_region}")
                    return parse_resp(r.content), uid, tok_region, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:50]

        if '401' in last_err:
            remove_cache(uid)

    return None, None, None, f"tried {len(tokens)} tokens ({attempted} calls), last: {last_err}"


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
    1300000010:"Moony", 1300000011:"Dreki", 1300000012:"Poring",
}

GENDER_MAP = {0: "None", 1: "Male", 2: "Female"}
LANGUAGE_MAP = {0: "None", 1: "English", 2: "Chinese (Simplified)", 3: "Chinese (Traditional)",
                4: "Thai", 5: "Vietnamese", 6: "Indonesian", 7: "Portuguese",
                8: "Spanish", 9: "Russian", 10: "Korean", 11: "French",
                12: "German", 13: "Turkish", 14: "Hindi", 15: "Japanese"}
MODE_PREFER_MAP = {0: "None", 1: "BR", 2: "CS", 3: "Entertainment"}
RANK_SHOW_MAP = {0: "None", 1: "BR", 2: "CS"}
VETERAN_MAP = {0: "None", 1: "Short", 2: "Normal", 3: "Long", 4: "Very Long"}
TIME_ONLINE_MAP = {0: "None", 1: "Workday", 2: "Weekend"}
TIME_ACTIVE_MAP = {0: "None", 1: "Morning", 2: "Afternoon", 3: "Night"}


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


def humanize_ago(ts):
    if not ts or not isinstance(ts, int):
        return None
    try:
        diff = int(time.time()) - ts
        if diff < 0:
            return "in the future"
        if diff < 60:
            return "just now"
        days = diff // 86400
        hrs = (diff % 86400) // 3600
        mins = (diff % 3600) // 60
        parts = []
        if days:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hrs:
            parts.append(f"{hrs} hr")
        if mins and not days:
            parts.append(f"{mins} min")
        return (" ".join(parts) + " ago") if parts else "just now"
    except Exception:
        return None


def build_report(resp):
    p = g(resp, 1) or {}

    uid        = g(p, 1)
    nickname   = g(p, 3, "Unknown")
    external_id = g(p, 4)
    region     = g(p, 5, "?")
    level      = g(p, 6, 0)
    exp        = g(p, 7, 0)
    banner_id  = g(p, 11, 0)
    head_pic   = g(p, 12, 0)
    clan_name  = g(p, 13)
    prime_level = g(p, 14, 0)
    br_points  = g(p, 15, 0)
    bp_badges  = g(p, 18, 0)
    badge_id   = g(p, 19, 0)
    season_id  = g(p, 20, 0)
    likes      = g(p, 21, 0)
    show_rank  = g(p, 23, 1)
    created_at = g(p, 24, 0)
    cs_blk     = g(g(p, 61, {}), 3, {})
    cs_pts     = cs_blk.get('3', 0) if isinstance(cs_blk, dict) else 0
    cs_stars   = cs_blk.get('4', 0) if isinstance(cs_blk, dict) else 0
    cs_rank    = g(p, 30, 0)
    cs_rank_pts = g(p, 36, 0)
    release_ver = g(p, 50, "?")
    clan_id    = g(p, 53, 0)
    weapon_skins = g(p, 32)
    pin_id     = g(p, 33, 0)
    title_id   = g(p, 48, 0)
    veteran_tag = g(p, 66, 0)
    last_login = g(p, 44, 0)

    bio_hex = g(g(g(p, 9, {}), 9, {}), 12, "")
    bio = decode_hex(bio_hex) or "(empty)"

    social = g(p, 9, {}) or {}
    social_9 = g(social, 9, {}) or {}
    gender_id = g(social_9, 2, 0)
    language_id = g(social_9, 3, 0)
    time_online_id = g(social_9, 4, 0)
    time_active_id = g(social_9, 5, 0)
    battle_tags = g(social_9, 6)
    social_tags = g(social_9, 7)
    mode_prefer_id = g(social_9, 8, 0)
    rank_show_id = g(social_9, 10, 0)

    gender_str = GENDER_MAP.get(gender_id, "Unknown")
    language_str = LANGUAGE_MAP.get(language_id, "Unknown")
    mode_prefer_str = MODE_PREFER_MAP.get(mode_prefer_id, "None")
    rank_show_str = RANK_SHOW_MAP.get(rank_show_id, "None")
    veteran_str = VETERAN_MAP.get(veteran_tag, "None")

    credit_blk = g(p, 11, {}) or g(resp, 11, {}) or {}
    if isinstance(credit_blk, dict):
        credit_score = g(credit_blk, 1, 0)
        weekly_matches = g(credit_blk, 6, 0)
    else:
        credit_score = 0
        weekly_matches = 0

    bp_t = g(g(p, 63, {}), 1, {})
    if isinstance(bp_t, dict):
        bp_event_id = bp_t.get('1') or bp_t.get(1)
        bp_owned = bp_t.get('2') or bp_t.get(2)
        bp_badge = bp_t.get('3') or bp_t.get(3)
        bp_badge_count = bp_t.get('4') or bp_t.get(4)
        bp_icon = bp_t.get('5') or bp_t.get(5)
        bp_max_level = bp_t.get('6') or bp_t.get(6)
        bp_name = bp_t.get('7') or bp_t.get(7)
    else:
        bp_event_id = bp_owned = bp_badge = bp_badge_count = bp_icon = bp_max_level = 0
        bp_name = "Basic"

    bp_label = "Premium" if bp_owned else "Free"

    pet_out = None
    pet_blk = g(resp, 8, {}) or g(p, 8, {})
    if isinstance(pet_blk, dict) and pet_blk:
        pid = pet_blk.get('1') or pet_blk.get(1)
        pet_out = {
            "id": pid,
            "name": pet_blk.get('2') or pet_blk.get(2) or pet_name(pid),
            "level": pet_blk.get('3') or pet_blk.get(3),
            "exp": pet_blk.get('4') or pet_blk.get(4),
            "is_selected": bool(pet_blk.get('5') or pet_blk.get(5)),
            "skin_id": pet_blk.get('6') or pet_blk.get(6),
            "selected_skill_id": pet_blk.get('9') or pet_blk.get(9),
        }

    clan_out = None
    c = g(resp, 6, {}) or g(p, 6, {})
    L = g(resp, 7, {}) or g(p, 7, {})
    if isinstance(c, dict) and c:
        clan_out = {
            "id": c.get('1') or c.get(1),
            "name": c.get('2') or c.get(2),
            "captain_id": c.get('3') or c.get(3),
            "level": c.get('4') or c.get(4),
            "capacity": c.get('5') or c.get(5),
            "member_num": c.get('6') or c.get(6),
            "honor_point": c.get('7') or c.get(7),
        }
        if isinstance(L, dict) and L:
            clan_out["leader"] = {
                "name": L.get('3') or L.get(3),
                "uid": L.get('1') or L.get(1),
                "level": L.get('6') or L.get(6),
                "exp": L.get('7') or L.get(7),
                "region": L.get('5') or L.get(5),
                "prime_level": L.get('14') or L.get(14),
                "created_at": L.get('24') or L.get(24),
                "last_login": L.get('44') or L.get(44),
                "release_version": L.get('50') or L.get(50),
            }

    rank_blk = g(p, 49, {})
    show_br_rank = g(rank_blk, 2, 0) if isinstance(rank_blk, dict) else 0
    show_cs_rank = g(rank_blk, 3, 0) if isinstance(rank_blk, dict) else 0

    craftland = None
    try:
        f41 = g(p, 41, {})
        if isinstance(f41, dict):
            f9 = f41.get('9') or f41.get(9)
            if isinstance(f9, dict):
                craftland = f9.get('25') or f9.get(25)
    except Exception:
        pass

    profile = g(resp, 2, {}) or g(p, 2, {})
    equipped = None
    if isinstance(profile, dict) and profile:
        equipped = {
            "avatar_id": profile.get('1') or profile.get(1),
            "clothes": profile.get('4') or profile.get(4),
            "equipped_skills": profile.get('5') or profile.get(5),
            "top": profile.get('14') or profile.get(14),
            "bottom": profile.get('15') or profile.get(15),
            "mask": profile.get('16') or profile.get(16),
            "facepaint": profile.get('17') or profile.get(17),
            "shoes": profile.get('18') or profile.get(18),
        }

    ach_blk = g(resp, 13) or g(p, 13)
    achievements = []
    if isinstance(ach_blk, list):
        for a in ach_blk:
            if isinstance(a, dict):
                achievements.append({
                    "id": a.get('1') or a.get(1),
                    "level": a.get('2') or a.get(2),
                })

    # ===== SWAPPED: created_at ↔ last_login =====
    return {
        "basic": {
            "uid": uid,
            "nickname": nickname,
            "region": region,
            "level": level,
            "exp": exp,
            "prime_level": prime_level,
            "likes": likes,
            # SWAPPED — "created_at" now shows last_login value
            "created_at": fmt_ts(last_login),
            "created_ago": humanize_ago(last_login),
            # SWAPPED — "last_login" now shows created_at value
            "last_login": fmt_ts(created_at),
            "last_login_ago": humanize_ago(created_at),
            "season": release_ver,
            "external_id": external_id,
            "title": title_id or "Not Equipped",
            "signature": bio,
        },
        "ranks": {
            "br_points": br_points,
            "br_rank": br_rank_name(br_points),
            "cs_points": cs_pts,
            "cs_rank": cs_rank_name(cs_pts),
            "cs_stars": cs_stars,
            "show_br": bool(show_br_rank),
            "show_cs": bool(show_cs_rank),
            "show_rank": rank_show_str,
        },
        "social": {
            "gender": gender_str,
            "language": language_str,
            "mode_prefer": mode_prefer_str,
            "time_online": TIME_ONLINE_MAP.get(time_online_id, "None"),
            "time_active": TIME_ACTIVE_MAP.get(time_active_id, "None"),
            "battle_tags": battle_tags if battle_tags else [],
            "social_tags": social_tags if social_tags else [],
        },
        "credit": {
            "credit_score": credit_score,
            "weekly_matches": weekly_matches,
        },
        "booyah_pass": {
            "type": bp_label,
            "event_name": bp_name,
            "event_id": bp_event_id,
            "owned": bool(bp_owned),
            "badge": bp_badge,
            "badge_count": bp_badge_count,
            "max_level": bp_max_level,
        },
        "cosmetics": {
            "banner_id": banner_id,
            "avatar_id": head_pic,
            "badge_id": badge_id,
            "pin_id": pin_id,
            "weapon_skins": weapon_skins,
            "veteran_tag": veteran_str,
            "season_id": season_id,
            "bp_badges": bp_badges,
        },
        "equipped": equipped,
        "pet": pet_out,
        "clan": clan_out,
        "craftland_map": craftland,
        "achievements": achievements,
    }


@app.route('/get', methods=['GET'])
def get_info():
    uid_in = (request.args.get('info') or request.args.get('uid') or '').strip()

    if not uid_in or not uid_in.isdigit():
        return jsonify({
            "success": False,
            "error": "info (numeric account_id) required",
            "example": "/get?info=7033908403",
            "premium": {"credit": CREDIT, "message": "Premium API by @os_codex"}
        }), 400

    aid = int(uid_in)
    log("GET", f"uid={aid} (auto-region)")

    resp, used_uid, used_region, err = fetch_player_auto(aid)

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
        "detected_region": used_region or "?",
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
                results.setdefault(reg, []).append(acc['uid'])
    return jsonify({"success": True, "regions": results, "credit": CREDIT})


@app.route('/regions', methods=['GET'])
def regions_info():
    cached = load_cache()
    out = {}
    for c in cached:
        r = c.get("region", "?")
        out[r] = out.get(r, 0) + 1
    return jsonify({
        "success": True,
        "cached_tokens_by_region": out,
        "total_cached": len(cached),
        "endpoint": "/get?info={uid}",
        "credit": CREDIT,
    })


@app.route('/')
def home():
    return jsonify({
        "name": "Advanced Player Info API",
        "endpoint": "/get?info={account_id}",
        "example": "/get?info=7033908403",
        "note": "Auto-detects region — no need to specify",
        "credit": CREDIT,
    })


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("   ADVANCED PLAYER INFO API")
    print("=" * 60)
    total = sum(len(v) for v in ACCOUNTS.values())
    print(f"   Regions   : {len(ACCOUNTS)}")
    print(f"   Accounts  : {total}")
    print(f"   Endpoint  : /get?info={{uid}}  (auto-region)")
    print(f"   Credit    : {CREDIT}")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
