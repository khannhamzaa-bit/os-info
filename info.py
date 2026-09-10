import sys, json, os, time, base64, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JWT_API = "https://ff-jwt-gen-api.lovable.app/api/public/token?uid={uid}&password={password}"
ACCOUNTS_FILE = "accounts.json"
TOKEN_FILE = "token.json"
CREDIT = "https://t.me/os_codex"

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

REGION_HOSTS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BD":  "https://client.bd.freefiremobile.com",
    "BR":  "https://client.br.freefiremobile.com",
    "US":  "https://client.us.freefiremobile.com",
    "NA":  "https://client.na.freefiremobile.com",
    "ID":  "https://client.id.freefiremobile.com",
    "VN":  "https://client.vn.freefiremobile.com",
    "SG":  "https://client.sg.freefiremobile.com",
    "TH":  "https://client.th.freefiremobile.com",
    "ME":  "https://client.me.freefiremobile.com",
    "PK":  "https://client.pk.freefiremobile.com",
    "EG":  "https://client.eg.freefiremobile.com",
    "RU":  "https://client.ru.freefiremobile.com",
    "MY":  "https://client.my.freefiremobile.com",
    "PH":  "https://client.ph.freefiremobile.com",
}
DEFAULT_HOST = "https://client.ind.freefiremobile.com"

SESSION = requests.Session()
SESSION.verify = False
SESSION.mount("http://", requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50))
SESSION.mount("https://", requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50))
TIMEOUT = 15

def load_accounts():
    try:
        with open(ACCOUNTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load {ACCOUNTS_FILE}: {e}")
        sys.exit(1)

ACCOUNTS = load_accounts()

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
        e = {"token": tok, "region": region, "uid": uid,
             "saved_at": int(time.time()), "expires_at": jwt_exp(tok)}
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
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        if r.status_code != 200:
            d = ""
            try:
                j = r.json()
                d = j.get("message") or j.get("detail") or ""
            except Exception:
                d = r.text[:60]
            return None, None, f"HTTP {r.status_code} {d}".strip()
        data = r.json()
        tok = data.get("token")
        if not tok:
            return None, None, "no token"
        reg = jwt_region(tok)
        save_cache(tok, reg, acc['uid'])
        return tok, reg, None
    except Exception as e:
        return None, None, str(e)[:60]

def acquire_token(region):
    region = region.upper()
    for c in load_cache():
        if c['region'] == region:
            return c['token'], c['region'], c['uid'], "cache", None

    pool = ACCOUNTS.get(region, [])
    if not pool:
        return None, None, None, "fail", f"no accounts for {region}"

    last = "no accounts"
    for i, acc in enumerate(pool, 1):
        print(f"  [{i}/{len(pool)}] trying {acc['uid']}...")
        tok, reg, err = fetch_token(acc)
        if tok:
            return tok, reg, acc['uid'], "api", None
        print(f"      ❌ {err}")
        last = err

    print(f"  cross-region fallback...")
    for r, pool in ACCOUNTS.items():
        if r == region:
            continue
        for acc in pool:
            tok, reg, err = fetch_token(acc)
            if tok:
                return tok, reg, acc['uid'], "cross_region", None
    return None, None, None, "fail", last

def fetch_player(jwt, aid, region):
    host = REGION_HOSTS.get(region, DEFAULT_HOST)
    try:
        body = enc(fi(1, aid) + fi(2, 1))
        h = {
            "Authorization": f"Bearer {jwt}",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "X-Unity-Version": "2022.3.47f1",
            "Accept": "*/*",
            "Accept-Encoding": "deflate, gzip",
        }
        r = SESSION.post(f"{host}/GetPlayerPersonalShow", headers=h, data=body, timeout=TIMEOUT)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return parse_resp(r.content), None
    except Exception as e:
        return None, str(e)[:80]

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
        return time.strftime("%d %B %Y at %I:%M:%S %p (IST)", time.gmtime(ts))
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
            "equipped": True,
            "id": pid,
            "name": pet_name(pid),
            "type": pet_name(pid),
            "level": pet_blk.get('3') or pet_blk.get(3),
            "exp": pet_blk.get('4') or pet_blk.get(4),
            "skin": pet_blk.get('6') or pet_blk.get(6),
            "skill": pet_blk.get('9') or pet_blk.get(9),
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
            cs_l = g(g(L, 61, {}), 3, {})
            cs_l_pts = cs_l.get('3', 0) if isinstance(cs_l, dict) else 0
            l_bp_t = g(g(L, 63, {}), 1, {})
            l_bp_type = l_bp_t.get('1', 0) if isinstance(l_bp_t, dict) else 0
            clan_out["leader"] = {
                "name": L.get('3') or L.get(3),
                "uid": L.get('1') or L.get(1),
                "level": L.get('6') or L.get(6),
                "exp": L.get('7') or L.get(7),
                "region": L.get('5') or L.get(5),
                "ob": L.get('50') or L.get(50),
                "bp": {1: "Free", 2: "Premium", 9: "Basic"}.get(l_bp_type, "Basic"),
                "created": L.get('24') or L.get(24),
                "last_login": L.get('44') or L.get(44),
                "bp_badges": L.get('18') or L.get(18),
                "title": L.get('75') or "Not Found",
                "br_points": L.get('15') or L.get(15),
                "cs_pts": cs_l_pts,
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
            "prime_level": prime,
            "name": name,
            "uid": uid,
            "level": level,
            "exp": exp,
            "region": region,
            "likes": likes,
            "honor_score": honor_score,
            "celebrity": False,
            "title": g(p, 75, "") or "Not Found",
            "signature": bio,
            "gender": gender,
        },
        "activity": {
            "ob": ob,
            "bp": bp_label,
            "bp_badges": bp_badges,
            "br_points": br_points,
            "br_rank": br_rank_name(br_points),
            "cs_points": cs_pts,
            "cs_rank": cs_rank_name(cs_pts),
            "cs_stars": cs_stars,
            "show_rank": show_rank_str,
            "show_br": bool(show_br),
            "show_cs": bool(show_cs),
            "created_at": fmt_ts(created),
            "last_login": fmt_ts(last_login),
        },
        "overview": {
            "avatar_id": g(p, 12, 0),
            "banner_id": g(p, 11, 0),
            "pin": "Not Found",
            "language": "English",
        },
        "pet": pet_out,
        "clan": clan_out,
        "craftland": craftland,
    }

def show(rep, used_uid=None, source=None):
    b = rep["basic"]
    a = rep["activity"]
    o = rep["overview"]

    print("\n" + "=" * 64)
    print(" Account Information:")
    print("┌ Basic Information:")
    print(f"├─ Prime Level: {b['prime_level']}")
    print(f"├─ Name: {b['name']}")
    print(f"├─ UID: {b['uid']}")
    print(f"├─ Level: {b['level']} (Exp: {b['exp']})")
    print(f"├─ Region: {b['region']}")
    print(f"├─ Likes: {b['likes']}")
    print(f"├─ Honor Score: {b['honor_score']}")
    print(f"├─ Celebrity Status: {b['celebrity']}")
    print(f"├─ Title Name: {b['title']}")
    print(f"└─ Signature: {b['signature']}")

    print("\n┌ Activity Information:")
    print(f"├─ Most Recent OB: {a['ob']}")
    print(f"├─ Booyah Pass: {a['bp']}")
    print(f"├─ Current Bp Badges: {a['bp_badges']}")
    print(f"├─ Br Rank: {a['br_rank']} ({a['br_points']})")
    print(f"├─ Cs Rank: {a['cs_rank']} ({a['cs_points']} pts / {a['cs_stars']} star)")
    print(f"├─ Gender: {a['gender']}")
    print(f"├─ Show Rank: {a['show_rank']}")
    print(f"├─ Show Br Rank: {a['show_br']}")
    print(f"├─ Show Cs Rank: {a['show_cs']}")
    print(f"├─ Created At: {a['created_at']}")
    print(f"└─ Last Login: {a['last_login']}")

    print("\n┌ Overview Information:")
    print(f"├─ Avatar ID: {o['avatar_id']}")
    print(f"├─ Banner ID: {o['banner_id']}")
    print(f"├─ Pin Name: {o['pin']}")
    print(f"├─ Language: {o['language']}")
    print(f"├─ Equipped Battle Card Name: Not Equipped")
    print(f"├─ Equipped Gun Name: Not Found")
    print(f"├─ Equipped Animation Name: Not Found")
    print(f"└─ Transform Animation Name: Not Found")

    if rep["pet"]:
        pt = rep["pet"]
        print("\n┌ Pet Details:")
        print(f"├─ Equipped?: Yes")
        print(f"├─ Pet Name: {pt['name']}")
        print(f"├─ Pet Type: {pt['type']}")
        print(f"├─ Pet Exp: {pt['exp']}")
        print(f"└─ Pet Level: {pt['level']}")

    if rep["clan"]:
        c = rep["clan"]
        print("\n┌ Guild Information:")
        print(f"├─ Guild Name: {c['name']}")
        print(f"├─ Guild ID: {c['id']}")
        print(f"├─ Guild Level: {c['level']}")
        print(f"├─ Live Members: {c['members_current']}/{c['members_max']}")
        if "leader" in c:
            L = c["leader"]
            print("└─ Leader Information:")
            print(f"    ├─ Leader Name: {L['name']}")
            print(f"    ├─ Leader UID: {L['uid']}")
            print(f"    ├─ Leader Level: {L['level']} (Exp: {L['exp']})")
            print(f"    ├─ Leader Region: {L['region']}")
            print(f"    ├─ Leader Booyah Pass: {L['bp']}")
            print(f"    ├─ Leader Created At: {L['created']}")
            print(f"    ├─ Leader Last Login: {L['last_login']}")
            print(f"    ├─ Leader Most Recent OB: {L['ob']}")
            print(f"    ├─ Leader Title Name: {L['title']}")
            print(f"    ├─ Leader Current Bp Badges: {L['bp_badges']}")
            print(f"    ├─ Leader Br Rank: {br_rank_name(L['br_points'])} ({L['br_points']})")
            print(f"    └─ Leader Cs Rank: {cs_rank_name(L['cs_pts'])} ({L['cs_pts']} pts)")

    if rep["craftland"]:
        print("\n┌ Public Craftland Maps")
        print(f"#{rep['craftland']}")

    if used_uid:
        print(f"\n  🔑 JWT from: {used_uid} ({source})")
    print(f"  💬 Credit: {CREDIT}")
    print("=" * 64)

def main():
    print("\n" + "=" * 64)
    print("   ADVANCED PLAYER INFO TOOL")
    print("=" * 64)
    print(f"   Regions : {', '.join(ACCOUNTS.keys())}")
    total = sum(len(v) for v in ACCOUNTS.values())
    print(f"   Pool    : {total} accounts")
    print(f"   Credit  : {CREDIT}")
    print("=" * 64)

    aid_in = input("\nEnter Account ID: ").strip()
    if not aid_in.isdigit():
        print("❌ Numeric required.")
        return
    aid = int(aid_in)

    region_in = input(f"Region [{'/'.join(ACCOUNTS.keys())}] (default IND): ").strip().upper() or "IND"
    if region_in not in REGION_HOSTS:
        print(f"❌ Unsupported region. Use: {list(REGION_HOSTS.keys())}")
        return

    print(f"\n🔹 Acquiring JWT for {region_in}...")
    jwt, region, used_uid, source, err = acquire_token(region_in)
    if not jwt:
        print(f"❌ Failed: {err}")
        return
    print(f"   ✅ JWT ready (source={source}, uid={used_uid}, region={region})")

    print(f"\n🔹 Fetching profile for {aid}...")
    resp, ferr = fetch_player(jwt, aid, region)

    if not resp and ferr and 'HTTP 401' in ferr:
        print(f"   ⚠️  401 — refreshing")
        remove_cache(used_uid)
        jwt, region, used_uid, source, err = acquire_token(region_in)
        if jwt:
            resp, ferr = fetch_player(jwt, aid, region)

    if not resp:
        print(f"❌ Failed: {ferr}")
        return

    rep = build_report(resp)
    show(rep, used_uid=used_uid, source=source)

    dump = input("\nShow raw JSON? (y/N): ").strip().lower()
    if dump == 'y':
        print("\n" + "=" * 64)
        print(json.dumps(resp, indent=2, ensure_ascii=False, default=str))
        print("=" * 64)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExited.")
        sys.exit(0)
