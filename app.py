from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import json
import requests
from flask import Flask, jsonify, request
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from data_pb2 import AccountPersonalShowInfo
import uid_generator_pb2
import GetWishListItems_pb2

# ------------------ Logging ------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.json.ensure_ascii = False          # ⬅️ print real Unicode names (SʏɴᴛᴀxX࿗࿌)

# ------------------ File Loading ------------------
BASE_DIR = Path(__file__).parent

def _load_json(name, default):
    path = BASE_DIR / name
    if not path.exists():
        logger.warning(f"[FILE] {name} not found — using empty {type(default).__name__}")
        return default
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[FILE] Failed to load {name}: {e}")
        return default

RAW_TOKENS = _load_json("token.json", [])
RAW_ACCOUNTS = _load_json("accounts.json", {})

REGION_TOKENS = {}
for t in RAW_TOKENS:
    r = (t.get("region") or t.get("expected_region") or "").upper()
    if r and t.get("token"):
        REGION_TOKENS.setdefault(r, []).append(t)

ACCOUNTS = {k.upper(): v for k, v in RAW_ACCOUNTS.items()}
QUERY_REGIONS = sorted(set(REGION_TOKENS.keys()) | set(ACCOUNTS.keys()))

logger.info(f"[BOOT] Loaded {sum(len(v) for v in REGION_TOKENS.values())} tokens across {list(REGION_TOKENS.keys())}")
logger.info(f"[BOOT] Loaded accounts for {list(ACCOUNTS.keys())}")
logger.info(f"[BOOT] Query regions: {QUERY_REGIONS}")


# ------------------ HTTP Session ------------------
def create_http_session():
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.4,
                  status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET", "POST"])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

http_session = create_http_session()


# ------------------ Token Refresh API ------------------
TOKEN_API_BASE = "https://ff-jwt-gen-api.lovable.app/api/public/token"
JWT_TTL = 600

jwt_cache  = {}
jwt_expiry = {}
jwt_lock   = threading.Lock()


def _fetch_token_live(uid, password):
    try:
        r = http_session.get(TOKEN_API_BASE,
                             params={"uid": uid, "password": password},
                             timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("success") and d.get("token"):
            return d["token"]
    except Exception as e:
        logger.warning(f"[TOKEN-FETCH] {uid}: {e}")
    return None


def get_token_for_region(region):
    now = time.time()

    if region in jwt_cache and now < jwt_expiry.get(region, 0):
        return jwt_cache[region]

    with jwt_lock:
        if region in jwt_cache and now < jwt_expiry.get(region, 0):
            return jwt_cache[region]

        best_tok, best_exp = None, 0
        for entry in REGION_TOKENS.get(region, []):
            exp = entry.get("expires_at", 0)
            if exp > now and exp > best_exp:
                best_tok, best_exp = entry["token"], exp

        if best_tok:
            jwt_cache[region] = best_tok
            jwt_expiry[region] = best_exp
            logger.info(f"[TOKEN] {region} ← token.json (valid {int(best_exp-now)}s)")
            return best_tok

        for cred in ACCOUNTS.get(region, []):
            tok = _fetch_token_live(cred["uid"], cred["password"])
            if tok:
                jwt_cache[region] = tok
                jwt_expiry[region] = now + JWT_TTL
                logger.info(f"[TOKEN] {region} ← fresh fetch (uid={cred['uid']})")
                return tok

        logger.error(f"[TOKEN] No valid token for {region}")
        return None


# ------------------ Endpoint Mapping ------------------
REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "IN":  "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "US":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "NA":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "BR":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SAC": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SG":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "BP":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "BD":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "ID":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "PK":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "VN":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "ME":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "TH":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "TW":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "CIS": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
}


def build_endpoint(region, method="GetPlayerPersonalShow"):
    base = REGION_URLS.get(region, "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo")
    return base.replace("UpdateSocialBasicInfo", method)


# ------------------ Protobuf + AES ------------------
def proto_to_dict(message):
    result = {}
    for field in getattr(message.DESCRIPTOR, 'fields', []):
        value = getattr(message, field.name)
        val_type = type(value).__name__

        if 'MapContainer' in val_type:
            result[field.name] = {
                k: (proto_to_dict(v) if hasattr(v, 'DESCRIPTOR')
                    else binascii.hexlify(v).decode() if isinstance(v, bytes) else v)
                for k, v in value.items()
            }
        elif 'Repeated' in val_type:
            result[field.name] = [
                proto_to_dict(i) if hasattr(i, 'DESCRIPTOR')
                else binascii.hexlify(i).decode() if isinstance(i, bytes) else i
                for i in value
            ]
        elif hasattr(value, 'DESCRIPTOR'):
            result[field.name] = proto_to_dict(value)
        elif getattr(field, 'type', None) == 14:
            try:
                result[field.name] = field.enum_type.values_by_number[value].name
            except Exception:
                result[field.name] = value
        elif isinstance(value, bytes):
            result[field.name] = binascii.hexlify(value).decode() if value else ""
        else:
            result[field.name] = value
    return result


default_key = "Yg&tc%DEuh6%Zc^8"
default_iv  = "6oyZDr22E3ychjM%"


def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv  = iv.encode()[:16]
    return binascii.hexlify(
        AES.new(key, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(hex_data), AES.block_size))
    ).decode()


def direct_ff_call(encrypted_hex, region, method="GetPlayerPersonalShow"):
    token = get_token_for_region(region)
    if not token:
        raise Exception(f"No token for {region}")

    url = build_endpoint(region, method)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB55',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    r = http_session.post(url, headers=headers,
                          data=bytes.fromhex(encrypted_hex), timeout=10)
    r.raise_for_status()
    return r.content


# ------------------ Multi-Region Lookup ------------------
def _try_region(uid_encrypted, region):
    try:
        raw = direct_ff_call(uid_encrypted, region, "GetPlayerPersonalShow")
        msg = AccountPersonalShowInfo()
        msg.ParseFromString(raw)
        basic = proto_to_dict(msg).get("basic_info") or {}
        if basic.get("account_id"):
            return basic
    except Exception as e:
        logger.debug(f"[INFO] {region}: {e}")
    return None


def lookup_all_regions(uid):
    m = uid_generator_pb2.uid_generator()
    m.saturn_ = int(uid)
    m.garena = 1
    enc = encrypt_aes(binascii.hexlify(m.SerializeToString()).decode(),
                      default_key, default_iv)

    with ThreadPoolExecutor(max_workers=len(QUERY_REGIONS) or 1) as executor:
        futures = {executor.submit(_try_region, enc, r): r for r in QUERY_REGIONS}
        for fut in as_completed(futures):
            try:
                basic = fut.result()
                if basic:
                    for f in futures:
                        f.cancel()
                    return basic
            except Exception:
                pass
    return None


# ------------------ Flask Routes ------------------
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "version": "OB55",
        "query_regions": QUERY_REGIONS,
        "tokens_loaded": {r: len(v) for r, v in REGION_TOKENS.items()},
        "accounts_loaded": {r: len(v) for r, v in ACCOUNTS.items()},
        "endpoints": {
            "info": "/info?uid={uid}",
            "wishlist": "/wishlist?uid={uid}&region=BD",
            "accounts": "/accounts",
        },
    })


@app.route('/accounts', methods=['GET'])
def list_accounts():
    """
    Print every loaded account.
    Passwords are masked (first 6 + … + last 4 chars).
    Use ?show=1 to reveal full passwords.
    """
    show_passwords = request.args.get('show') == '1'

    def mask(pwd):
        if not pwd:
            return ""
        if show_passwords or len(pwd) <= 10:
            return pwd
        return f"{pwd[:6]}…{pwd[-4:]}"

    # Group tokens (unique per region) alongside accounts
    result = {}
    for region in QUERY_REGIONS:
        result[region] = {
            "tokens": [
                {
                    "uid": t.get("uid"),
                    "expires_at": t.get("expires_at"),
                    "valid": time.time() < t.get("expires_at", 0),
                    "token_preview": (t.get("token", "")[:20] + "…") if t.get("token") else None,
                }
                for t in REGION_TOKENS.get(region, [])
            ],
            "accounts": [
                {"uid": a.get("uid"), "password": mask(a.get("password", ""))}
                for a in ACCOUNTS.get(region, [])
            ],
            "cached_token": bool(jwt_cache.get(region)),
        }

    total_tokens = sum(len(v) for v in REGION_TOKENS.values())
    total_accounts = sum(len(v) for v in ACCOUNTS.values())

    return jsonify({
        "version": "OB55",
        "total_tokens": total_tokens,
        "total_accounts": total_accounts,
        "password_visible": show_passwords,
        "regions": result,
    })


@app.route('/info', methods=['GET'])
def info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "UID parameter is required"}), 400
    try:
        uid_int = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400

    try:
        basic = lookup_all_regions(uid_int)
    except Exception as e:
        logger.error(f"[INFO] {e}")
        return jsonify({"error": str(e)}), 500

    if not basic:
        return jsonify({"error": f"Player {uid_int} not found in any region"}), 404

    return jsonify({
        "account_id": basic.get("account_id"),
        "level":      basic.get("level"),
        "region":     basic.get("region"),
        "name":       basic.get("nickname"),
    })


@app.route('/wishlist', methods=['GET'])
def wishlist():
    uid = request.args.get('uid')
    region = request.args.get('region', 'BD').upper()
    if not uid:
        return jsonify({"error": "UID parameter is required"}), 400
    if region not in QUERY_REGIONS:
        return jsonify({"error": f"Unsupported region. Choose from {QUERY_REGIONS}"}), 400
    try:
        uid_int = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400

    try:
        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = uid_int
        enc = encrypt_aes(binascii.hexlify(req.SerializeToString()).decode(),
                          default_key, default_iv)
        raw = direct_ff_call(enc, region, method="GetWishListItems")
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(raw)
        return jsonify(proto_to_dict(res))
    except Exception as e:
        logger.error(f"[WISHLIST] {region}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/favicon.ico')
def favicon():
    return '', 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, threaded=True)
