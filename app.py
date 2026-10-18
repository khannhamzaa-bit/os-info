from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from data_pb2 import AccountPersonalShowInfo
import uid_generator_pb2
import GetWishListItems_pb2

# ------------------ Logging ------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

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

# ============================================================
# TOKEN API
# ============================================================
TOKEN_API_BASE = "https://ff-jwt-gen-api.lovable.app/api/public/token"


def fetch_token(uid, password):
    try:
        r = http_session.get(TOKEN_API_BASE,
                             params={"uid": uid, "password": password},
                             timeout=10)
        if r.status_code != 200:
            logger.warning(f"[TOKEN] HTTP {r.status_code} for {uid}")
            return None
        data = r.json()
        if data.get("success") and data.get("token"):
            return data["token"]
        logger.warning(f"[TOKEN] Bad response for {uid}: {data}")
        return None
    except Exception as e:
        logger.warning(f"[TOKEN] Request failed for {uid}: {e}")
        return None


# ============================================================
# REGION URLS  (your mapping + ggpolarbear extensions)
# ============================================================
REGION_URLS = {
    # ---- Your mapping (unchanged) ----
    "IND": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "IN":  "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "US":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "NA":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "BR":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SAC": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SG":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "BP":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",

    # ---- Added for accounts we already have (ggpolarbear cluster) ----
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
    """Take region's REGION_URLS entry and swap method name."""
    base = REGION_URLS.get(region)
    if not base:
        base = "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo"
    return base.replace("UpdateSocialBasicInfo", method)


# ============================================================
# REGION ACCOUNTS  (we query only regions we have creds for)
# ============================================================
REGION_ACCOUNTS = {
    "BD":  {"uid": "8063692016",
            "password": "0D15656349D81510A007CCA7C63AD6D3D7D34D816012686DB9042A266A96A457"},
    "IND": {"uid": "4520536411",
            "password": "B31452B326F2A4C919BEDF5D119AC884043BAAE8BFE168A6CB7C6B4CE7C6A0FD"},
    "ME":  {"uid": "8304690996",
            "password": "6CC453C9E0D37D33DC16861DCACC675C8726D017950E11B693A656770D7F88C8"},
    "ID":  {"uid": "8304693210",
            "password": "B125B2DDEF5B9C827C014DA5F4BA548E6281EEFDBA8B51708818CD00CDAC52C8"},
    "VN":  {"uid": "8304696053",
            "password": "12C4AD1C68022FD05227743AA5B0FA69797E68244FCC7DD6DF213909867B3BA1"},
    "TH":  {"uid": "8304697462",
            "password": "987282103FA98575AAE2218D7D2DCB1CA0452EE1DD2A39EE4B2440C89A9AE216"},
    "PK":  {"uid": "8304710694",
            "password": "7D1232078446A16BB168B02ECD2BF0E30B472547C84A1719BAF5D9B49E3BDF60"},
    "TW":  {"uid": "8304716792",
            "password": "B66C4C83F8D07C040142577312428BF4510E6D7659026125E858D9914998B21C"},
    "CIS": {"uid": "8304718687",
            "password": "C7D64DD09683C88FFD459B3D9B1FC351155EDE47C09D3B5111772AC75491DE35"},
    "NA":  {"uid": "7642807933",
            "password": "HAMZA-_ODSJ"},
}

QUERY_REGIONS = list(REGION_ACCOUNTS.keys())


# ============================================================
# JWT CACHE
# ============================================================
jwt_cache  = {}
jwt_expiry = {}
jwt_lock   = threading.Lock()
JWT_TTL    = 600


def get_jwt(region):
    now = time.time()
    if region in jwt_cache and now < jwt_expiry.get(region, 0):
        return jwt_cache[region]

    with jwt_lock:
        if region in jwt_cache and now < jwt_expiry.get(region, 0):
            return jwt_cache[region]

        acct = REGION_ACCOUNTS.get(region)
        if not acct:
            logger.error(f"[JWT] No account for {region}")
            return None

        tok = fetch_token(acct["uid"], acct["password"])
        if tok:
            jwt_cache[region] = tok
            jwt_expiry[region] = now + JWT_TTL
            logger.info(f"[JWT] {region} cached (uid={acct['uid']})")
            return tok

        logger.error(f"[JWT] No token for {region}")
        return None


# ============================================================
# PROTOBUF
# ============================================================
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
    token = get_jwt(region)
    if not token:
        raise Exception(f"No JWT for {region}")

    url = build_endpoint(region, method)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    r = http_session.post(url, headers=headers,
                          data=bytes.fromhex(encrypted_hex), timeout=10)
    r.raise_for_status()
    return r.content


# ============================================================
# MULTI-REGION LOOKUP
# ============================================================
def _try_region_info(uid_encrypted, region):
    try:
        raw = direct_ff_call(uid_encrypted, region, "GetPlayerPersonalShow")
        msg = AccountPersonalShowInfo()
        msg.ParseFromString(raw)
        basic = proto_to_dict(msg).get("basic_info") or {}
        if basic.get("account_id"):
            return basic
    except Exception as e:
        logger.debug(f"[INFO] {region} failed: {e}")
    return None


def lookup_all_regions(uid):
    m = uid_generator_pb2.uid_generator()
    m.saturn_ = int(uid)
    m.garena = 1
    enc = encrypt_aes(binascii.hexlify(m.SerializeToString()).decode(),
                      default_key, default_iv)

    with ThreadPoolExecutor(max_workers=len(QUERY_REGIONS)) as executor:
        futures = {executor.submit(_try_region_info, enc, r): r for r in QUERY_REGIONS}
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


# ============================================================
# FLASK ROUTES
# ============================================================
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "token_api": TOKEN_API_BASE,
        "query_regions": QUERY_REGIONS,
        "region_endpoints": {r: REGION_URLS[r] for r in REGION_URLS},
        "endpoints": {
            "info": "/info?uid={uid}",
            "wishlist": "/wishlist?uid={uid}&region=BD",
        },
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
        logger.error(f"[INFO] lookup failed: {e}")
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
        logger.error(f"[WISHLIST] {region} failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/favicon.ico')
def favicon():
    return '', 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, threaded=True)
