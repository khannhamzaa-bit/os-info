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
from google.protobuf.descriptor import FieldDescriptor
import uid_generator_pb2
import GetWishListItems_pb2

# ------------------ Logging Setup ------------------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------ JWT Cache ------------------
jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()

# ------------------ HTTP Session with Retries ------------------
def create_http_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.timeout = (5, 10)
    return session

http_session = create_http_session()

# ------------------ All Regions ------------------
ALL_REGIONS = ["IND", "BR", "US", "SAC", "BD", "ID", "PK", "VN", "ME", "TH"]

# ------------------ Protobuf to Dict ------------------
def proto_to_dict(message):
    result = {}
    for field in getattr(message.DESCRIPTOR, 'fields', []):
        value = getattr(message, field.name)
        val_type = type(value).__name__
        
        if 'MapContainer' in val_type:
            map_result = {}
            for k, v in value.items():
                if hasattr(v, 'DESCRIPTOR'):
                    map_result[k] = proto_to_dict(v)
                elif isinstance(v, bytes):
                    map_result[k] = binascii.hexlify(v).decode('utf-8')
                else:
                    map_result[k] = v
            result[field.name] = map_result
            
        elif 'Repeated' in val_type:
            list_result = []
            for item in value:
                if hasattr(item, 'DESCRIPTOR'):
                    list_result.append(proto_to_dict(item))
                elif isinstance(item, bytes):
                    list_result.append(binascii.hexlify(item).decode('utf-8'))
                else:
                    list_result.append(item)
            result[field.name] = list_result
            
        elif hasattr(value, 'DESCRIPTOR'):
            result[field.name] = proto_to_dict(value)
            
        elif getattr(field, 'type', None) == 14:
            try:
                result[field.name] = field.enum_type.values_by_number[value].name
            except Exception:
                result[field.name] = value
                
        elif isinstance(value, bytes):
            result[field.name] = binascii.hexlify(value).decode('utf-8') if value else ""
            
        else:
            result[field.name] = value
    return result


def extract_token_from_response(data, region):
    if not isinstance(data, dict):
        return None
    for key in ("token", "jwt_token", "access_token", "jwt"):
        if key in data and data[key]:
            return data[key]
    if "data" in data and isinstance(data["data"], dict):
        for key in ("token", "jwt_token", "access_token", "jwt"):
            if key in data["data"] and data["data"][key]:
                return data["data"][key]
    if data.get("success") is True and "token" in data:
        return data["token"]
    return None


def ensure_jwt_token_sync(region):
    global jwt_tokens, jwt_expiry
    current_time = time.time()

    if region.upper() == "DEFAULT":
        region = "default"

    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
        return jwt_tokens[region]

    with jwt_lock:
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
            return jwt_tokens[region]

        logger.info(f"[JWT] Fetching token for {region}...")

        credentials = {
            "IND": {"uid": "6994493475", "password": "1_JAHID_X_EMPIRE_9r0A2xxT"},
            "BR":  {"uid": "4345418798", "password": "JOBAYAR_GK6VJ"},
            "US":  {"uid": "3787481313", "password": "JlOivPeosauV0l9SG6gwK39lH3x2kJkO"},
            "SAC": {"uid": "6994520397", "password": "1_JAHID_X_EMPIRE_quRc2lOr"},
            "BD":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "ID":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "PK":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "VN":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "ME":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "TH":  {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"},
            "default": {"uid": "6994726488", "password": "1_JAHID_X_EMPIRE_yLAicWRP"}
        }

        creds = credentials.get(region, credentials["default"])
        url = (
            f"https://ff-jwt-gen-api.lovable.app/api/public/token"
            f"?uid={creds['uid']}&password={creds['password']}"
        )

        try:
            response = http_session.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            token = extract_token_from_response(data, region)
            if token:
                jwt_tokens[region] = token
                jwt_expiry[region] = current_time + 600
                logger.info(f"[JWT] Token for {region} updated.")
                return token
            else:
                logger.error(f"[JWT] Failed to extract token for {region}: {data}")
        except Exception as e:
            logger.error(f"[JWT] Request error for {region}: {e}")

    return jwt_tokens.get(region)


def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()


def apis(idd, region):
    """Send encrypted request to a specific region."""
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    response = http_session.post(endpoint, headers=headers, data=data, timeout=10)
    response.raise_for_status()
    return response.content.hex()


# ------------------ Multi-Region Auto-Detect ------------------
def _try_region(encrypted_hex, region):
    """Attempt to fetch player info from a single region."""
    try:
        api_response = apis(encrypted_hex, region)
        if not api_response:
            return None
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        result = proto_to_dict(message)
        basic = result.get('basic_info') or {}
        # Player exists only if account_id is present and non-zero
        if basic.get('account_id'):
            return {"region": region, "basic_info": basic, "full": result}
    except Exception as e:
        logger.debug(f"[INFO] Region {region} failed: {e}")
    return None


def get_player_info_all_regions(encrypted_hex):
    """Fire requests to all regions in parallel; return first valid result."""
    with ThreadPoolExecutor(max_workers=len(ALL_REGIONS)) as executor:
        futures = {executor.submit(_try_region, encrypted_hex, r): r for r in ALL_REGIONS}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    # Cancel remaining pending futures
                    for f in futures:
                        f.cancel()
                    return result
            except Exception as e:
                logger.debug(f"[INFO] Future failed: {e}")
    return None


# ------------------ Flask Routes ------------------
@app.route('/', methods=['GET'])
def home():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ARAFAT ACCOUNT INFO</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root { --accent: #00FF94; --bg-dark: #0f172a; --glass: rgba(255,255,255,0.05); --glass-border: rgba(255,255,255,0.1); }
            * { margin:0; padding:0; box-sizing:border-box; }
            body { font-family:'Outfit',sans-serif; background-color:var(--bg-dark);
                background-image: radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%),
                                  radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%),
                                  radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
                color:white; height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center; overflow:hidden; }
            .container { background:var(--glass); backdrop-filter:blur(16px); -webkit-backdrop-filter:blur(16px);
                border:1px solid var(--glass-border); padding:3rem 2rem; border-radius:24px; text-align:center;
                box-shadow:0 25px 50px -12px rgba(0,0,0,0.5); max-width:600px; width:90%; animation:float 6s ease-in-out infinite; }
            h1 { font-size:2.5rem; font-weight:700; margin-bottom:0.5rem;
                background:linear-gradient(to right,#fff,#cbd5e1); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
            .badge { display:inline-flex; align-items:center; gap:8px; background:rgba(0,255,148,0.1);
                border:1px solid rgba(0,255,148,0.2); color:var(--accent); padding:8px 16px; border-radius:100px;
                font-size:0.9rem; font-weight:500; font-family:'JetBrains Mono',monospace; margin-bottom:2rem; }
            .dot { width:8px; height:8px; background-color:var(--accent); border-radius:50%; animation:pulse 2s infinite; }
            .code-box { background:rgba(0,0,0,0.3); border:1px solid var(--glass-border); border-radius:12px;
                padding:1.5rem; margin:0 auto 1rem auto; font-family:'JetBrains Mono',monospace; font-size:0.9rem;
                color:#a5b4fc; cursor:pointer; transition:all 0.3s ease; }
            .code-box:last-of-type { margin-bottom:2.5rem; }
            .code-box:hover { border-color:rgba(255,255,255,0.3); transform:translateY(-2px); }
            .footer-links { display:flex; flex-direction:column; gap:12px; margin-top:1rem; }
            .btn { text-decoration:none; padding:12px 20px; border-radius:12px; font-weight:500;
                transition:all 0.3s ease; display:flex; align-items:center; justify-content:center; gap:10px; }
            .btn-credit { background:rgba(255,255,255,0.03); border:1px solid var(--glass-border); color:#e2e8f0; }
            .btn-credit:hover { background:rgba(255,255,255,0.1); }
            .btn-power { background:linear-gradient(45deg,#4f46e5,#06b6d4); color:white; }
            .btn-power:hover { filter:brightness(1.1); transform:scale(1.02); }
            @keyframes pulse { 0%{transform:scale(0.95); box-shadow:0 0 0 0 rgba(0,255,148,0.7);}
                70%{transform:scale(1); box-shadow:0 0 0 10px rgba(0,255,148,0);}
                100%{transform:scale(0.95); box-shadow:0 0 0 0 rgba(0,255,148,0);} }
            @keyframes float { 0%{transform:translateY(0);} 50%{transform:translateY(-10px);} 100%{transform:translateY(0);} }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Free Fire<br>PLAYER INFO API</h1>
            <div class="badge"><div class="dot"></div>API IS RUNNING</div>
            <div class="code-box" onclick="copyText('/info?uid={uid}')">/info?uid={uid}</div>
            <div class="code-box" onclick="copyText('/wishlist?uid={uid}&region=BD')">/wishlist?uid={uid}&region=BD</div>
            <div class="footer-links">
                <a href="https://t.me/Jahid_x_Empire" target="_blank" class="btn btn-credit">
                    <i class="fab fa-telegram"></i><span>Credit: @arafat_flex</span>
                </a>
                <a href="https://t.me/arafat_source" target="_blank" class="btn btn-power">
                    <i class="fas fa-bolt"></i><span>TELEGRAM CHANNEL: @arafat_flex</span>
                </a>
            </div>
        </div>
        <script>function copyText(t){navigator.clipboard.writeText(t);}</script>
    </body>
    </html>
    """
    return html_content


@app.route('/info', methods=['GET'])
def get_player_info():
    """
    Auto-detects the region and returns only:
      { account_id, level, region, name }
    """
    try:
        uid = request.args.get('uid')
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        # Build encrypted request payload once
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)

        # Try every region in parallel
        found = get_player_info_all_regions(encrypted_hex)

        if not found:
            return jsonify({"error": f"Player {uid} not found in any region"}), 404

        basic = found["basic_info"]
        return jsonify({
            "account_id": basic.get("account_id"),
            "level": basic.get("level"),
            "region": basic.get("region") or found["region"],
            "name": basic.get("nickname")
        })

    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        logger.error(f"[ERROR] Processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500


@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'BD').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)

        base_endpoint = get_api_endpoint(region)
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")

        token = ensure_jwt_token_sync(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = http_session.post(wishlist_url, headers=headers,
                                     data=bytes.fromhex(encrypted_hex), timeout=10)
        response.raise_for_status()
        resp_hex = response.content.hex()

        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(resp_hex))
        return jsonify(proto_to_dict(res))

    except Exception as e:
        logger.error(f"[ERROR] Wishlist request: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/favicon.ico')
def favicon():
    return '', 404


# ------------------ Main ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1080, threaded=True)
