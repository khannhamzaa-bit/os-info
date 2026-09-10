import json, os, time, base64, sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JWT_API = "https://ff-jwt-gen-api.lovable.app/api/public/token?uid={uid}&password={password}"
ACCOUNTS_FILE = "accounts.json"
OUT_FILE = "token.json"
TIMEOUT = 20

def jwt_payload(tok):
    try:
        s = tok.split('.')[1]
        s += '=' * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return {}

def fetch_one(acc, region):
    url = JWT_API.format(uid=acc["uid"], password=acc["password"])
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        if r.status_code != 200:
            d = ""
            try:
                j = r.json()
                d = j.get("message") or j.get("detail") or ""
            except Exception:
                d = r.text[:60]
            print(f"  ✗ [{region}] {acc['uid']}  HTTP {r.status_code}  {d.strip()}")
            return None
        data = r.json()
        tok = data.get("token")
        if not tok:
            print(f"  ✗ [{region}] {acc['uid']}  no token")
            return None
        p = jwt_payload(tok)
        reg = (p.get("noti_region") or p.get("country_code") or region).upper()
        exp = int(p.get("exp") or 0)
        print(f"  ✓ [{region}] {acc['uid']}  region={reg}  exp={exp}")
        return {
            "token": tok,
            "region": reg,
            "uid": acc["uid"],
            "saved_at": int(time.time()),
            "expires_at": exp,
            "expected_region": region,
        }
    except Exception as e:
        print(f"  ✗ [{region}] {acc['uid']}  {type(e).__name__}: {str(e)[:80]}")
        return None

def load_existing():
    if not os.path.exists(OUT_FILE):
        return []
    try:
        with open(OUT_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []

def main():
    try:
        with open(ACCOUNTS_FILE) as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load accounts.json: {e}")
        sys.exit(1)

    total = sum(len(v) for v in accounts.values())
    print(f"Refreshing {total} account(s) across {len(accounts)} region(s)...")

    results = []
    for region, pool in accounts.items():
        print(f"\n── Region: {region} ({len(pool)} accounts)")
        for acc in pool:
            e = fetch_one(acc, region)
            if e:
                results.append(e)

    print(f"\n{'=' * 50}")
    print(f"Success: {len(results)}/{total}")

    if not results:
        existing = load_existing()
        now = int(time.time())
        valid = [e for e in existing if isinstance(e, dict)
                 and int(e.get("expires_at") or 0) > now + 600]
        if valid:
            print(f"⚠️  Keeping {len(valid)} cached token(s)")
            sys.exit(0)
        print("❌ No tokens — check credentials")
        sys.exit(1)

    existing = load_existing()
    now = int(time.time())
    merged = {e["uid"]: e for e in existing
              if isinstance(e, dict) and e.get("uid")
              and int(e.get("expires_at") or 0) > now + 600}
    for r in results:
        merged[r["uid"]] = r

    final = list(merged.values())
    with open(OUT_FILE, "w") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)
    print(f"✅ Wrote {OUT_FILE} ({len(final)} total)")

if __name__ == "__main__":
    main()
