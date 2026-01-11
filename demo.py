import base64
import hashlib
import json
import random
import time
import urllib.parse
import urllib.request
import hmac
import subprocess
from pathlib import Path

# --- Core Protocol Logic (Sans-IO) ---

def gen_nonce():
    """Generate a nonce for Mijia API requests."""
    millis = int(round(time.time() * 1000))
    # Using 8 bytes random for simplicity, matching the original logic roughly
    b = random.randbytes(8)
    part2 = int(millis / 60000)
    # Append the time part
    b += part2.to_bytes(((part2.bit_length() + 7) // 8), "big")
    return base64.b64encode(b).decode("utf-8")

def get_signed_nonce(ssecret, nonce):
    """Sign the nonce with ssecurity."""
    m = hashlib.sha256()
    m.update(base64.b64decode(ssecret))
    m.update(base64.b64decode(nonce))
    return base64.b64encode(m.digest()).decode("utf-8")

def gen_signature(uri, method, signed_nonce, params):
    """Generate the signature for the request."""
    signature_params = [method.upper(), uri]
    # Parameters MUST be sorted by key for signing
    for k in sorted(params.keys()):
        v = params[k]
        signature_params.append(f"{k}={v}")
    signature_params.append(signed_nonce)
    signature_string = "&".join(signature_params)
    return base64.b64encode(hashlib.sha1(signature_string.encode("utf-8")).digest()).decode()

def rc4_openssl(signed_nonce, data_bytes):
    """RC4 encryption/decryption using OpenSSL CLI with 1024-byte drop."""
    key_hex = base64.b64decode(signed_nonce).hex()
    # Prepend 1024 null bytes to discard the first 1024 bytes of keystream
    input_data = b'\x00' * 1024 + data_bytes
    
    cmd = ['openssl', 'enc', '-rc4', '-K', key_hex, '-nosalt', '-nopad']
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=input_data)
    
    if proc.returncode != 0:
        raise Exception(f"OpenSSL error: {stderr.decode()}")
    
    return stdout[1024:]

def prepare_request_params(uri, method, signed_nonce, nonce, params, ssecurity):
    """Prepare request parameters with signatures and RC4 encryption."""
    # Sign parameters first
    params["rc4_hash__"] = gen_signature(uri, method, signed_nonce, params)
    
    # Encrypt all parameter values
    encrypted_params = {}
    for k, v in params.items():
        encrypted_v = rc4_openssl(signed_nonce, v.encode())
        encrypted_params[k] = base64.b64encode(encrypted_v).decode()
    
    # Add final signature and auth data
    encrypted_params.update({
        "signature": gen_signature(uri, method, signed_nonce, encrypted_params),
        "ssecurity": ssecurity,
        "_nonce": nonce,
    })
    return encrypted_params

# --- Mijia API Client ---

class MijiaClient:
    def __init__(self, auth_path=None):
        self.auth_path = Path(auth_path or Path.home() / ".config" / "mijia-api" / "auth.json")
        self.auth_data = {}
        self.load_auth()
        self.base_url = "https://api.mijia.tech/app"

    def load_auth(self):
        if self.auth_path.exists():
            with open(self.auth_path, "r") as f:
                self.auth_data = json.load(f)

    def save_auth(self):
        self.auth_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.auth_path, "w") as f:
            json.dump(self.auth_data, f, indent=2)

    def login(self):
        """Minimal QR Login Flow."""
        if self.auth_data.get("serviceToken"):
            print("Already logged in.")
            return

        # 1. Get initial login URL
        device_id = "".join(random.choices("0123456789abcdef", k=16))
        url = f"https://account.xiaomi.com/pass/serviceLogin?_json=true&sid=mijia&_locale=zh_CN"
        req = urllib.request.Request(url, headers={"User-Agent": "MijiaDemo/1.0"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode().replace("&&&START&&&", ""))
        
        login_url_params = urllib.parse.parse_qs(urllib.parse.urlparse(data["location"]).query)
        login_url_params = {k: v[0] for k, v in login_url_params.items()}
        login_url_params.update({"_qrsize": "240", "_dc": str(int(time.time() * 1000))})
        
        qr_api_url = "https://account.xiaomi.com/longPolling/loginUrl?" + urllib.parse.urlencode(login_url_params)
        with urllib.request.urlopen(qr_api_url) as resp:
            qr_data = json.loads(resp.read().decode().replace("&&&START&&&", ""))
        
        print(f"\nScan this URL with Mijia APP: {qr_data['loginUrl']}\n")
        print("Waiting for login...")
        
        # 2. Poll for login
        while True:
            try:
                with urllib.request.urlopen(qr_data["lp"]) as resp:
                    lp_data = json.loads(resp.read().decode().replace("&&&START&&&", ""))
                    if lp_data.get("code") == 0:
                        self.auth_data.update(lp_data)
                        break
            except Exception:
                pass
            time.sleep(2)
        
        # 3. Get service token
        callback_url = self.auth_data["location"]
        req = urllib.request.Request(callback_url)
        with urllib.request.urlopen(req) as resp:
            cookies = resp.info().get_all("Set-Cookie")
            for cookie in cookies:
                if "serviceToken=" in cookie:
                    self.auth_data["serviceToken"] = cookie.split("serviceToken=")[1].split(";")[0]
                if "cUserId=" in cookie:
                    self.auth_data["cUserId"] = cookie.split("cUserId=")[1].split(";")[0]
        
        self.save_auth()
        print("Login successful.")

    def request(self, uri, data):
        """Make an authenticated request to Mijia API."""
        url = self.base_url + uri
        nonce = gen_nonce()
        signed_nonce = get_signed_nonce(self.auth_data["ssecurity"], nonce)
        
        payload = {"data": json.dumps(data, separators=(',', ':'))}
        final_params = prepare_request_params(uri, "POST", signed_nonce, nonce, payload, self.auth_data["ssecurity"])
        
        body = urllib.parse.urlencode(final_params).encode()
        headers = {
            "User-Agent": "MijiaDemo/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": f"serviceToken={self.auth_data['serviceToken']}; userId={self.auth_data['userId']}; cUserId={self.auth_data['cUserId']}",
            "miot-encrypt-algorithm": "ENCRYPT-RC4"
        }
        
        req = urllib.request.Request(url, data=body, headers=headers)
        with urllib.request.urlopen(req) as resp:
            resp_text = resp.read().decode()
            try:
                # Try clear-text JSON first
                ret_data = json.loads(resp_text)
            except json.JSONDecodeError:
                # If it's not JSON, it's likely encrypted
                decrypted_bytes = rc4_openssl(signed_nonce, base64.b64decode(resp_text))
                ret_data = json.loads(decrypted_bytes.decode('utf-8'))
            
            if ret_data.get("code", 0) != 0:
                raise Exception(f"API Error: {ret_data.get('message', ret_data.get('desc', 'Unknown error'))}")
            return ret_data["result"]

    def get_devices(self):
        """List all devices."""
        # First get homes
        homes = self.request("/v2/homeroom/gethome_merged", {"fg": True, "fetch_share": True})["homelist"]
        all_devices = []
        for home in homes:
            # Simplified device listing
            data = {"home_owner": int(home["uid"]), "home_id": int(home["id"]), "limit": 200}
            resp = self.request("/home/home_device_list", data)
            if resp and "device_info" in resp:
                all_devices.extend(resp["device_info"])
        return all_devices

# --- Demo Main ---

def main():
    client = MijiaClient()
    client.login()
    
    print("Fetching devices...")
    devices = client.get_devices()
    
    speakers = [d for d in devices if "wifispeaker" in d.get("model", "")]
    if not speakers:
        print("No speakers found.")
        return
    
    print("\nFound Speakers:")
    for i, s in enumerate(speakers):
        print(f"{i}: {s['name']} ({s['model']}) - DID: {s['did']}")
    
    choice = input("\nSelect speaker index (default 0): ") or "0"
    speaker = speakers[int(choice)]
    
    music_url = input("Enter music URL to play: ") or "http://music.163.com/song/media/outer/url?id=1407551413.mp3"
    
    print(f"Playing on {speaker['name']}...")
    
    # Action: play-url
    # Many Xiaomi speakers use siid=3 (Play Control) and aiid=1 (Play URL) for streaming.
    # We will try a few common combinations if the first one fails.
    
    actions_to_try = [
        {"siid": 3, "aiid": 1}, # Play Control -> Play URL (common)
        {"siid": 2, "aiid": 1}, # Intelligent Speaker -> Execute Text Directive (some models)
        {"siid": 5, "aiid": 1}, # Multimedia -> Play URL (some models)
    ]
    
    success = False
    for action in actions_to_try:
        print(f"Trying action {action['siid']}:{action['aiid']}...")
        action_data = {
            "params": {
                "did": speaker["did"],
                "siid": action["siid"],
                "aiid": action["aiid"],
                "value": [music_url]
            }
        }
        try:
            res = client.request("/miotspec/action", action_data)
            if res.get("code") == 0:
                print(f"Success! {speaker['name']} should be playing now.")
                success = True
                break
            else:
                print(f"Action failed with code {res.get('code')}: {res.get('message', '')}")
        except Exception as e:
            print(f"Error executing action: {e}")
    
    if not success:
        print("\nAll attempts failed. You might need to check the specific siid/aiid for your model at https://home.miot-spec.com/")

if __name__ == "__main__":
    main()
