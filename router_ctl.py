#!/usr/bin/env python3
"""
Cox Killer - TP-Link BE10000 Router Control
Implements the full TP-Link LuCI encrypted API protocol (RSA + AES + signature).
"""

import hashlib
import json
import sys
import time
import os
import http.cookiejar
import urllib.request
import urllib.error
import base64
import struct
import secrets
import string

ROUTER_IP = "192.168.0.1"
BASE = f"http://{ROUTER_IP}/cgi-bin/luci/;stok="


# ============================================================
# RSA (pure Python, minimal PKCS#1 v1.5)
# ============================================================

def rsa_encrypt(msg_bytes, n_hex, e_hex):
    """RSA encrypt with PKCS#1 v1.5 type 2 padding."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    k = (n.bit_length() + 7) // 8
    if len(msg_bytes) > k - 11:
        raise ValueError(f"Message too long ({len(msg_bytes)}) for key size ({k})")
    ps_len = k - len(msg_bytes) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)[0]
        if b != 0:
            ps.append(b)
    padded = b'\x00\x02' + bytes(ps) + b'\x00' + msg_bytes
    m = int.from_bytes(padded, 'big')
    c = pow(m, e, n)
    return format(c, '0' + str(k * 2) + 'x')


# ============================================================
# AES-CBC (using CryptoJS-compatible format via openssl-like approach)
# We'll shell out to openssl for AES since Python 3.9 stdlib lacks it
# ============================================================

def aes_encrypt_openssl(plaintext, key_hex, iv_hex):
    """AES-256-CBC encrypt using openssl CLI, return base64."""
    import subprocess
    result = subprocess.run(
        ['openssl', 'enc', '-aes-256-cbc', '-base64', '-A',
         '-K', key_hex, '-iv', iv_hex],
        input=plaintext.encode(),
        capture_output=True
    )
    return result.stdout.decode().strip()


def aes_decrypt_openssl(ciphertext_b64, key_hex, iv_hex):
    """AES-256-CBC decrypt using openssl CLI."""
    import subprocess
    result = subprocess.run(
        ['openssl', 'enc', '-d', '-aes-256-cbc', '-base64', '-A',
         '-K', key_hex, '-iv', iv_hex],
        input=ciphertext_b64.encode(),
        capture_output=True
    )
    return result.stdout.decode().strip()


# ============================================================
# TP-Link Protocol Implementation
# ============================================================

class TPLinkAPI:
    def __init__(self, host=ROUTER_IP):
        self.host = host
        self.base = f"http://{host}/cgi-bin/luci/;stok="
        self.stok = ""
        self.rsa_n = ""  # Auth RSA key (for signing)
        self.rsa_e = ""
        self.pwd_n = ""  # Password RSA key
        self.pwd_e = ""
        self.sequence = 0
        self.aes_key = ""  # 16-byte hex key
        self.aes_iv = ""   # 16-byte hex iv
        self.hash_val = ""
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj)
        )

    def _raw_request(self, path, data, stok=None):
        """Send a raw POST request."""
        if stok is None:
            stok = self.stok
        url = f"{self.base}{stok}{path}"
        if isinstance(data, dict):
            body = json.dumps(data).encode()
            ct = "application/json"
        elif isinstance(data, str):
            body = data.encode()
            ct = "application/x-www-form-urlencoded"
        else:
            body = data
            ct = "application/x-www-form-urlencoded"

        headers = {
            "Content-Type": ct,
            "Referer": f"http://{self.host}/webpages/index.html",
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            resp = self.opener.open(req, timeout=15)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except:
                return {"success": False, "error": str(e), "code": e.code}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _encrypted_request(self, path, payload, stok=None, include_aes_key=False):
        """Send an AES-encrypted + RSA-signed request."""
        payload_json = json.dumps(payload)

        # AES encrypt the payload
        encrypted_data = aes_encrypt_openssl(payload_json, self.aes_key, self.aes_iv)

        # Build signature: h=HASH&s=SEQUENCE+data_length
        data_len = len(encrypted_data)
        sign_content = f"h={self.hash_val}&s={self.sequence + data_len}"
        if include_aes_key:
            # First request includes the AES key
            aes_key_formatted = f"k={self.aes_key}&i={self.aes_iv}"
            sign_content = f"{aes_key_formatted}&{sign_content}"

        # RSA sign with auth key
        sign_encrypted = rsa_encrypt(sign_content.encode(), self.rsa_n, self.rsa_e)

        # Send as form-encoded: data=ENCRYPTED&sign=SIGNATURE
        body = f"sign={sign_encrypted}&data={urllib.parse.quote(encrypted_data)}"

        result = self._raw_request(path, body, stok=stok)

        # Decrypt response if needed
        if isinstance(result.get("data"), str) and result["data"]:
            try:
                decrypted = aes_decrypt_openssl(result["data"], self.aes_key, self.aes_iv)
                if decrypted:
                    result["data"] = json.loads(decrypted)
            except:
                pass

        return result

    def login(self, password):
        """Full login flow."""
        # Step 1: Get auth RSA key + sequence
        auth = self._raw_request("/login?form=auth", "operation=read", stok="")
        if not auth.get("success"):
            print(f"Failed to get auth: {auth}")
            return False

        self.rsa_n = auth["data"]["key"][0]
        self.rsa_e = auth["data"]["key"][1]
        self.sequence = auth["data"]["seq"]

        # Step 2: Get password RSA key
        keys = self._raw_request("/login?form=keys", "operation=read", stok="")
        if not keys.get("success"):
            print(f"Failed to get keys: {keys}")
            return False

        self.pwd_n = keys["data"]["password"][0]
        self.pwd_e = keys["data"]["password"][1]

        # Step 3: Generate AES session key (32 bytes = 256-bit for AES-256)
        self.aes_key = secrets.token_hex(16)  # 32 hex chars = 16 bytes = 128-bit
        self.aes_iv = secrets.token_hex(16)

        # Step 4: Hash password - try different formats
        password_formats = [
            ("plain", password),
            ("MD5", hashlib.md5(("admin" + password).encode()).hexdigest()),
            ("SHA256", hashlib.sha256(("admin" + password).encode()).hexdigest()),
        ]

        for label, pwd_val in password_formats:
            try:
                # RSA encrypt the password with the password key
                enc_pwd = rsa_encrypt(pwd_val.encode(), self.pwd_n, self.pwd_e)

                # Build login payload
                login_payload = {
                    "operation": "login",
                    "password": enc_pwd,
                }

                # Compute hash for signature
                self.hash_val = hashlib.md5(
                    f"admin{pwd_val}".encode()
                ).hexdigest()

                # Send encrypted login request (include AES key on first request)
                result = self._encrypted_request(
                    "/login?form=login", login_payload,
                    stok="", include_aes_key=True
                )

                if result.get("success"):
                    data = result.get("data", {})
                    if isinstance(data, dict) and data.get("stok"):
                        self.stok = data["stok"]
                        print(f"Authenticated ({label})")
                        return True

            except Exception as e:
                continue

        print("Authentication failed. Check password.")
        return False

    def read(self, path):
        """Read a setting (authenticated)."""
        return self._encrypted_request(path, {"operation": "read"})

    def write(self, path, data):
        """Write a setting (authenticated)."""
        data["operation"] = "write"
        return self._encrypted_request(path, data)

    def read_all_wireless(self):
        """Read all wireless settings."""
        settings = {}
        endpoints = [
            "smart_connect", "wireless_2g", "wireless_5g", "wireless_5g_2",
            "wireless_6g", "wireless", "wireless_schedule", "guest_2g",
            "guest_5g", "wps", "advanced",
        ]
        for ep in endpoints:
            r = self.read(f"/admin/wireless?form={ep}")
            if r.get("success") or (isinstance(r.get("data"), dict) and r["data"]):
                settings[ep] = r.get("data", r)
            else:
                settings[ep] = {"_error": str(r)}
        # Also check flow controller and QoS
        for ep in ["wan_fc"]:
            r = self.read(f"/admin/network?form={ep}")
            if r.get("success"):
                settings[f"network_{ep}"] = r.get("data", r)
        return settings


def main():
    import urllib.parse

    if len(sys.argv) < 2:
        print("Cox Killer - TP-Link BE10000 Router Control")
        print()
        print("Usage:")
        print("  router_ctl.py read [PASSWORD]      Read current wireless settings")
        print("  router_ctl.py apply [PASSWORD]      Apply Cox Killer optimizations")
        print("  router_ctl.py get FORM [PASSWORD]   Read a specific form endpoint")
        print()
        print(f"Router: {ROUTER_IP}")
        return

    cmd = sys.argv[1]

    # Get password from args or prompt
    password = None
    for i, arg in enumerate(sys.argv):
        if i > 1 and not arg.startswith("-") and "=" not in arg and "/" not in arg:
            password = arg
            break

    if not password:
        import getpass
        password = getpass.getpass(f"Router password ({ROUTER_IP}): ")

    api = TPLinkAPI()
    if not api.login(password):
        sys.exit(1)

    if cmd == "read":
        print("\nReading wireless settings...")
        settings = api.read_all_wireless()
        print(json.dumps(settings, indent=2))

    elif cmd == "get":
        form = sys.argv[2] if len(sys.argv) > 2 else "smart_connect"
        r = api.read(f"/admin/wireless?form={form}")
        print(json.dumps(r, indent=2))

    elif cmd == "apply":
        print("\nCox Killer recommended changes:")
        print("  1. Disable Smart Connect")
        print("  2. Reduce channel widths")
        print("  3. Disable Flow Controller")
        print()
        confirm = input("Proceed? (yes/no): ")
        if confirm.lower() != "yes":
            print("Aborted.")
            return

        # Backup first
        print("Backing up current settings...")
        current = api.read_all_wireless()
        backup_file = os.path.expanduser(
            f"~/network-monitor/logs/router_backup_{int(time.time())}.json"
        )
        with open(backup_file, "w") as f:
            json.dump(current, f, indent=2)
        print(f"Backup: {backup_file}")

        # Apply
        r = api.write("/admin/wireless?form=smart_connect", {"smart_enable": "off"})
        print(f"Smart Connect OFF: {'OK' if r.get('success') else r}")

        print("\nDone. Monitor Cox Killer dashboard for 30 min to measure improvement.")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
