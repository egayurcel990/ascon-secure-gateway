"""
ASCON-AEAD Client Library + Demo Script
=======================================
Simulasi client yang berkomunikasi dengan ASCON Gateway.
Request dan response memakai format payload ASCON-AEAD:
version, key_id, nonce, ciphertext, tag, dan aad.
"""

import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "gateway"))
from ascon import ascon_encrypt, ascon_decrypt, generate_nonce  # noqa: E402


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AsconClient:
    def __init__(self, gateway_url: str, psk: bytes, client_id: str = "client-demo", key_id: str = "key-v1"):
        self.gateway_url = gateway_url.rstrip("/")
        self.psk = psk
        self.client_id = client_id
        self.key_id = key_id
        self.session = requests.Session()

    @staticmethod
    def _b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _b64d(data: str) -> bytes:
        return base64.b64decode(data.encode("ascii"), validate=True)

    @staticmethod
    def _split_ciphertext_and_tag(ciphertext_with_tag: bytes) -> tuple[bytes, bytes]:
        return ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]

    def _build_aad(self, path: str, method: str) -> dict:
        return {
            "client_id": self.client_id,
            "request_id": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "path": path,
            "method": method.upper(),
        }

    def _encrypt_payload(self, path: str, method: str, data: dict) -> dict:
        nonce = generate_nonce()
        aad = self._build_aad(path, method)
        plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
        ct_with_tag = ascon_encrypt(self.psk, nonce, plaintext, canonical_json(aad))
        ciphertext, tag = self._split_ciphertext_and_tag(ct_with_tag)
        return {
            "version": "ascon-aead128",
            "key_id": self.key_id,
            "nonce": self._b64e(nonce),
            "ciphertext": self._b64e(ciphertext),
            "tag": self._b64e(tag),
            "aad": aad,
        }

    def _decrypt_response(self, response_json: dict) -> dict:
        ct = self._b64d(response_json["ciphertext"])
        tag = self._b64d(response_json["tag"])
        nonce = self._b64d(response_json["nonce"])
        aad = response_json["aad"]
        pt = ascon_decrypt(self.psk, nonce, ct + tag, canonical_json(aad))
        return json.loads(pt.decode("utf-8"))

    def post(self, path: str, data: dict) -> tuple[dict, int]:
        encrypted_body = self._encrypt_payload(path, "POST", data)
        resp = self.session.post(f"{self.gateway_url}/secure/{path}", json=encrypted_body)
        resp_json = resp.json()
        if resp.status_code >= 400 and "ciphertext" not in resp_json:
            return resp_json, resp.status_code
        return self._decrypt_response(resp_json), resp.status_code

    def post_raw_encrypted(self, path: str, data: dict) -> dict:
        """Membuat payload encrypted tanpa mengirim. Berguna untuk demo replay/tamper."""
        return self._encrypt_payload(path, "POST", data)

    def get(self, path: str) -> tuple[dict, int]:
        resp = self.session.get(f"{self.gateway_url}/secure/{path}")
        return self._decrypt_response(resp.json()), resp.status_code


GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")
PSK = bytes.fromhex(os.environ.get("ASCON_PSK", "deadbeefcafebabedeadbeefcafebabe"))
client = AsconClient(GATEWAY_URL, PSK)


def separator(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def demo_register():
    separator("DEMO: Register User Baru")
    data, status = client.post("auth/register", {"username": "bob", "password": "secret123"})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")


def demo_login(username: str, password: str) -> str | None:
    separator(f"DEMO: Login sebagai '{username}'")
    data, status = client.post("auth/login", {"username": username, "password": password})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")
    return data.get("token")


def demo_wrong_login():
    separator("DEMO: Login dengan password salah")
    data, status = client.post("auth/login", {"username": "admin", "password": "wrongpassword"})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")


def demo_verify(token: str):
    separator("DEMO: Verifikasi Token")
    data, status = client.post("auth/verify", {"token": token})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")


def demo_profile(token: str):
    separator("DEMO: Get Profile")
    data, status = client.post("auth/profile", {"token": token})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")


def demo_logout(token: str):
    separator("DEMO: Logout")
    data, status = client.post("auth/logout", {"token": token})
    print(f"Status  : {status}")
    print(f"Response: {json.dumps(data, indent=2)}")


def demo_raw_request():
    separator("DEMO: Raw Network Traffic Secure Payload")
    raw_payload = client.post_raw_encrypted("auth/login", {"username": "admin", "password": "admin123"})
    print(json.dumps(raw_payload, indent=2))
    print("\nDi Wireshark, username dan password tidak muncul sebagai plaintext pada endpoint /secure.")


def demo_insecure_baseline():
    separator("DEMO: Insecure Baseline untuk Wireshark")
    payload = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{GATEWAY_URL}/insecure/auth/login", json=payload)
    print("Payload plaintext yang dikirim ke /insecure/auth/login:")
    print(json.dumps(payload, indent=2))
    print(f"Status  : {resp.status_code}")
    print(f"Response: {resp.text[:300]}")


def demo_replay_attack():
    separator("DEMO: Replay Attack Rejected")
    payload = client.post_raw_encrypted("auth/login", {"username": "admin", "password": "admin123"})
    first = requests.post(f"{GATEWAY_URL}/secure/auth/login", json=payload)
    second = requests.post(f"{GATEWAY_URL}/secure/auth/login", json=payload)
    print(f"First request status : {first.status_code}")
    print(f"Replay request status: {second.status_code}")
    print(f"Replay response      : {second.text}")


def demo_tampered_ciphertext():
    separator("DEMO: Tampered Ciphertext Rejected")
    payload = client.post_raw_encrypted("auth/login", {"username": "admin", "password": "admin123"})
    raw = bytearray(base64.b64decode(payload["ciphertext"]))
    raw[0] ^= 1
    payload["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    resp = requests.post(f"{GATEWAY_URL}/secure/auth/login", json=payload)
    print(f"Status  : {resp.status_code}")
    print(f"Response: {resp.text}")


if __name__ == "__main__":
    print("\n" + "█" * 60)
    print("  ASCON-AEAD Encrypted Login System Demo")
    print("  Gateway: " + GATEWAY_URL)
    print("█" * 60)

    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=3)
        print(f"\n✓ Gateway online: {r.json()}")
    except Exception:
        print("\n✗ Gateway tidak bisa diakses. Jalankan: docker-compose up -d --build")
        sys.exit(1)

    demo_register()
    time.sleep(0.3)
    token = demo_login("admin", "admin123")
    time.sleep(0.3)
    demo_wrong_login()
    time.sleep(0.3)

    if token:
        demo_verify(token)
        time.sleep(0.3)
        demo_profile(token)
        time.sleep(0.3)
        demo_logout(token)

    demo_raw_request()
    demo_replay_attack()
    demo_tampered_ciphertext()
    demo_insecure_baseline()

    print("\n✓ Demo selesai. Untuk Wireshark gunakan filter: tcp.port == 8000\n")
