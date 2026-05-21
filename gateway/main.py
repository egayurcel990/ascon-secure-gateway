"""
ASCON-AEAD Secure Gateway
=========================
Reverse proxy berbasis FastAPI yang bertindak sebagai encryption layer.
Client mengirim payload ASCON-AEAD ke gateway. Gateway mendekripsi,
memvalidasi tag, mengecek replay protection, lalu meneruskan request
ke webapp di internal Docker network.
"""

import base64
import json
import os
import time
import uuid
from collections import OrderedDict
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from ascon import InvalidTagError, ascon_decrypt, ascon_encrypt, generate_nonce

app = FastAPI(title="ASCON-AEAD Secure Gateway", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Key registry sederhana. Untuk fase berikutnya, ini bisa dipindah ke Docker Secret,
# HashiCorp Vault, atau KMS. Format env: ASCON_PSK_<KEY_ID>, contoh ASCON_PSK_KEY_V1.
DEFAULT_KEY_ID = os.environ.get("ASCON_DEFAULT_KEY_ID", "key-v1")
PSK = bytes.fromhex(os.environ.get("ASCON_PSK", "deadbeefcafebabedeadbeefcafebabe"))
KEYRING: dict[str, bytes] = {DEFAULT_KEY_ID: PSK}

WEBAPP_URL = os.environ.get("WEBAPP_URL", "http://webapp:5000")
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
REPLAY_WINDOW_SECONDS = int(os.environ.get("REPLAY_WINDOW_SECONDS", "300"))
MAX_REPLAY_CACHE = int(os.environ.get("MAX_REPLAY_CACHE", "10000"))

# Cache in-memory untuk nonce/request_id yang sudah dipakai.
# Untuk production multi-instance, gunakan Redis agar cache konsisten antar replica.
SEEN_REQUESTS: OrderedDict[str, int] = OrderedDict()

METRICS = {
    "secure_requests_total": 0,
    "decrypt_success_total": 0,
    "decrypt_failed_total": 0,
    "replay_rejected_total": 0,
    "tampered_rejected_total": 0,
    "insecure_requests_total": 0,
    "last_decrypt_ms": 0.0,
    "last_encrypt_ms": 0.0,
}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical_json(data: Any) -> bytes:
    """JSON stabil untuk Associated Data agar client dan gateway identik."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_aad(aad: dict) -> bytes:
    return canonical_json(aad)


def split_ciphertext_and_tag(ciphertext_with_tag: bytes) -> tuple[bytes, bytes]:
    if len(ciphertext_with_tag) < 16:
        raise ValueError("ciphertext terlalu pendek")
    return ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]


def encode_encrypted(ciphertext_with_tag: bytes, nonce: bytes, aad: dict, key_id: str = DEFAULT_KEY_ID) -> dict:
    ciphertext, tag = split_ciphertext_and_tag(ciphertext_with_tag)
    return {
        "version": "ascon-aead128",
        "key_id": key_id,
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
        "aad": aad,
    }


def decode_encrypted(payload: dict) -> tuple[bytes, bytes, dict, str]:
    required = {"version", "key_id", "nonce", "ciphertext", "tag", "aad"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"field wajib hilang: {', '.join(missing)}")

    if payload["version"] != "ascon-aead128":
        raise ValueError("version tidak didukung")

    key_id = payload["key_id"]
    if key_id not in KEYRING:
        raise ValueError("key_id tidak dikenal")

    nonce = _b64d(payload["nonce"])
    ciphertext = _b64d(payload["ciphertext"])
    tag = _b64d(payload["tag"])
    aad = payload["aad"]

    if not isinstance(aad, dict):
        raise ValueError("aad harus berupa object JSON")
    if len(nonce) != 16:
        raise ValueError("nonce harus 16 byte")
    if len(tag) != 16:
        raise ValueError("tag harus 16 byte")

    return ciphertext + tag, nonce, aad, key_id


def _cleanup_replay_cache(now: int) -> None:
    expired_before = now - REPLAY_WINDOW_SECONDS
    while SEEN_REQUESTS:
        _, ts = next(iter(SEEN_REQUESTS.items()))
        if ts >= expired_before and len(SEEN_REQUESTS) <= MAX_REPLAY_CACHE:
            break
        SEEN_REQUESTS.popitem(last=False)


def validate_aad(aad: dict, path: str, method: str) -> None:
    now = int(time.time())
    _cleanup_replay_cache(now)

    required = ["client_id", "request_id", "timestamp", "path", "method"]
    missing = [field for field in required if field not in aad]
    if missing:
        raise ValueError(f"aad tidak lengkap: {', '.join(missing)}")

    if aad["path"].strip("/") != path.strip("/"):
        raise ValueError("aad path tidak cocok")
    if aad["method"].upper() != method.upper():
        raise ValueError("aad method tidak cocok")

    timestamp = int(aad["timestamp"])
    if abs(now - timestamp) > REPLAY_WINDOW_SECONDS:
        raise ValueError("request timestamp berada di luar replay window")

    replay_key = f"{aad['client_id']}:{aad['request_id']}:{aad['nonce_ref'] if 'nonce_ref' in aad else ''}"
    if replay_key in SEEN_REQUESTS:
        METRICS["replay_rejected_total"] += 1
        raise ValueError("request replay terdeteksi")
    SEEN_REQUESTS[replay_key] = now


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ascon-aead-gateway", "version": "1.1.0"}


@app.get("/info")
async def info():
    return {
        "algorithm": "ASCON-AEAD128",
        "key_size": "128-bit",
        "nonce_size": "128-bit",
        "tag_size": "128-bit",
        "security_features": [
            "confidentiality",
            "authentication tag verification",
            "associated data binding",
            "timestamp validation",
            "request_id replay protection",
            "key_id support",
        ],
        "demo_mode": DEMO_MODE,
    }


@app.get("/metrics")
async def metrics():
    return METRICS | {"replay_cache_size": len(SEEN_REQUESTS)}


@app.post("/secure/{path:path}")
async def secure_proxy(path: str, request: Request):
    METRICS["secure_requests_total"] += 1

    try:
        body = await request.json()
        ciphertext_with_tag, nonce, aad, key_id = decode_encrypted(body)
        validate_aad(aad, path, "POST")
    except Exception as e:
        return Response(
            content=json.dumps({"success": False, "error": f"Invalid encrypted payload: {str(e)}"}),
            status_code=400,
            media_type="application/json",
        )

    try:
        start = time.perf_counter()
        plaintext = ascon_decrypt(KEYRING[key_id], nonce, ciphertext_with_tag, build_aad(aad))
        METRICS["last_decrypt_ms"] = round((time.perf_counter() - start) * 1000, 4)
        METRICS["decrypt_success_total"] += 1
        inner_data = json.loads(plaintext.decode("utf-8"))
    except InvalidTagError:
        METRICS["decrypt_failed_total"] += 1
        METRICS["tampered_rejected_total"] += 1
        return Response(
            content=json.dumps({"success": False, "error": "Decryption failed: authentication tag invalid"}),
            status_code=400,
            media_type="application/json",
        )
    except Exception:
        METRICS["decrypt_failed_total"] += 1
        return Response(
            content=json.dumps({"success": False, "error": "Decryption failed"}),
            status_code=400,
            media_type="application/json",
        )

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{WEBAPP_URL}/{path}", json=inner_data, timeout=10.0)
        webapp_response = resp.json()
        status_code = resp.status_code
    except Exception as e:
        return Response(
            content=json.dumps({"success": False, "error": f"Webapp unreachable: {str(e)}"}),
            status_code=502,
            media_type="application/json",
        )

    response_aad = {
        "client_id": aad["client_id"],
        "request_id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "path": path,
        "method": "RESPONSE",
        "response_to": aad["request_id"],
    }
    response_nonce = generate_nonce()
    response_plain = json.dumps(webapp_response, separators=(",", ":")).encode("utf-8")

    start = time.perf_counter()
    response_ct = ascon_encrypt(KEYRING[key_id], response_nonce, response_plain, build_aad(response_aad))
    METRICS["last_encrypt_ms"] = round((time.perf_counter() - start) * 1000, 4)

    encrypted_response = encode_encrypted(response_ct, response_nonce, response_aad, key_id)
    return Response(content=json.dumps(encrypted_response), status_code=status_code, media_type="application/json")


@app.get("/secure/{path:path}")
async def secure_get_proxy(path: str, request: Request):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{WEBAPP_URL}/{path}", params=dict(request.query_params), timeout=10.0)
        webapp_response = resp.json()
    except Exception as e:
        return Response(
            content=json.dumps({"success": False, "error": f"Webapp unreachable: {str(e)}"}),
            status_code=502,
            media_type="application/json",
        )

    response_aad = {
        "client_id": "public-get",
        "request_id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "path": path,
        "method": "RESPONSE",
    }
    response_nonce = generate_nonce()
    response_plain = json.dumps(webapp_response, separators=(",", ":")).encode("utf-8")
    response_ct = ascon_encrypt(PSK, response_nonce, response_plain, build_aad(response_aad))
    encrypted_response = encode_encrypted(response_ct, response_nonce, response_aad, DEFAULT_KEY_ID)
    return Response(content=json.dumps(encrypted_response), status_code=resp.status_code, media_type="application/json")


@app.post("/insecure/{path:path}")
async def insecure_proxy(path: str, request: Request):
    """Baseline pembanding untuk Wireshark. Aktif hanya ketika DEMO_MODE=true."""
    if not DEMO_MODE:
        return Response(
            content=json.dumps({"success": False, "error": "insecure endpoint disabled"}),
            status_code=404,
            media_type="application/json",
        )

    METRICS["insecure_requests_total"] += 1
    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{WEBAPP_URL}/{path}", json=body, timeout=10.0)
        return Response(content=resp.text, status_code=resp.status_code, media_type="application/json")
    except Exception as e:
        return Response(
            content=json.dumps({"success": False, "error": f"Insecure proxy failed: {str(e)}"}),
            status_code=502,
            media_type="application/json",
        )
