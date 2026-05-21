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
from metrics import record_metric, snapshot

app = FastAPI(title="ASCON-AEAD Secure Gateway", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_KEY_ID = os.environ.get("ASCON_DEFAULT_KEY_ID", "key-v1")
PSK = bytes.fromhex(os.environ.get("ASCON_PSK", "deadbeefcafebabedeadbeefcafebabe"))
KEYRING: dict[str, bytes] = {DEFAULT_KEY_ID: PSK}

WEBAPP_URL = os.environ.get("WEBAPP_URL", "http://webapp:5000")
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"
REPLAY_WINDOW_SECONDS = int(os.environ.get("REPLAY_WINDOW_SECONDS", "300"))
MAX_REPLAY_CACHE = int(os.environ.get("MAX_REPLAY_CACHE", "10000"))

SEEN_REQUESTS: OrderedDict[str, int] = OrderedDict()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_aad(aad: dict) -> bytes:
    return canonical_json(aad)


def split_ciphertext_and_tag(ciphertext_with_tag: bytes) -> tuple[bytes, bytes]:
    if len(ciphertext_with_tag) < 16:
        raise ValueError("ciphertext terlalu pendek")
    return ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]


def encode_encrypted(
    ciphertext_with_tag: bytes,
    nonce: bytes,
    aad: dict,
    key_id: str = DEFAULT_KEY_ID,
) -> dict:
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

    replay_key = f"{aad['client_id']}:{aad['request_id']}"
    if replay_key in SEEN_REQUESTS:
        record_metric("replay_rejected")
        raise ValueError("request replay terdeteksi")

    SEEN_REQUESTS[replay_key] = now


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "ascon-aead-gateway",
        "version": "1.2.0",
    }


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
            "runtime metrics",
        ],
        "demo_mode": DEMO_MODE,
    }


@app.get("/metrics")
async def get_metrics():
    return snapshot()


@app.post("/secure/{path:path}")
async def secure_proxy(path: str, request: Request):
    request_start = time.perf_counter()

    record_metric("requests_total")
    record_metric("secure_requests_total")
    record_metric("encrypted_requests")

    try:
        body = await request.json()
        ciphertext_with_tag, nonce, aad, key_id = decode_encrypted(body)
        validate_aad(aad, path, "POST")
    except Exception as e:
        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)
        return Response(
            content=json.dumps(
                {"success": False, "error": f"Invalid encrypted payload: {str(e)}"}
            ),
            status_code=400,
            media_type="application/json",
        )

    try:
        decrypt_start = time.perf_counter()
        plaintext = ascon_decrypt(
            KEYRING[key_id],
            nonce,
            ciphertext_with_tag,
            build_aad(aad),
        )
        decrypt_elapsed = (time.perf_counter() - decrypt_start) * 1000
        record_metric("avg_decrypt_ms", decrypt_elapsed)
        record_metric("decrypt_success")

        inner_data = json.loads(plaintext.decode("utf-8"))

    except InvalidTagError:
        record_metric("decrypt_failures")
        record_metric("tampered_rejected")

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=json.dumps(
                {"success": False, "error": "Decryption failed: authentication tag invalid"}
            ),
            status_code=400,
            media_type="application/json",
        )

    except Exception:
        record_metric("decrypt_failures")

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=json.dumps({"success": False, "error": "Decryption failed"}),
            status_code=400,
            media_type="application/json",
        )

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{WEBAPP_URL}/{path}",
                json=inner_data,
                timeout=10.0,
            )

        webapp_response = resp.json()
        status_code = resp.status_code

    except Exception as e:
        record_metric("webapp_errors")

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=json.dumps(
                {"success": False, "error": f"Webapp unreachable: {str(e)}"}
            ),
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

    encrypt_start = time.perf_counter()
    response_ct = ascon_encrypt(
        KEYRING[key_id],
        response_nonce,
        response_plain,
        build_aad(response_aad),
    )
    encrypt_elapsed = (time.perf_counter() - encrypt_start) * 1000
    record_metric("avg_encrypt_ms", encrypt_elapsed)

    encrypted_response = encode_encrypted(
        response_ct,
        response_nonce,
        response_aad,
        key_id,
    )

    elapsed = (time.perf_counter() - request_start) * 1000
    record_metric("request_latency_ms", elapsed)

    return Response(
        content=json.dumps(encrypted_response),
        status_code=status_code,
        media_type="application/json",
    )


@app.get("/secure/{path:path}")
async def secure_get_proxy(path: str, request: Request):
    request_start = time.perf_counter()

    record_metric("requests_total")
    record_metric("secure_requests_total")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{WEBAPP_URL}/{path}",
                params=dict(request.query_params),
                timeout=10.0,
            )

        webapp_response = resp.json()

    except Exception as e:
        record_metric("webapp_errors")

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=json.dumps(
                {"success": False, "error": f"Webapp unreachable: {str(e)}"}
            ),
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

    encrypt_start = time.perf_counter()
    response_ct = ascon_encrypt(
        PSK,
        response_nonce,
        response_plain,
        build_aad(response_aad),
    )
    encrypt_elapsed = (time.perf_counter() - encrypt_start) * 1000
    record_metric("avg_encrypt_ms", encrypt_elapsed)

    encrypted_response = encode_encrypted(
        response_ct,
        response_nonce,
        response_aad,
        DEFAULT_KEY_ID,
    )

    elapsed = (time.perf_counter() - request_start) * 1000
    record_metric("request_latency_ms", elapsed)

    return Response(
        content=json.dumps(encrypted_response),
        status_code=resp.status_code,
        media_type="application/json",
    )


@app.post("/insecure/{path:path}")
async def insecure_proxy(path: str, request: Request):
    if not DEMO_MODE:
        return Response(
            content=json.dumps({"success": False, "error": "insecure endpoint disabled"}),
            status_code=404,
            media_type="application/json",
        )

    request_start = time.perf_counter()

    record_metric("requests_total")
    record_metric("insecure_requests_total")

    try:
        body = await request.json()

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{WEBAPP_URL}/{path}",
                json=body,
                timeout=10.0,
            )

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=resp.text,
            status_code=resp.status_code,
            media_type="application/json",
        )

    except Exception as e:
        record_metric("webapp_errors")

        elapsed = (time.perf_counter() - request_start) * 1000
        record_metric("request_latency_ms", elapsed)

        return Response(
            content=json.dumps(
                {"success": False, "error": f"Insecure proxy failed: {str(e)}"}
            ),
            status_code=502,
            media_type="application/json",
        )