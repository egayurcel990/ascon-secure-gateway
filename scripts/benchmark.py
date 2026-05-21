import base64
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "client"))
sys.path.insert(0, str(PROJECT_ROOT / "gateway"))

from ascon import ascon_encrypt, generate_nonce
from demo import AsconClient

BASE_URL = "http://localhost:8000"
REQUESTS_COUNT = 50

PSK_HEX = "deadbeefcafebabedeadbeefcafebabe"
PSK = bytes.fromhex(PSK_HEX)

SECURE_PATH = "auth/login"
INSECURE_URL = f"{BASE_URL}/insecure/auth/login"

LOGIN_PAYLOAD = {
    "username": "admin",
    "password": "admin123",
}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def canonical_json(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_secure_payload(path: str, payload: dict) -> dict:
    aad = {
        "client_id": "benchmark-client",
        "request_id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "path": path,
        "method": "POST",
    }

    nonce = generate_nonce()
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext_with_tag = ascon_encrypt(PSK, nonce, plaintext, canonical_json(aad))

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return {
        "version": "ascon-aead128",
        "key_id": "key-v1",
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
        "aad": aad,
    }


def percentile(values, percent):
    values = sorted(values)
    index = int(len(values) * percent / 100)
    index = min(index, len(values) - 1)
    return values[index]


def summarize(results):
    latencies = [r["latency_ms"] for r in results]
    sizes = [r["payload_size_bytes"] for r in results]

    return {
        "requests": len(results),
        "success_rate": round(
            len([r for r in results if r["success"]]) / len(results) * 100,
            2,
        ),
        "avg_latency_ms": round(statistics.mean(latencies), 3),
        "min_latency_ms": round(min(latencies), 3),
        "max_latency_ms": round(max(latencies), 3),
        "p95_latency_ms": round(percentile(latencies, 95), 3),
        "avg_payload_size_bytes": round(statistics.mean(sizes), 2),
    }


def benchmark_insecure():
    results = []

    for _ in range(REQUESTS_COUNT):
        start = time.perf_counter()
        response = requests.post(INSECURE_URL, json=LOGIN_PAYLOAD)
        elapsed = (time.perf_counter() - start) * 1000

        results.append(
            {
                "status": response.status_code,
                "success": response.status_code < 400,
                "latency_ms": elapsed,
                "payload_size_bytes": len(json.dumps(LOGIN_PAYLOAD).encode("utf-8")),
            }
        )

    return results


def benchmark_secure():
    results = []
    client = AsconClient(BASE_URL, PSK)

    for _ in range(REQUESTS_COUNT):
        encrypted_payload = build_secure_payload(SECURE_PATH, LOGIN_PAYLOAD)

        start = time.perf_counter()
        response = requests.post(f"{BASE_URL}/secure/{SECURE_PATH}", json=encrypted_payload)
        elapsed = (time.perf_counter() - start) * 1000

        success = response.status_code < 400

        results.append(
            {
                "status": response.status_code,
                "success": success,
                "latency_ms": elapsed,
                "payload_size_bytes": len(json.dumps(encrypted_payload).encode("utf-8")),
            }
        )

    return results


def run_benchmark():
    print("\nRunning valid ASCON-AEAD benchmark...\n")

    insecure_results = benchmark_insecure()
    secure_results = benchmark_secure()

    insecure_summary = summarize(insecure_results)
    secure_summary = summarize(secure_results)

    report = {
        "metadata": {
            "requests_per_scenario": REQUESTS_COUNT,
            "base_url": BASE_URL,
            "secure_endpoint": f"/secure/{SECURE_PATH}",
            "insecure_endpoint": "/insecure/auth/login",
        },
        "benchmark": {
            "insecure": insecure_summary,
            "secure_ascon_aead": secure_summary,
        },
        "overhead": {
            "avg_latency_overhead_ms": round(
                secure_summary["avg_latency_ms"] - insecure_summary["avg_latency_ms"],
                3,
            ),
            "p95_latency_overhead_ms": round(
                secure_summary["p95_latency_ms"] - insecure_summary["p95_latency_ms"],
                3,
            ),
            "payload_overhead_bytes": round(
                secure_summary["avg_payload_size_bytes"]
                - insecure_summary["avg_payload_size_bytes"],
                2,
            ),
        },
    }

    output_path = PROJECT_ROOT / "benchmark-result.json"
    output_path.write_text(json.dumps(report, indent=2))

    print(json.dumps(report, indent=2))
    print(f"\nBenchmark saved to {output_path}")


if __name__ == "__main__":
    run_benchmark()