import time
from threading import Lock

_lock = Lock()

metrics = {
    "requests_total": 0,
    "secure_requests_total": 0,
    "insecure_requests_total": 0,
    "encrypted_requests": 0,
    "decrypt_success": 0,
    "decrypt_failures": 0,
    "replay_rejected": 0,
    "tampered_rejected": 0,
    "webapp_errors": 0,
    "avg_encrypt_ms": [],
    "avg_decrypt_ms": [],
    "request_latency_ms": [],
    "started_at": int(time.time()),
}


def record_metric(name: str, value=None) -> None:
    with _lock:
        if name not in metrics:
            return

        if isinstance(metrics[name], list):
            if value is not None:
                metrics[name].append(float(value))
        else:
            metrics[name] += 1


def avg(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def snapshot() -> dict:
    with _lock:
        return {
            "uptime_seconds": int(time.time()) - metrics["started_at"],
            "requests_total": metrics["requests_total"],
            "secure_requests_total": metrics["secure_requests_total"],
            "insecure_requests_total": metrics["insecure_requests_total"],
            "encrypted_requests": metrics["encrypted_requests"],
            "decrypt_success": metrics["decrypt_success"],
            "decrypt_failures": metrics["decrypt_failures"],
            "replay_rejected": metrics["replay_rejected"],
            "tampered_rejected": metrics["tampered_rejected"],
            "webapp_errors": metrics["webapp_errors"],
            "avg_encrypt_ms": avg(metrics["avg_encrypt_ms"]),
            "avg_decrypt_ms": avg(metrics["avg_decrypt_ms"]),
            "avg_request_latency_ms": avg(metrics["request_latency_ms"]),
            "samples": {
                "encrypt": len(metrics["avg_encrypt_ms"]),
                "decrypt": len(metrics["avg_decrypt_ms"]),
                "latency": len(metrics["request_latency_ms"]),
            },
        }