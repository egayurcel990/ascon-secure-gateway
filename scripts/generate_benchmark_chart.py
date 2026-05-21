import json
from pathlib import Path

import matplotlib.pyplot as plt

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULT_FILE = PROJECT_ROOT / "benchmark-result.json"
OUTPUT_DIR = PROJECT_ROOT / "docs" / "images"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

with RESULT_FILE.open() as file:
    data = json.load(file)

insecure = data["benchmark"]["insecure"]
secure = data["benchmark"]["secure_ascon_aead"]
overhead = data["overhead"]

labels = ["Insecure", "ASCON-AEAD Secure"]

# Chart 1: Average Latency
plt.figure(figsize=(7, 5))
plt.bar(labels, [insecure["avg_latency_ms"], secure["avg_latency_ms"]])
plt.ylabel("Latency (ms)")
plt.title("Average Latency: Insecure vs ASCON-AEAD Secure")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "benchmark_avg_latency.png", dpi=200)
plt.close()

# Chart 2: P95 Latency
plt.figure(figsize=(7, 5))
plt.bar(labels, [insecure["p95_latency_ms"], secure["p95_latency_ms"]])
plt.ylabel("Latency (ms)")
plt.title("P95 Latency: Insecure vs ASCON-AEAD Secure")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "benchmark_p95_latency.png", dpi=200)
plt.close()

# Chart 3: Payload Size
plt.figure(figsize=(7, 5))
plt.bar(labels, [insecure["avg_payload_size_bytes"], secure["avg_payload_size_bytes"]])
plt.ylabel("Payload Size (bytes)")
plt.title("Average Payload Size Comparison")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "benchmark_payload_size.png", dpi=200)
plt.close()

# Chart 4: Overhead Summary
overhead_labels = ["Avg Latency\nOverhead (ms)", "P95 Latency\nOverhead (ms)", "Payload\nOverhead (bytes)"]
overhead_values = [
    overhead["avg_latency_overhead_ms"],
    overhead["p95_latency_overhead_ms"],
    overhead["payload_overhead_bytes"],
]

plt.figure(figsize=(8, 5))
plt.bar(overhead_labels, overhead_values)
plt.ylabel("Value")
plt.title("ASCON-AEAD Overhead Summary")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "benchmark_overhead_summary.png", dpi=200)
plt.close()

print("Benchmark charts generated:")
print(f"- {OUTPUT_DIR / 'benchmark_avg_latency.png'}")
print(f"- {OUTPUT_DIR / 'benchmark_p95_latency.png'}")
print(f"- {OUTPUT_DIR / 'benchmark_payload_size.png'}")
print(f"- {OUTPUT_DIR / 'benchmark_overhead_summary.png'}")