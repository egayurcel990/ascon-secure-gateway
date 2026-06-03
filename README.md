# ASCON-AEAD Secure Gateway

> Docker-based encrypted communication gateway · NIST Lightweight Cryptography Standard 2023

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![ASCON](https://img.shields.io/badge/Crypto-ASCON--AEAD128-orange)
![Status](https://img.shields.io/badge/Status-Research%20Prototype-success)
![Focus](https://img.shields.io/badge/CIA%20Triad-Confidentiality-red)

A containerized reverse proxy that encrypts all client-server communication using **ASCON-AEAD128** — implemented from scratch in pure Python, with no TLS or external cryptography libraries.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         public_net                              │
│                                                                 │
│   ┌──────────┐   ASCON-AEAD encrypted payload   ┌───────────┐  │
│   │  Client  │ ─────────────────────────────▶   │  Gateway  │  │
│   │          │ ◀─────────────────────────────   │   :8000   │  │
│   └──────────┘                                  └─────┬─────┘  │
└──────────────────────────────────────────────────────┼─────────┘
                                            internal_net│ (isolated)
                                                 ┌──────▼──────┐
                                                 │   WebApp    │
                                                 │   :5000     │
                                                 │  (SQLite)   │
                                                 └─────────────┘
```

The **WebApp is never directly reachable** from outside Docker. All traffic passes through the Gateway, which handles all encryption and decryption transparently.

---

## Security Features

| Feature | Status |
|---|---|
| ASCON-AEAD128 Encryption | ✅ |
| Authentication Tag Verification | ✅ |
| Associated Data (AAD) Binding | ✅ |
| Replay Attack Protection | ✅ |
| Tampered Ciphertext Rejection | ✅ |
| Timestamp Validation | ✅ |
| Docker Network Isolation | ✅ |
| Runtime Security Metrics | ✅ |

---

## Encrypted Payload Structure

Every request between client and gateway looks like this on the wire:

```json
{
  "version": "ascon-aead128",
  "key_id": "key-v1",
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "tag": "<base64>",
  "aad": {
    "client_id": "demo-client",
    "request_id": "<uuid>",
    "timestamp": 1716300000,
    "path": "auth/login",
    "method": "POST"
  }
}
```

No username. No password. No readable data.

---

## Benchmark Results

50 requests per scenario, measured end-to-end from client to gateway to webapp.

| Metric | Insecure | ASCON-AEAD |
|---|---:|---:|
| Avg Latency | 13.87 ms | 15.49 ms |
| P95 Latency | 17.91 ms | 20.03 ms |
| Payload Size | 45 bytes | 355 bytes |
| Success Rate | 100% | 100% |

**Encryption overhead: only ~1.6 ms average** — consistent with ASCON's design goal as a lightweight algorithm.

![Avg Latency](docs/images/benchmark_avg_latency.png)
![Overhead](docs/images/benchmark_overhead_summary.png)

---

## Quick Start

### Prerequisites
- Docker Desktop (WSL2 integration enabled if on Windows)
- Python 3.12+
- Wireshark — [download](https://www.wireshark.org/download.html) *(install Npcap when prompted)*

### 1. Clone and start

```bash
git clone https://github.com/egayurcel990/ascon-secure-gateway.git
cd ascon-secure-gateway

cp .env.example .env
docker compose up -d --build
```

Verify:
```bash
docker compose ps
curl http://localhost:8000/health
# {"status":"ok","service":"ascon-aead-gateway","version":"1.2.0"}
```

### 2. Run the demo

```bash
cd client
python3 -m venv venv && source venv/bin/activate
pip install requests
python3 demo.py
```

The demo tests: encrypted login, wrong password, token verification, replay attack rejection, tampered ciphertext rejection, and insecure comparison.

### 3. Open the Web UI

```bash
# Still in client/ with venv active
python3 -m http.server 3000
```

> **WSL users:** find your WSL IP first: `ip addr show eth0 | grep "inet "`  
> Then open `http://<WSL-IP>:3000` instead of localhost.

Open the URL in your browser. Try logging in — the traffic monitor on the right shows each encrypted request in real time.

Demo accounts: `admin / admin123` · `alice / user123`

---

## Wireshark Capture (Proving Confidentiality)

> **Why tcpdump inside the container?**  
> Docker Desktop routes container traffic through an internal virtual network that doesn't pass through Windows interfaces. We capture from inside the container and export the `.pcap` file.

**Open two terminals.**

**Terminal 1 — start web server:**
```bash
cd client && source venv/bin/activate
python3 -m http.server 3000
```

**Terminal 2 — start packet capture:**
```bash
docker exec -it ascon-gateway tcpdump -i any -w /tmp/capture.pcap port 8000
```

**Perform actions in the browser** — login, logout, try wrong password, click "Run Security Test".

**Terminal 2 — stop capture and export:**
```bash
# Press Ctrl+C, then:
docker cp ascon-gateway:/tmp/capture.pcap ./captures/demo.pcap
```

**Open in Wireshark:**
1. File → Open → `captures/demo.pcap`
2. Filter: `tcp.port == 8000`
3. Click any `POST /secure/auth/login` packet
4. Expand **JavaScript Object Notation** in the bottom panel

**Secure endpoint** — only ciphertext visible:
```
ciphertext: 4AtmCjcqUCpekudjWtejY16M...
nonce:      tM1uYJxSrHz8IWyipi1RIw==
tag:        xZ9k2mP...
```

**Insecure endpoint** (for comparison) — plaintext exposed:
```
username: admin
password: admin123
```

Wireshark filter to compare both: `frame contains "ciphertext"` vs `frame contains "password"`

---

## Runtime Metrics

```bash
curl http://localhost:8000/metrics
```

```json
{
  "requests_total": 10,
  "decrypt_success": 8,
  "decrypt_failures": 1,
  "replay_rejected": 1,
  "tampered_rejected": 1,
  "avg_encrypt_ms": 1.085,
  "avg_decrypt_ms": 1.296,
  "avg_request_latency_ms": 20.93
}
```

---

## Benchmark

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install requests matplotlib
python3 scripts/benchmark.py
python3 scripts/generate_benchmark_chart.py
```

Charts are saved to `docs/images/`.

---

## Project Structure

```
ascon-secure-gateway/
├── gateway/
│   ├── ascon.py          ← ASCON-AEAD128 from scratch (pure Python)
│   ├── main.py           ← FastAPI gateway with replay & tag validation
│   └── metrics.py        ← Runtime metrics
├── webapp/
│   └── main.py           ← Flask login system (SQLite)
├── client/
│   ├── demo.py           ← CLI demo script
│   └── index.html        ← Web UI with traffic monitor
├── scripts/
│   ├── benchmark.py      ← Performance benchmark
│   └── capture_traffic.sh
├── docs/
│   ├── SECURITY_MODEL.md
│   ├── BENCHMARK_REPORT.md
│   └── images/
├── captures/             ← Put .pcap files here
└── docker-compose.yml
```

---

## Threat Model

| Threat | Coverage |
|---|---|
| Plaintext credential exposure | ✅ Mitigated |
| Replay attack | ✅ Mitigated |
| Ciphertext tampering | ✅ Mitigated |
| Payload modification | ✅ Mitigated |
| Endpoint compromise | ⚠️ Out of scope |
| Key leakage | ⚠️ Out of scope |

---

## Roadmap

- [x] ASCON-AEAD128 pure Python implementation
- [x] Authenticated encryption with tag verification
- [x] Replay protection (request ID + timestamp window)
- [x] Docker network isolation
- [x] Runtime metrics endpoint
- [x] Benchmark with chart visualization
- [x] Insecure comparison endpoint
- [ ] Key rotation
- [ ] Redis-based distributed replay cache
- [ ] Argon2 password hashing
- [ ] Prometheus + Grafana integration
- [ ] Kubernetes deployment

---

## References

- [ASCON Specification v1.2](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf)
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography)
- [ASCON Official Website](https://ascon.iaik.tugraz.at/)

---

*For educational and research purposes.*
