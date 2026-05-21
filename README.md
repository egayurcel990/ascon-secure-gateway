# ASCON-AEAD Secure Gateway

Docker-based lightweight secure communication gateway implementing ASCON-AEAD authenticated encryption for confidential client-server communication.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED)
![FastAPI](https://img.shields.io/badge/FastAPI-Gateway-009688)
![ASCON](https://img.shields.io/badge/Crypto-ASCON--AEAD128-orange)
![Status](https://img.shields.io/badge/Status-Research%20Prototype-success)
---

# Overview

ASCON-AEAD Secure Gateway is a containerized reverse proxy architecture that provides an encryption layer between external clients and internal web services.

The system implements:

- ASCON-AEAD128 authenticated encryption
- Authentication tag verification
- Associated Data (AAD) validation
- Replay attack protection
- Tampered ciphertext rejection
- Secure encrypted API communication
- Docker network segmentation
- Runtime security metrics
- Benchmark and traffic analysis

This project demonstrates how lightweight cryptography can be integrated into containerized microservice communication while maintaining relatively low performance overhead.

---

# Demo Preview

## Browser-side Encrypted Login UI

![UI Preview](docs/images/ui-preview.png)

## Secure Traffic Analysis

![Wireshark Preview](docs/images/wireshark-preview.png)

# Threat Model

| Threat | Status |
|---|---|
| Plaintext Credential Exposure | Mitigated |
| Replay Attack | Mitigated |
| Ciphertext Tampering | Mitigated |
| Unauthorized Payload Modification | Mitigated |
| Endpoint Compromise | Not Covered |
| Key Leakage | Not Covered |
| TLS Downgrade Attack | Not Covered |

# Technologies Used

| Category | Technology |
|---|---|
| Encryption | ASCON-AEAD128 |
| Backend Gateway | FastAPI |
| Internal Service | Flask |
| Containerization | Docker Compose |
| Metrics | Custom Runtime Metrics |
| Visualization | Matplotlib |
| Traffic Analysis | Wireshark / tcpdump |
| Frontend | HTML, CSS, Vanilla JavaScript |

# Key Features

## Security Features

- Confidentiality using ASCON-AEAD128
- Authentication tag verification
- Replay protection using request ID and timestamp validation
- Associated Data (AAD) binding
- Tampered ciphertext detection
- Secure encrypted API communication
- Secure vs insecure traffic comparison

---

## Infrastructure Features

- Docker-based architecture
- Internal network segmentation
- FastAPI secure gateway
- Flask internal web application
- Runtime metrics endpoint
- Benchmark automation
- Wireshark traffic analysis support

---

# Architecture

```text
Client
   │
   │  ASCON-AEAD Encrypted Payload
   ▼
┌────────────────────┐
│  FastAPI Gateway   │
│  Encryption Layer  │
└────────────────────┘
   │
   │  Internal Docker Network
   ▼
┌────────────────────┐
│   Flask WebApp     │
└────────────────────┘
```

---

# Security Model

The secure gateway validates:

1. Authentication Tag
2. Associated Data
3. Request Timestamp
4. Request ID Replay Protection

The system rejects:
- modified ciphertext,
- replayed requests,
- invalid authentication tags,
- malformed encrypted payloads.

---

# Secure Payload Structure

```json
{
  "version": "ascon-aead128",
  "key_id": "key-v1",
  "nonce": "...",
  "ciphertext": "...",
  "tag": "...",
  "aad": {
    "client_id": "...",
    "request_id": "...",
    "timestamp": 1234567890,
    "path": "auth/login",
    "method": "POST"
  }
}
```

---

# Security Validation

| Security Test | Result |
|---|---|
| Replay Attack | Rejected |
| Tampered Ciphertext | Rejected |
| Authentication Tag Validation | Successful |
| Plaintext Exposure on Secure Endpoint | Not Visible |
| Plaintext Exposure on Insecure Endpoint | Visible |

---

# Benchmark Result

| Metric | Insecure | Secure ASCON-AEAD |
|---|---:|---:|
| Average Latency | 13.874 ms | 15.490 ms |
| P95 Latency | 17.905 ms | 20.028 ms |
| Success Rate | 100% | 100% |
| Payload Size | 45 bytes | 355 bytes |

### Average Overhead

- Average Latency Overhead: **1.616 ms**
- P95 Latency Overhead: **2.123 ms**
- Payload Overhead: **310 bytes**

---

# Benchmark Visualization

## Average Latency

![Average Latency](docs/images/benchmark_avg_latency.png)

---

## P95 Latency

![P95 Latency](docs/images/benchmark_p95_latency.png)

---

## Payload Size Comparison

![Payload Size](docs/images/benchmark_payload_size.png)

---

## Overhead Summary

![Overhead Summary](docs/images/benchmark_overhead_summary.png)

---

# Runtime Metrics

The system provides runtime observability via:

```http
GET /metrics
```

Example metrics:

```json
{
  "requests_total": 10,
  "secure_requests_total": 9,
  "decrypt_success": 7,
  "decrypt_failures": 1,
  "replay_rejected": 1,
  "tampered_rejected": 1,
  "avg_encrypt_ms": 1.085,
  "avg_decrypt_ms": 1.295
}
```

---

# Wireshark Traffic Analysis

The project includes comparative traffic analysis between:

- insecure plaintext communication
- ASCON-AEAD encrypted communication

Traffic analysis demonstrates that secure endpoints only expose:
- ciphertext
- nonce
- authentication tag
- associated data

while plaintext credentials remain hidden.

---

# Project Structure

```text
ascon-secure-gateway/
├── client/
├── gateway/
├── webapp/
├── scripts/
├── docs/
├── captures/
├── docker-compose.yml
└── README.md
```

---

# Run and Test

## 1. Clone Repository

```bash
git clone https://github.com/egayurcel990/ascon-secure-gateway.git
cd ascon-secure-gateway
```

## 2. Create Environment File

```bash
cp .env.example .env
```

## 3. Build and Start Containers

```bash
docker compose up -d --build
```

Check container status:

```bash
docker compose ps
```

Check gateway health:

```bash
curl http://localhost:8000/health
```

Expected result:

```json
{
  "status": "ok",
  "service": "ascon-aead-gateway",
  "version": "1.2.0"
}
```

## 4. Run CLI Security Demo

```bash
cd client
python3 demo.py
```

This demo validates:

- encrypted login request
- login failure handling
- token verification
- logout
- replay attack rejection
- tampered ciphertext rejection
- insecure plaintext comparison

## 5. Run Browser Web UI

From the project root:

```bash
cd client
python3 -m http.server 3000
```

Open:

```text
http://localhost:3000
```

Use demo credentials:

```text
username: admin
password: admin123
```

The web UI provides:

- browser-side ASCON-AEAD encryption
- encrypted login testing
- traffic monitor
- realtime security metrics
- Run Security Test button
- secure vs insecure request comparison

## 6. Run Automated Security Test from UI

Click:

```text
Run Security Test
```

The UI will automatically test:

- secure encrypted login
- replay attack rejection
- tampered ciphertext rejection
- insecure plaintext request comparison
- metrics update

Expected result:

| Test | Expected Result |
|---|---|
| Secure Login | 200 OK |
| Replay Attack | 400 Rejected |
| Tampered Ciphertext | 400 Rejected |
| Insecure Login | 200 OK, plaintext visible |

## 7. Check Runtime Metrics

```bash
curl http://localhost:8000/metrics
```

Example output:

```json
{
  "requests_total": 10,
  "secure_requests_total": 9,
  "insecure_requests_total": 1,
  "decrypt_success": 7,
  "decrypt_failures": 1,
  "replay_rejected": 1,
  "tampered_rejected": 1,
  "avg_encrypt_ms": 1.085,
  "avg_decrypt_ms": 1.2959,
  "avg_request_latency_ms": 20.9292
}
```

## 8. Capture Traffic with PCAP

Start capture:

```bash
sudo tcpdump -i any port 8000 -w captures/ascon-demo.pcap
```

Run CLI demo or browser UI test.

Stop capture:

```text
CTRL + C
```

Open the `.pcap` file in Wireshark.

Useful Wireshark filters:

```text
frame contains "ciphertext"
```

```text
frame contains "password"
```

Expected result:

- `/secure/auth/login` only exposes ciphertext, nonce, tag, and AAD.
- `/insecure/auth/login` exposes username and password in plaintext.

## 9. Run Benchmark

From project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests matplotlib
python3 scripts/benchmark.py
```

This generates:

```text
benchmark-result.json
```

## 10. Generate Benchmark Charts

```bash
python3 scripts/generate_benchmark_chart.py
```

Generated charts are saved to:

```text
docs/images/
```

## 11. Stop Containers

```bash
docker compose down
```

To remove volumes:

```bash
docker compose down -v
```

---

# Documentation

| Document | Description |
|---|---|
| `docs/BENCHMARK_REPORT.md` | Benchmark analysis |
| `docs/SECURITY_MODEL.md` | Security architecture |
| `docs/TESTING_GUIDE.md` | Testing procedure |

---

# Research Contribution

This project demonstrates the feasibility of integrating lightweight authenticated encryption into Docker-based microservice communication while maintaining relatively low latency overhead.

The implementation combines:
- lightweight cryptography,
- secure gateway architecture,
- runtime validation,
- replay protection,
- authenticated encrypted communication,
- and traffic analysis validation.

---

# Future Improvements

- Prometheus & Grafana integration
- Argon2 password hashing
- Key rotation support
- Redis-based distributed replay cache
- TLS integration
- Kubernetes deployment
- Load testing with k6
- CI/CD security pipeline

---

# License

This project is intended for educational, research, and security engineering purposes.
