# ASCON-AEAD Secure Gateway

Implementation of a Docker-based secure web gateway using ASCON-AEAD128 for encrypted API communication between a client and an internal web application.

This project was built as a cryptography final project prototype. The system demonstrates confidentiality, integrity protection, replay protection, and network segmentation using Docker.

## Project Focus

The main objective is to protect sensitive authentication payloads before they reach the internal web application. The client sends encrypted JSON payloads to a public gateway. The gateway decrypts and validates the payload, then forwards the plaintext request to an internal-only Flask web application.

Core security features:

- ASCON-AEAD128 encrypted request and response payloads
- Authentication tag verification
- Associated Data binding for path, method, timestamp, client ID, and request ID
- Replay attack protection using request ID and timestamp validation
- Docker network segmentation between public gateway and internal web application
- Insecure baseline endpoint for traffic comparison and Wireshark demonstration
- Tampered ciphertext rejection
- Basic runtime metrics endpoint

## Architecture

```text
Client
  |
  | HTTP JSON payload encrypted with ASCON-AEAD128
  v
Gateway FastAPI :8000
  |
  | Plain JSON forwarded only inside internal Docker network
  v
Internal Flask WebApp :5000
  |
  v
SQLite database volume
```

Docker network model:

```text
public_net
  Client -> Gateway :8000

internal_net
  Gateway -> WebApp :5000
  WebApp is not exposed to the host
```

The web application cannot be accessed directly from outside Docker. All external communication must go through the gateway.

## Request Payload Format

Secure requests use this payload structure:

```json
{
  "version": "ascon-aead128",
  "key_id": "key-v1",
  "nonce": "base64-nonce",
  "ciphertext": "base64-ciphertext",
  "tag": "base64-authentication-tag",
  "aad": {
    "client_id": "client-demo",
    "request_id": "uuid",
    "timestamp": 1779339575,
    "path": "auth/login",
    "method": "POST"
  }
}
```

The actual username and password are inside the ciphertext and are not visible in network capture for `/secure/auth/login`.

## Repository Structure

```text
ascon-secure-gateway/
├── client/                 # Python demo client and optional web UI
├── gateway/                # FastAPI ASCON-AEAD secure gateway
├── webapp/                 # Internal Flask authentication app
├── docs/                   # Technical documentation and security notes
├── captures/               # Optional local Wireshark/tcpdump evidence, ignored by Git
├── scripts/                # Utility scripts for testing and capture
├── tests/                  # Reserved for future automated tests
├── docker-compose.yml
├── .env.example
├── .gitignore
├── .dockerignore
└── README.md
```

## Requirements

- Docker
- Docker Compose
- Python 3.10+
- Optional: Wireshark or tcpdump for packet capture

## Quick Start

Copy the environment template:

```bash
cp .env.example .env
```

Build and run the services:

```bash
docker compose up -d --build
```

Check service status:

```bash
docker compose ps
curl http://localhost:8000/health
curl http://localhost:8000/info
```

Run the client demo:

```bash
cd client
python3 demo.py
```

If `requests` is not installed, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
python3 demo.py
```

## Demo Accounts

| Username | Password |
|---|---|
| admin | admin123 |
| alice | user123 |

## Testing Scenarios

The demo script performs these checks:

| Scenario | Expected Result |
|---|---|
| Register user | New user is created or duplicate is rejected |
| Valid login | Login succeeds and token is returned |
| Invalid login | Request is rejected |
| Token verification | Valid token is accepted |
| Profile request | User profile is returned |
| Logout | Session is removed |
| Replay attack | Reused encrypted payload is rejected |
| Tampered ciphertext | Modified ciphertext is rejected due to invalid authentication tag |
| Insecure baseline | Username and password are visible as plaintext |

Expected security evidence:

```text
Replay request status: 400
Invalid encrypted payload: request replay terdeteksi
```

```text
Decryption failed: authentication tag invalid
```

## Packet Capture Evidence

Recommended capture method from WSL/Linux:

```bash
sudo tcpdump -i any port 8000 -w captures/ascon-demo.pcap
```

In another terminal:

```bash
cd client
python3 demo.py
```

Stop tcpdump with `Ctrl + C`, then open the `.pcap` file in Wireshark.

Useful Wireshark filters:

```text
tcp.port == 8000
frame contains "ciphertext"
frame contains "password"
frame contains "replay"
frame contains "authentication tag invalid"
```

What to capture for documentation:

| Evidence | Wireshark Filter | Expected Finding |
|---|---|---|
| Secure login | `frame contains "ciphertext"` | Payload contains nonce, ciphertext, tag, and aad |
| Insecure login | `frame contains "password"` | Username and password are visible |
| Replay rejection | `frame contains "replay"` | Gateway rejects reused request |
| Tampered payload | `frame contains "authentication tag invalid"` | Gateway rejects modified ciphertext |

## Metrics

Gateway metrics are available at:

```text
GET /metrics
```

Example tracked values:

- `secure_requests_total`
- `decrypt_success_total`
- `decrypt_failed_total`
- `replay_rejected_total`
- `tampered_rejected_total`
- `insecure_requests_total`
- `last_decrypt_ms`
- `last_encrypt_ms`

## Environment Variables

Use `.env.example` as the template:

```env
ASCON_PSK=deadbeefcafebabedeadbeefcafebabe
ASCON_DEFAULT_KEY_ID=key-v1
DEMO_MODE=true
REPLAY_WINDOW_SECONDS=300
MAX_REPLAY_CACHE=10000
```

For demonstration, `DEMO_MODE=true` enables `/insecure/{path}` as a plaintext baseline. For a stricter deployment, set:

```env
DEMO_MODE=false
```

## Security Notes

This repository is a research and educational prototype, not a production-ready cryptographic product.

Current security properties:

- Confidentiality through ASCON-AEAD128 encryption
- Integrity and authenticity through tag verification
- Associated Data binding for endpoint metadata
- Replay resistance using timestamp and request ID validation
- Internal service isolation through Docker network segmentation

Known limitations:

- The pre-shared key is loaded from environment variables
- Replay cache is in-memory and not shared across multiple gateway replicas
- The web application still uses a simple password hashing approach for demonstration
- TLS is not enabled because the project focuses on application-layer ASCON payload protection
- The insecure endpoint exists only for experimental comparison

Recommended next improvements:

- Replace demo PSK handling with Docker Secrets or a KMS-like secret manager
- Add Argon2id or bcrypt password hashing
- Add rate limiting for authentication endpoints
- Add automated unit and integration tests
- Add benchmark scripts for latency, throughput, and payload overhead
- Add Prometheus/Grafana observability
- Harden containers with non-root users and stricter runtime options
