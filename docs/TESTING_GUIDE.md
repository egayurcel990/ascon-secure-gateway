# Testing Guide

## 1. Start the System

```bash
cp .env.example .env
docker compose down -v
docker compose up -d --build
```

Check health:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/info
```

## 2. Run Functional and Security Demo

```bash
cd client
python3 demo.py
```

Expected results:

- Valid login returns HTTP 200.
- Wrong password returns HTTP 401.
- Replay attack returns HTTP 400.
- Tampered ciphertext returns HTTP 400.
- Insecure baseline returns plaintext response.

## 3. Capture Traffic into PCAP

From project root:

```bash
mkdir -p captures
sudo tcpdump -i any port 8000 -w captures/ascon-demo.pcap
```

Run demo in another terminal:

```bash
cd client
python3 demo.py
```

Stop tcpdump with `Ctrl + C`.

## 4. Analyze in Wireshark

Open `captures/ascon-demo.pcap` with Wireshark.

Recommended filters:

```text
tcp.port == 8000
frame contains "ciphertext"
frame contains "password"
frame contains "replay"
frame contains "authentication tag invalid"
```

Screenshots to collect:

1. `/secure/auth/login`: shows ciphertext, nonce, tag, and aad.
2. `/insecure/auth/login`: shows username and password in plaintext.
3. Replay rejection: shows `request replay terdeteksi`.
4. Tampered ciphertext rejection: shows `authentication tag invalid`.
