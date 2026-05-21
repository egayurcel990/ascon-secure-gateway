# GitHub Push Checklist

Before pushing to GitHub, verify these items:

```bash
git status
```

Do not push:

- `.env`
- `client/venv/`
- `.venv/`
- `__pycache__/`
- `*.pyc`
- SQLite database files
- Large `.pcap` files unless intentionally included as evidence

Recommended first commit:

```bash
git init
git add .
git commit -m "feat: implement ASCON-AEAD secure gateway with replay protection"
```

Recommended repository description:

```text
Docker-based ASCON-AEAD secure gateway prototype with encrypted API payloads, replay protection, and Wireshark traffic evidence.
```
