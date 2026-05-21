# Stage 1 Security Upgrade

Upgrade ini mengubah gateway dari mode `confidentiality-only` menjadi `ASCON-AEAD secure gateway`.

## Perubahan utama

1. **Tag verification aktif**
   - `ascon_decrypt()` sekarang memverifikasi authentication tag.
   - Ciphertext, nonce, key, atau AAD yang berubah akan ditolak.

2. **Payload format baru**

```json
{
  "version": "ascon-aead128",
  "key_id": "key-v1",
  "nonce": "base64...",
  "ciphertext": "base64...",
  "tag": "base64...",
  "aad": {
    "client_id": "client-demo",
    "request_id": "uuid",
    "timestamp": 1710000000,
    "path": "auth/login",
    "method": "POST"
  }
}
```

3. **Associated Data binding**
   - Metadata request tidak dienkripsi, tetapi ikut diautentikasi.
   - Jika path/method/AAD berubah, tag verification gagal.

4. **Replay protection dasar**
   - Gateway menyimpan `client_id + request_id` dalam cache in-memory.
   - Request yang sama akan ditolak sebagai replay.
   - Untuk multi-instance production, cache ini sebaiknya dipindahkan ke Redis.

5. **Insecure baseline endpoint**
   - `/insecure/{path}` hanya aktif jika `DEMO_MODE=true`.
   - Endpoint ini dipakai untuk pembanding Wireshark: plaintext vs encrypted traffic.

6. **Metrics endpoint**
   - `/metrics` menampilkan counter request, decrypt success/failure, replay rejected, dan tampered rejected.

## Cara menjalankan

```bash
cp .env.example .env
docker-compose up -d --build
python client/demo.py
```

## Demo yang tersedia

- Login/register encrypted.
- Payload secure yang terlihat di network.
- Replay attack rejected.
- Tampered ciphertext rejected.
- Insecure plaintext baseline untuk Wireshark.

## Catatan

Folder `client/venv/` tidak perlu dimasukkan ke repository. Gunakan virtual environment lokal dan pastikan `.gitignore` aktif.
