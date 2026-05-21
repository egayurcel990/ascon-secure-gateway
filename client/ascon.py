"""
ASCON-128 Manual Implementation
================================
Implementasi manual ASCON-128 berdasarkan spesifikasi resmi:
https://ascon.iaik.tugraz.at/

ASCON adalah algoritma authenticated encryption yang dipilih NIST (2023)
sebagai standar lightweight cryptography.

Untuk project ini hanya digunakan bagian ENCRYPTION (Confidentiality / CIA Triad).
Integrity dan Authentication sudah diaktifkan melalui verifikasi tag AEAD.

Author  : [Nama Kamu]
Version : 1.0.0
"""

import struct
import os
import hmac


class InvalidTagError(Exception):
    """Raised when ASCON authentication tag verification fails."""
    pass


# ---------------------------------------------------------------------------
# ASCON CONSTANTS
# ---------------------------------------------------------------------------

# Round constants untuk permutasi (12 round untuk initialization & finalization,
# 6 round untuk permutasi di encryption)
ROUND_CONSTANTS = [
    0xf0, 0xe1, 0xd2, 0xc3,
    0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b,
]

# Parameter ASCON-128
ASCON128_KEY_LEN   = 16   # 128 bit = 16 byte
ASCON128_NONCE_LEN = 16   # 128 bit = 16 byte
ASCON128_TAG_LEN   = 16   # 128 bit = 16 byte
ASCON128_IV        = 0x80400c0600000000  # IV resmi dari spesifikasi


# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

def _rotr(val: int, n: int) -> int:
    """Rotate right 64-bit integer."""
    return ((val >> n) | (val << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _bytes_to_state(b: bytes) -> list[int]:
    """Convert 40 bytes menjadi 5 word 64-bit (state ASCON)."""
    return list(struct.unpack(">5Q", b))


def _state_to_bytes(state: list[int]) -> bytes:
    """Convert 5 word 64-bit menjadi 40 bytes."""
    return struct.pack(">5Q", *state)


def _int_to_bytes(val: int, length: int) -> bytes:
    return val.to_bytes(length, byteorder="big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# ASCON PERMUTATION
# ---------------------------------------------------------------------------

def _permutation(state: list[int], rounds: int) -> list[int]:
    """
    ASCON permutation p^a (a = jumlah rounds).
    Terdiri dari 3 layer:
      1. Constant Addition
      2. Substitution Layer (S-box 5-bit)
      3. Linear Diffusion Layer
    """
    s = state[:]   # copy state

    start_round = 12 - rounds
    for r in range(start_round, 12):

        # ── 1. Constant Addition ──────────────────────────────────────────
        s[2] ^= ROUND_CONSTANTS[r]

        # ── 2. Substitution Layer (ASCON S-box, applied bitsliced) ────────
        # S-box bekerja pada 5 bit yang diambil dari posisi bit yang sama
        # di setiap word state. Implementasi bitsliced berikut mengikuti
        # referensi resmi ASCON.
        s[0] ^= s[4]
        s[4] ^= s[3]
        s[2] ^= s[1]

        t = [
            (s[0] ^ 0xFFFFFFFFFFFFFFFF) & s[1],
            (s[1] ^ 0xFFFFFFFFFFFFFFFF) & s[2],
            (s[2] ^ 0xFFFFFFFFFFFFFFFF) & s[3],
            (s[3] ^ 0xFFFFFFFFFFFFFFFF) & s[4],
            (s[4] ^ 0xFFFFFFFFFFFFFFFF) & s[0],
        ]

        s[0] ^= t[1]
        s[1] ^= t[2]
        s[2] ^= t[3]
        s[3] ^= t[4]
        s[4] ^= t[0]

        s[1] ^= s[0]
        s[0] ^= s[4]
        s[3] ^= s[2]
        s[2] ^= 0xFFFFFFFFFFFFFFFF

        # ── 3. Linear Diffusion Layer ─────────────────────────────────────
        # Setiap word di-XOR dengan dua rotasi dari dirinya sendiri.
        # Nilai rotasi diambil langsung dari spesifikasi ASCON.
        s[0] ^= _rotr(s[0], 19) ^ _rotr(s[0], 28)
        s[1] ^= _rotr(s[1], 61) ^ _rotr(s[1], 39)
        s[2] ^= _rotr(s[2],  1) ^ _rotr(s[2],  6)
        s[3] ^= _rotr(s[3], 10) ^ _rotr(s[3], 17)
        s[4] ^= _rotr(s[4],  7) ^ _rotr(s[4], 41)

    return s


# ---------------------------------------------------------------------------
# ASCON-128 CORE
# ---------------------------------------------------------------------------

def ascon_encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Enkripsi menggunakan ASCON-128 dengan output ciphertext + tag.

    Perbaikan penting:
    - Panjang ciphertext sekarang selalu sama dengan panjang plaintext.
    - Jika panjang plaintext kelipatan 8 byte, padding tetap diserap ke state,
      tetapi tidak ikut dikirim sebagai ciphertext.
    """
    assert len(key) == ASCON128_KEY_LEN, f"Key harus 16 byte, dapat {len(key)}"
    assert len(nonce) == ASCON128_NONCE_LEN, f"Nonce harus 16 byte, dapat {len(nonce)}"

    k0, k1 = struct.unpack(">2Q", key)
    n0, n1 = struct.unpack(">2Q", nonce)

    # INITIALIZATION
    state = [ASCON128_IV, k0, k1, n0, n1]
    state = _permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    # ASSOCIATED DATA
    if associated_data:
        ad_padded = associated_data + b"\x80" + b"\x00" * (7 - len(associated_data) % 8)
        for i in range(0, len(ad_padded), 8):
            block = struct.unpack(">Q", ad_padded[i:i + 8])[0]
            state[0] ^= block
            state = _permutation(state, 6)

    # Domain separation
    state[4] ^= 1

    # PLAINTEXT
    ciphertext = b""
    offset = 0

    # Proses semua full block plaintext.
    while offset + 8 <= len(plaintext):
        block = struct.unpack(">Q", plaintext[offset:offset + 8])[0]
        state[0] ^= block
        ciphertext += struct.pack(">Q", state[0])
        state = _permutation(state, 6)
        offset += 8

    # Proses final partial block + padding. Untuk plaintext kelipatan 8,
    # bagian ini hanya menyerap padding dan tidak menambah ciphertext.
    remaining = plaintext[offset:]
    pad_len = 8 - len(remaining) - 1
    final_block = remaining + b"\x80" + b"\x00" * pad_len
    final_word = struct.unpack(">Q", final_block)[0]
    state[0] ^= final_word
    ciphertext += struct.pack(">Q", state[0])[:len(remaining)]

    # FINALIZATION
    state[1] ^= k0
    state[2] ^= k1
    state = _permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    tag = struct.pack(">2Q", state[3], state[4])
    return ciphertext + tag


def ascon_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Dekripsi menggunakan ASCON-128 dan verifikasi tag AEAD.

    Jika ciphertext, tag, nonce, key, atau associated_data berubah,
    fungsi akan raise InvalidTagError.
    """
    assert len(key) == ASCON128_KEY_LEN
    assert len(nonce) == ASCON128_NONCE_LEN
    assert len(ciphertext_with_tag) >= ASCON128_TAG_LEN

    ciphertext = ciphertext_with_tag[:-ASCON128_TAG_LEN]
    received_tag = ciphertext_with_tag[-ASCON128_TAG_LEN:]

    k0, k1 = struct.unpack(">2Q", key)
    n0, n1 = struct.unpack(">2Q", nonce)

    # INITIALIZATION
    state = [ASCON128_IV, k0, k1, n0, n1]
    state = _permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    # ASSOCIATED DATA
    if associated_data:
        ad_padded = associated_data + b"\x80" + b"\x00" * (7 - len(associated_data) % 8)
        for i in range(0, len(ad_padded), 8):
            block = struct.unpack(">Q", ad_padded[i:i + 8])[0]
            state[0] ^= block
            state = _permutation(state, 6)

    state[4] ^= 1

    # CIPHERTEXT
    plaintext = b""
    offset = 0

    # Proses semua full block ciphertext.
    while offset + 8 <= len(ciphertext):
        c_word = struct.unpack(">Q", ciphertext[offset:offset + 8])[0]
        p_word = state[0] ^ c_word
        plaintext += struct.pack(">Q", p_word)
        state[0] = c_word
        state = _permutation(state, 6)
        offset += 8

    # Proses final partial block + padding.
    remaining = ciphertext[offset:]
    if remaining:
        stream = struct.pack(">Q", state[0])
        p_last = _xor_bytes(remaining, stream[:len(remaining)])
        plaintext += p_last

        # Rekonstruksi state setelah absorb partial plaintext + padding.
        padded_plain = p_last + b"\x80" + b"\x00" * (7 - len(p_last))
        final_word = struct.unpack(">Q", padded_plain)[0]
        state[0] ^= final_word
    else:
        # Plaintext kelipatan 8 byte: hanya padding yang diserap.
        state[0] ^= 0x8000000000000000

    # FINALIZATION
    state[1] ^= k0
    state[2] ^= k1
    state = _permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    calculated_tag = struct.pack(">2Q", state[3], state[4])
    if not hmac.compare_digest(received_tag, calculated_tag):
        raise InvalidTagError("ASCON authentication tag verification failed")

    return plaintext


# ---------------------------------------------------------------------------
# KEY MANAGEMENT HELPERS
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """Generate random 128-bit key."""
    return os.urandom(ASCON128_KEY_LEN)


def generate_nonce() -> bytes:
    """Generate random 128-bit nonce. Harus unik setiap enkripsi!"""
    return os.urandom(ASCON128_NONCE_LEN)


# ---------------------------------------------------------------------------
# QUICK SELF-TEST
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  ASCON-128 Self-Test")
    print("=" * 55)

    key   = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt    = b"Hello, ASCON!"
    ad    = b"header"

    ct = ascon_encrypt(key, nonce, pt, ad)
    print(f"Plaintext  : {pt}")
    print(f"Key        : {key.hex()}")
    print(f"Nonce      : {nonce.hex()}")
    print(f"Ciphertext : {ct.hex()}")

    recovered = ascon_decrypt(key, nonce, ct, ad)
    print(f"Decrypted  : {recovered}")
    print(f"Match      : {pt == recovered}")
    assert pt == recovered, "DECRYPT GAGAL!"
    print("\n✓ ASCON-128 berjalan dengan benar.")
