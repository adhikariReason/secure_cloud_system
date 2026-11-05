import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings


def _key():
    # 256-bit master key, read from the Docker secret file (never hard-coded, never stored with the files)
    return bytes.fromhex(Path(settings.MASTER_KEY_FILE).read_text().strip())


def encrypt(data: bytes, aad: bytes):
    nonce = os.urandom(12)                      # fresh random 96-bit nonce for every file
    ciphertext = AESGCM(_key()).encrypt(nonce, data, aad)   # ciphertext + 16-byte auth tag
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    # raises cryptography.exceptions.InvalidTag if the file or nonce was tampered with
    return AESGCM(_key()).decrypt(nonce, ciphertext, aad)
