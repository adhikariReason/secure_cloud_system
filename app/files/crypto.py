"""All cryptography for Secure Cloud lives in this file.

Key hierarchy (nothing usable is stored in plaintext):

    user password --scrypt--> password key --AES-GCM--> user's RSA private key
    user's RSA public key --RSA-OAEP--> per-file AES-256 key --AES-GCM--> file
    user's RSA private key --RSA-PSS--> signatures on files and audit entries
"""
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1   # deliberately slow: makes password guessing expensive


# ---------- per-user RSA key pair ----------

def new_user_keypair():
    """Return (private_key, public_pem). RSA-2048, generated from the OS CSPRNG."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, public_pem


def private_key_to_der(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def private_key_from_der(der: bytes):
    return serialization.load_der_private_key(der, password=None)


def load_public_key(public_pem: str):
    return serialization.load_pem_public_key(public_pem.encode())


def _password_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())


def lock_private_key(private_key, password: str, aad: bytes):
    """Encrypt the private key with a key derived from the user's password.
    Returns (salt, nonce, ciphertext) to store in the database."""
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(_password_key(password, salt)).encrypt(nonce, private_key_to_der(private_key), aad)
    return salt, nonce, ciphertext


def unlock_private_key(password: str, salt: bytes, nonce: bytes, ciphertext: bytes, aad: bytes):
    """Raises InvalidTag if the password is wrong or the stored key was modified."""
    der = AESGCM(_password_key(password, salt)).decrypt(nonce, ciphertext, aad)
    return private_key_from_der(der)


# ---------- per-file hybrid encryption ----------

def encrypt_file(data: bytes, aad: bytes):
    """Fresh random AES-256 key + fresh random 96-bit nonce for every file.
    One key is used for exactly one encryption, so a nonce can never repeat under the same key."""
    file_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    return file_key, nonce, AESGCM(file_key).encrypt(nonce, data, aad)


def decrypt_file(file_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if anything was altered."""
    return AESGCM(file_key).decrypt(nonce, ciphertext, aad)


def wrap_key(public_key, file_key: bytes) -> bytes:
    return public_key.encrypt(file_key, OAEP)


def unwrap_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, OAEP)


# ---------- signatures and hashing ----------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, PSS, hashes.SHA256())


def verify(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, PSS, hashes.SHA256())
        return True
    except Exception:
        return False


# ---------- session key splitting ----------

def seal_for_session(private_key, aad: bytes):
    """Encrypt the unlocked private key with a random key that is only kept in the browser cookie.
    Returns (cookie_key, nonce, ciphertext). The server session stores nonce+ciphertext only."""
    cookie_key, nonce = os.urandom(32), os.urandom(12)
    return cookie_key, nonce, AESGCM(cookie_key).encrypt(nonce, private_key_to_der(private_key), aad)


def open_from_session(cookie_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes):
    return private_key_from_der(AESGCM(cookie_key).decrypt(nonce, ciphertext, aad))
