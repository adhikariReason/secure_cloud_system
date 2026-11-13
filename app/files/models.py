import uuid

from django.conf import settings
from django.db import models

User = settings.AUTH_USER_MODEL


class UserKeys(models.Model):
    """A user's RSA key pair. The private key is stored ONLY encrypted with the user's password."""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="keys")
    public_pem = models.TextField()
    private_salt = models.BinaryField(max_length=16)     # scrypt salt
    private_nonce = models.BinaryField(max_length=12)    # AES-GCM nonce
    private_ciphertext = models.BinaryField()            # AES-GCM(password key, private key DER)
    created_at = models.DateTimeField(auto_now_add=True)

    def fingerprint(self):
        import hashlib
        return hashlib.sha256(self.public_pem.encode()).hexdigest()[:16]


class StoredFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="files")
    name = models.CharField(max_length=255)          # original filename (shown to users)
    size = models.BigIntegerField()                  # plaintext size in bytes
    nonce = models.BinaryField(max_length=12)        # AES-GCM nonce for this file
    wrapped_key = models.BinaryField()               # file key encrypted with the owner's public key (RSA-OAEP)
    sha256 = models.CharField(max_length=64)         # hash of the original plaintext
    signature = models.BinaryField()                 # owner's RSA-PSS signature over signed_message()
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def path(self):
        # encrypted blob on disk is named by the random UUID, not the user's filename
        return settings.PRIVATE_STORAGE_ROOT / f"{self.id}.enc"

    def aad(self):
        return str(self.id).encode()

    def signed_message(self):
        return f"securecloud-file|{self.id}|{self.name}|{self.size}|{self.sha256}".encode()

    def extension(self):
        return self.name.rsplit(".", 1)[-1].lower() if "." in self.name else ""


class FileShare(models.Model):
    """A copy of the file key, encrypted with the recipient's public key."""
    file = models.ForeignKey(StoredFile, on_delete=models.CASCADE, related_name="shares")
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="shared_with_me")
    wrapped_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["file", "recipient"], name="one_share_per_recipient")]


class AuditEntry(models.Model):
    """Append-only, hash-chained, signed log. entry_hash covers the previous entry's hash,
    so editing or deleting any earlier row breaks every hash after it."""
    timestamp = models.DateTimeField()
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    username = models.CharField(max_length=150)       # kept even if the user is deleted
    action = models.CharField(max_length=32)
    file_id = models.CharField(max_length=36, blank=True)
    file_name = models.CharField(max_length=255, blank=True)
    file_sha256 = models.CharField(max_length=64, blank=True)
    detail = models.CharField(max_length=255, blank=True)
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64)
    signature = models.BinaryField(null=True)          # user's RSA-PSS signature over entry_hash
    signer_public_pem = models.TextField(blank=True)    # key that signed it (verifiable later)

    class Meta:
        ordering = ["id"]

    def canonical(self):
        return "|".join([
            self.prev_hash, self.timestamp.isoformat(), self.username, self.action,
            self.file_id, self.file_name, self.file_sha256, self.detail,
        ]).encode()
