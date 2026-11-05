import uuid

from django.conf import settings
from django.db import models


class StoredFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)          # original filename (shown to the user)
    size = models.BigIntegerField()                  # plaintext size in bytes
    nonce = models.BinaryField(max_length=12)        # AES-GCM nonce for this file
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def path(self):
        # encrypted blob on disk is named by the random UUID, not the user's filename
        return settings.PRIVATE_STORAGE_ROOT / f"{self.id}.enc"
