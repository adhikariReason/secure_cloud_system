import io
import logging
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.http import FileResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .crypto import decrypt, encrypt
from .models import StoredFile

log = logging.getLogger(__name__)
MAX_SIZE = 1024 ** 3  # 1 GB
ALLOWED_TYPES = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".docx", ".zip", ".bin"}


def register(request):
    form = UserCreationForm(request.POST or None)
    if form.is_valid():
        form.save()
        messages.success(request, "Account created. Please log in.")
        return redirect("login")
    return render(request, "registration/register.html", {"form": form})


@login_required
def file_list(request):
    files = StoredFile.objects.filter(owner=request.user).order_by("-uploaded_at")
    return render(request, "files/list.html", {"files": files})


@login_required
@require_POST
def upload(request):
    f = request.FILES.get("file")
    if f is None:
        messages.error(request, "Choose a file first.")
    elif Path(f.name).suffix.lower() not in ALLOWED_TYPES:
        messages.error(request, "File type not allowed.")
    elif f.size > MAX_SIZE:
        messages.error(request, "File is larger than 1 GB.")
    else:
        record = StoredFile(owner=request.user, name=Path(f.name).name, size=f.size)
        start = time.perf_counter()
        record.nonce, ciphertext = encrypt(f.read(), aad=str(record.id).encode())
        log.info("encrypt %s bytes in %.3fs", f.size, time.perf_counter() - start)
        record.path().write_bytes(ciphertext)
        record.save()
        messages.success(request, f"Uploaded {record.name} (encrypted).")
    return redirect("file_list")


@login_required
def download(request, file_id):
    # owner=request.user -> another user's file gives 404, exactly like a file that doesn't exist
    record = get_object_or_404(StoredFile, id=file_id, owner=request.user)
    start = time.perf_counter()
    try:
        data = decrypt(bytes(record.nonce), record.path().read_bytes(), aad=str(record.id).encode())
    except InvalidTag:
        log.warning("integrity check FAILED for %s", record.id)
        return HttpResponseBadRequest("Integrity check failed: file was modified. Download rejected.")
    log.info("decrypt %s bytes in %.3fs", record.size, time.perf_counter() - start)
    return FileResponse(io.BytesIO(data), as_attachment=True, filename=record.name)


@login_required
@require_POST
def delete(request, file_id):
    record = get_object_or_404(StoredFile, id=file_id, owner=request.user)
    record.path().unlink(missing_ok=True)
    record.delete()
    messages.success(request, f"Deleted {record.name}.")
    return redirect("file_list")
