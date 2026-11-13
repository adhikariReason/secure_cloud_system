import io
import logging
import time
from functools import wraps
from pathlib import Path

from cryptography.exceptions import InvalidTag
from django.contrib import messages
from django.contrib.auth import get_user_model, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db.models import Count, Q
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import crypto, keys
from .models import AuditEntry, FileShare, StoredFile

log = logging.getLogger(__name__)
User = get_user_model()
MAX_SIZE = 1024 ** 3  # 1 GB
ALLOWED_TYPES = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".pptx", ".csv", ".zip", ".bin"}


class IntegrityFailure(Exception):
    pass


def key_required(view):
    """Login required AND the session's private key must be recoverable (DB half + cookie half)."""
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        request.private_key = keys.session_private_key(request)
        if request.private_key is None:
            auth_logout(request)
            messages.error(request, "Your session key is no longer available. Please sign in again.")
            return redirect("login")
        return view(request, *args, **kwargs)
    return wrapper


# ---------- accounts ----------

def register(request):
    form = UserCreationForm(request.POST or None)
    if form.is_valid():
        user = form.save()
        private_key = keys.create_keys(user, form.cleaned_data["password1"])
        keys.audit(user, "register", private_key, detail=f"key {user.keys.fingerprint()}")
        messages.success(request, "Account created. Your encryption keys were generated. Sign in to continue.")
        return redirect("login")
    return render(request, "registration/register.html", {"form": form})


def login_view(request):
    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            user = form.get_user()
            try:
                private_key = keys.unlock(user, form.cleaned_data["password"])
            except InvalidTag:
                messages.error(request, "Your private key could not be unlocked.")
                return redirect("login")
            auth_login(request, user)
            nxt = request.GET.get("next", "")
            safe = url_has_allowed_host_and_scheme(nxt, {request.get_host()}, require_https=True)
            response = redirect(nxt if safe and nxt else "file_list")
            keys.start_session(request, response, private_key)
            keys.audit(user, "login", private_key)
            return response
        keys.audit(None, "login_failed", username=request.POST.get("username", "")[:150] or "?")
    return render(request, "registration/login.html", {"form": form})


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        keys.audit(request.user, "logout", keys.session_private_key(request))
    auth_logout(request)
    response = redirect("login")
    response.delete_cookie(keys.COOKIE, samesite="Strict")
    return response


# ---------- helpers ----------

def _accessible(request, file_id):
    """Owner or explicit share recipient; everyone else gets 404 (same as a file that doesn't exist)."""
    record = StoredFile.objects.select_related("owner").filter(id=file_id).first()
    if record is None:
        raise Http404
    if record.owner_id == request.user.id:
        return record, bytes(record.wrapped_key), None
    share = record.shares.filter(recipient=request.user).first()
    if share is None:
        raise Http404
    return record, bytes(share.wrapped_key), share


def _decrypt_and_verify(record, wrapped_key, private_key):
    """Unwrap file key -> AES-GCM decrypt -> check SHA-256 -> check owner's signature."""
    try:
        file_key = crypto.unwrap_key(private_key, wrapped_key)
        data = crypto.decrypt_file(file_key, bytes(record.nonce), record.path().read_bytes(), record.aad())
    except (InvalidTag, ValueError, FileNotFoundError) as exc:
        raise IntegrityFailure(f"decryption failed ({type(exc).__name__})")
    if crypto.sha256_hex(data) != record.sha256:
        raise IntegrityFailure("SHA-256 mismatch")
    if not crypto.verify(keys.public_key_of(record.owner), bytes(record.signature), record.signed_message()):
        raise IntegrityFailure(f"signature by {record.owner.username} is not valid")
    return data


def _owned(request, file_id):
    return get_object_or_404(StoredFile, id=file_id, owner=request.user)


# ---------- files ----------

@key_required
def file_list(request):
    files = (StoredFile.objects.filter(owner=request.user)
             .annotate(share_count=Count("shares")).order_by("-uploaded_at"))
    return render(request, "files/list.html", {"files": files, "tab": "files",
                                               "allowed": sorted(ALLOWED_TYPES)})


@key_required
def shared_list(request):
    shares = (FileShare.objects.filter(recipient=request.user)
              .select_related("file", "file__owner").order_by("-created_at"))
    return render(request, "files/shared.html", {"shares": shares, "tab": "shared"})


@key_required
@require_POST
def upload(request):
    f = request.FILES.get("file")
    if f is None:
        messages.error(request, "Choose a file first.")
    elif Path(f.name).suffix.lower() not in ALLOWED_TYPES:
        messages.error(request, f"“{f.name}” was rejected: file type not allowed.")
    elif f.size > MAX_SIZE:
        messages.error(request, f"“{f.name}” was rejected: larger than 1 GB.")
    else:
        data = f.read()
        record = StoredFile(owner=request.user, name=Path(f.name).name[:255], size=len(data),
                            sha256=crypto.sha256_hex(data))
        start = time.perf_counter()
        file_key, record.nonce, ciphertext = crypto.encrypt_file(data, record.aad())
        log.info("encrypt %s bytes in %.3fs", len(data), time.perf_counter() - start)
        record.wrapped_key = crypto.wrap_key(keys.public_key_of(request.user), file_key)
        record.signature = crypto.sign(request.private_key, record.signed_message())
        record.path().write_bytes(ciphertext)
        record.save()
        keys.audit(request.user, "upload", request.private_key, file=record)
        messages.success(request, f"Uploaded “{record.name}”. Encrypted and signed.")
    return redirect("file_list")


@key_required
def download(request, file_id):
    record, wrapped_key, _ = _accessible(request, file_id)
    start = time.perf_counter()
    try:
        data = _decrypt_and_verify(record, wrapped_key, request.private_key)
    except IntegrityFailure as exc:
        log.warning("integrity check FAILED for %s: %s", record.id, exc)
        keys.audit(request.user, "integrity_fail", request.private_key, file=record, detail=str(exc))
        return render(request, "files/rejected.html", {"record": record, "reason": str(exc)}, status=400)
    log.info("decrypt %s bytes in %.3fs", record.size, time.perf_counter() - start)
    keys.audit(request.user, "download", request.private_key, file=record)
    return FileResponse(io.BytesIO(data), as_attachment=True, filename=record.name)


@key_required
def detail(request, file_id):
    record, _, share = _accessible(request, file_id)
    is_owner = share is None
    shares = record.shares.select_related("recipient").order_by("created_at") if is_owner else []
    return render(request, "files/detail.html", {
        "record": record, "is_owner": is_owner, "shares": shares,
        "tab": "files" if is_owner else "shared",
        "wrapped_len": len(bytes(record.wrapped_key)), "sig_len": len(bytes(record.signature)),
        "owner_fp": record.owner.keys.fingerprint(),
    })


@key_required
@require_POST
def verify(request, file_id):
    record, wrapped_key, _ = _accessible(request, file_id)
    try:
        _decrypt_and_verify(record, wrapped_key, request.private_key)
    except IntegrityFailure as exc:
        keys.audit(request.user, "integrity_fail", request.private_key, file=record, detail=str(exc))
        messages.error(request, f"Integrity check failed: {exc}.")
    else:
        keys.audit(request.user, "verify", request.private_key, file=record, detail="ok")
        messages.success(request, f"Verified: decrypts correctly, SHA-256 matches, signed by {record.owner.username}.")
    return redirect("detail", file_id=record.id)


@key_required
@require_POST
def share(request, file_id):
    record = _owned(request, file_id)
    username = request.POST.get("username", "").strip()
    recipient = User.objects.filter(username=username).select_related("keys").first()
    if recipient is None or not hasattr(recipient, "keys"):
        messages.error(request, f"No user named “{username}”.")
    elif recipient == request.user:
        messages.error(request, "You already own this file.")
    elif record.shares.filter(recipient=recipient).exists():
        messages.error(request, f"Already shared with {recipient.username}.")
    else:
        file_key = crypto.unwrap_key(request.private_key, bytes(record.wrapped_key))
        FileShare.objects.create(file=record, recipient=recipient,
                                 wrapped_key=crypto.wrap_key(keys.public_key_of(recipient), file_key))
        keys.audit(request.user, "share", request.private_key, file=record, detail=f"to {recipient.username}")
        messages.success(request, f"Shared with {recipient.username}. Their copy of the file key is encrypted with their public key.")
    return redirect("detail", file_id=record.id)


@key_required
@require_POST
def unshare(request, file_id, share_id):
    record = _owned(request, file_id)
    s = get_object_or_404(FileShare, id=share_id, file=record)
    name = s.recipient.username
    s.delete()
    keys.audit(request.user, "unshare", request.private_key, file=record, detail=f"from {name}")
    messages.success(request, f"Access removed for {name}.")
    return redirect("detail", file_id=record.id)


@key_required
@require_POST
def delete(request, file_id):
    record = _owned(request, file_id)  # only the owner can delete; others get 404
    keys.audit(request.user, "delete", request.private_key, file=record)
    record.path().unlink(missing_ok=True)
    name = record.name
    record.delete()
    messages.success(request, f"Deleted “{name}”.")
    return redirect("file_list")


@key_required
def audit_log(request):
    chain_ok, first_broken, status = keys.verify_chain()
    mine = set(StoredFile.objects.filter(owner=request.user).values_list("id", flat=True))
    mine |= set(FileShare.objects.filter(recipient=request.user).values_list("file_id", flat=True))
    entries = (AuditEntry.objects.filter(Q(user=request.user) | Q(file_id__in=[str(i) for i in mine]))
               .order_by("-id")[:200])
    rows = [(e, status.get(e.id)) for e in entries]
    return render(request, "files/audit.html", {
        "rows": rows, "chain_ok": chain_ok, "first_broken": first_broken,
        "total": AuditEntry.objects.count(), "tab": "audit",
    })
