"""Key management and the audit log: the glue between crypto.py and the views."""
import base64

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import crypto
from .models import AuditEntry, UserKeys

COOKIE = "sc_key"          # browser half of the session key split
GENESIS = "0" * 64         # prev_hash of the very first audit entry


def _user_aad(user):
    return f"securecloud-user|{user.pk}".encode()


def _session_aad(user):
    return f"securecloud-session|{user.pk}".encode()


# ---------- user key pairs ----------

def create_keys(user, password):
    """Called at registration: new RSA key pair, private key locked with the password."""
    private_key, public_pem = crypto.new_user_keypair()
    salt, nonce, ciphertext = crypto.lock_private_key(private_key, password, _user_aad(user))
    UserKeys.objects.create(user=user, public_pem=public_pem, private_salt=salt,
                            private_nonce=nonce, private_ciphertext=ciphertext)
    return private_key


def unlock(user, password):
    """Return the user's private key (creating keys for accounts that have none yet)."""
    keys = UserKeys.objects.filter(user=user).first()
    if keys is None:
        return create_keys(user, password)
    return crypto.unlock_private_key(password, bytes(keys.private_salt), bytes(keys.private_nonce),
                                     bytes(keys.private_ciphertext), _user_aad(user))


def public_key_of(user):
    return crypto.load_public_key(user.keys.public_pem)


# ---------- session: private key split between DB session and browser cookie ----------

def start_session(request, response, private_key):
    cookie_key, nonce, ciphertext = crypto.seal_for_session(private_key, _session_aad(request.user))
    request.session["pk_nonce"] = base64.b64encode(nonce).decode()
    request.session["pk_ct"] = base64.b64encode(ciphertext).decode()
    response.set_cookie(COOKIE, base64.urlsafe_b64encode(cookie_key).decode(),
                        max_age=settings.SESSION_COOKIE_AGE, secure=True, httponly=True, samesite="Strict")


def session_private_key(request):
    """The logged-in user's private key, or None if either half is missing."""
    try:
        cookie_key = base64.urlsafe_b64decode(request.COOKIES[COOKIE])
        nonce = base64.b64decode(request.session["pk_nonce"])
        ciphertext = base64.b64decode(request.session["pk_ct"])
        return crypto.open_from_session(cookie_key, nonce, ciphertext, _session_aad(request.user))
    except Exception:
        return None


# ---------- audit log ----------

def audit(user, action, private_key=None, file=None, detail="", username=None):
    """Append one signed, hash-chained entry. The IMMEDIATE transaction (see settings)
    stops two requests from chaining onto the same previous entry.
    user may be None (e.g. a failed login); such entries are chained but unsigned."""
    with transaction.atomic():
        last = AuditEntry.objects.order_by("-id").first()
        entry = AuditEntry(
            timestamp=timezone.now(), user=user, username=username or user.username, action=action,
            file_id=str(file.id) if file else "", file_name=file.name if file else "",
            file_sha256=file.sha256 if file else "", detail=detail[:255],
            prev_hash=last.entry_hash if last else GENESIS,
        )
        entry.entry_hash = crypto.sha256_hex(entry.canonical())
        if private_key is not None:
            entry.signature = crypto.sign(private_key, entry.entry_hash.encode())
            entry.signer_public_pem = user.keys.public_pem
        entry.save()
        return entry


def _registered_pem(entry):
    # Verify against the key on the user's account, not just the key copied into the entry,
    # so someone editing the database can't swap in their own key and re-sign.
    keys = UserKeys.objects.filter(user_id=entry.user_id).first()
    return keys.public_pem if keys else entry.signer_public_pem


def verify_chain():
    """Re-check every entry. Returns (chain_ok, first_broken_id, {entry_id: status})."""
    status, prev, first_broken = {}, GENESIS, None
    for e in AuditEntry.objects.order_by("id"):
        recomputed = crypto.sha256_hex(e.canonical())
        if e.prev_hash != prev or recomputed != e.entry_hash:
            status[e.id] = "broken"
            first_broken = first_broken or e.id
        elif e.signature is None:
            status[e.id] = "unsigned"
        elif crypto.verify(crypto.load_public_key(_registered_pem(e)), bytes(e.signature), e.entry_hash.encode()):
            status[e.id] = "ok"
        else:
            status[e.id] = "bad-signature"
            first_broken = first_broken or e.id
        prev = e.entry_hash
    return first_broken is None, first_broken, status
