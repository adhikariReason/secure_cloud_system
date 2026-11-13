# Self-test for every project requirement. From ~/secure_cloud_system run:
#   docker compose exec -T web python manage.py shell < scripts/check.py
# Creates throwaway users chk_a / chk_b / chk_c and deletes them (and their files) at the end.
import re
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile as U
from django.test import Client
from files.models import AuditEntry, FileShare, StoredFile, UserKeys

H = dict(secure=True, HTTP_HOST="localhost")
PW = "Chk-Pass-2026!"
results = []
def r(name, ok): results.append(ok); print(("PASS " if ok else "FAIL ") + name)

def cleanup():
    for f in StoredFile.objects.filter(owner__username__startswith="chk_"):
        f.path().unlink(missing_ok=True)
    User.objects.filter(username__in=["chk_a", "chk_b", "chk_c"]).delete()

def account(name):
    c = Client()
    c.post("/register/", {"username": name, "password1": PW, "password2": PW}, **H)
    c.post("/login/", {"username": name, "password": PW}, **H)
    return c

cleanup()
a, b, c = account("chk_a"), account("chk_b"), account("chk_c")
r("B7  register + login", a.get("/", **H).status_code == 200 and b.get("/", **H).status_code == 200)
k = UserKeys.objects.get(user__username="chk_a")
r("C13 private key stored only encrypted", b"PRIVATE KEY" not in bytes(k.private_ciphertext) and "PUBLIC KEY" in k.public_pem)

data = b"TOP SECRET plaintext " * 2000
a.post("/upload/", {"file": U("t.txt", data)}, **H)
f = StoredFile.objects.get(owner__username="chk_a")
ct = f.path().read_bytes()
r("B8  upload", f.size == len(data))
r("C11 encrypted at rest", b"TOP SECRET" not in ct)
r("C14 nonce 12B, wrapped key + signature stored", len(bytes(f.nonce)) == 12 and len(bytes(f.wrapped_key)) == 256 and len(bytes(f.signature)) == 256)
r("B9  list own files only", b"t.txt" in a.get("/", **H).content and b"t.txt" not in b.get("/", **H).content)
dl = lambda cl: cl.get(f"/files/{f.id}/download/", **H)
r("C12 owner download = original", b"".join(dl(a).streaming_content) == data)
r("D   cross-user download 404", dl(b).status_code == 404)
r("D   cross-user delete 404", b.post(f"/files/{f.id}/delete/", **H).status_code == 404)
r("D   anonymous -> login", Client().get(f"/files/{f.id}/download/", **H).status_code == 302)
a.post("/upload/", {"file": U("x.exe", b"x")}, **H)
r("D   bad file type rejected", not StoredFile.objects.filter(name="x.exe").exists())

a.post(f"/files/{f.id}/share/", {"username": "chk_b"}, **H)
r("Share: recipient gets original", b"".join(dl(b).streaming_content) == data)
r("Share: third user still 404", dl(c).status_code == 404)
r("Share: recipient can't delete", b.post(f"/files/{f.id}/delete/", **H).status_code == 404)

bad = bytearray(ct); bad[5] ^= 0xFF; f.path().write_bytes(bad)
r("C15 tampered ciphertext rejected (400)", dl(a).status_code == 400)
f.path().write_bytes(ct)
r("Audit: chain intact", b"Log intact" in a.get("/audit/", **H).content)
e = AuditEntry.objects.filter(username="chk_a", action="upload").first()
e.username = "mallory"; e.save()
r("Audit: edited entry detected", b"Log has been altered" in a.get("/audit/", **H).content)
e.username = "chk_a"; e.save()

a.post(f"/files/{f.id}/delete/", **H)
r("B10 delete removes row + file", not f.path().exists() and not StoredFile.objects.filter(id=f.id).exists())
a.post("/logout/", **H)
r("B7  logout", a.get("/", **H).status_code == 302)

cleanup()
print(f"\n{sum(results)}/{len(results)} passed")
