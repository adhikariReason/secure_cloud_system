# Secure Cloud System

Browser --HTTPS--> **mynginx** (TLS termination, HTTP->HTTPS redirect) --> **django-web** (Gunicorn + Django)
--> SQLite (volume `db_data`) + encrypted files (volume `private_storage`).

## Run (Ubuntu VM with Docker + Compose v2)
```bash
./scripts/init_secrets.sh      # Django secret in ~/securecloud-secrets, TLS cert in nginx/certs
docker compose up -d --build
docker compose exec -T web python manage.py shell < scripts/check.py   # self-test, prints PASS/FAIL
```
Open https://localhost (or https://<VM-IP>), register, sign in, upload.

## Security design
| Layer | Mechanism |
|---|---|
| Transport | TLS 1.2/1.3 at nginx; HTTP redirected to HTTPS; only ports 80/443 published |
| Accounts | Django auth (salted PBKDF2 password hashes), CSRF tokens, Secure/HttpOnly cookies |
| User keys | RSA-2048 key pair per user, made at registration. Private key encrypted with AES-256-GCM under a key derived from the password (scrypt). The server never stores it unlocked. |
| File encryption | Fresh random AES-256 key + 96-bit nonce per file (AES-GCM, file ID as AAD). The file key is wrapped with the owner's public key (RSA-OAEP). One key per file, so a nonce never repeats under a key. |
| Session | At sign-in the private key is unlocked and re-encrypted with a random key held only in an HttpOnly cookie; the server session stores the ciphertext. Neither half alone recovers the key. |
| Integrity + origin | Owner signs `file id + name + size + SHA-256` with RSA-PSS. Each download: unwrap key, decrypt (GCM tag), recompute SHA-256, verify signature. Any failure = 400, download rejected, logged. |
| Access control | Download: owner or explicit share recipient; everyone else 404. Delete/share/unshare: owner only. |
| Sharing | Owner unwraps the file key and wraps a copy with the recipient's public key. |
| Audit log | Every register/login/upload/download/share/unshare/delete/integrity failure is a row with the previous row's hash and the acting user's RSA-PSS signature. Editing or removing a row breaks the chain. |
| Limits | Extension allow-list, 1 GB max (nginx + Django), encrypted blobs named by UUID outside any served path |

**Stored on disk:** public keys, password-encrypted private keys, wrapped file keys, nonces, hashes, signatures, ciphertext. **Never stored:** passwords, unlocked private keys, unwrapped file keys.

## Contents
| Path | What |
|---|---|
| `docker-compose.yml` | 2 services; only nginx publishes ports |
| `nginx/default.conf` | HTTPS, redirect, reverse proxy to `web:8000`, 1 GB body limit |
| `app/Dockerfile`, `app/requirements.txt` | Django + Gunicorn image (`cryptography` pinned to 43.0.3: newer wheels crash on the UTM VM's CPU) |
| `app/files/crypto.py` | All cryptographic primitives |
| `app/files/keys.py` | Key management, session key split, audit log + chain verification |
| `app/files/models.py` | `UserKeys`, `StoredFile`, `FileShare`, `AuditEntry` |
| `app/files/views.py` | Accounts, upload, list, download, verify, share, delete, audit |
| `app/files/templates/` | UI |
| `scripts/init_secrets.sh` | Generates the Django secret + TLS certificate (not included in the ZIP) |
| `scripts/check.py` | Automated test of every requirement |

## Limitations
Whole file encrypted in memory (1 GB needs ~2 GB RAM); forgotten password = unrecoverable files (by design);
the server could sign on a user's behalf while they're signed in (full non-repudiation needs client-side signing);
self-signed certificate; SQLite; extension-based type check.
