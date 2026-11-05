# Secure Cloud System (barebones)

Browser --HTTPS--> **mynginx** (TLS, HTTP->HTTPS redirect) --> **django-web** (Gunicorn + Django)
-> SQLite (volume `db_data`) + AES-256-GCM encrypted files (volume `private_storage`).

## Run (Ubuntu VM with Docker + Compose v2)
```bash
./scripts/init_secrets.sh      # master key + Django secret in ~/securecloud-secrets, TLS cert in nginx/certs
docker compose up -d --build
```
Open https://localhost (or https://<VM-IP>), accept the self-signed cert, register, upload.

## Contents
| Path | What |
|---|---|
| `docker-compose.yml` | 2 services; only nginx publishes ports 80/443; key mounted as a Docker secret |
| `nginx/default.conf` | HTTP->HTTPS redirect, TLS, reverse proxy to `web:8000`, 1 GB body limit |
| `app/Dockerfile`, `app/requirements.txt` | Django + Gunicorn image |
| `app/securecloud/` | Django settings / URLs |
| `app/files/crypto.py` | AES-256-GCM encrypt/decrypt (random 12-byte nonce per file, file ID as AAD) |
| `app/files/models.py` | `StoredFile`: owner, name, size, nonce |
| `app/files/views.py` | register, upload, list, download, delete (owner-only, tamper -> 400) |
| `app/files/templates/` | HTML pages |
| `scripts/init_secrets.sh` | generates secrets + cert (not included in the ZIP) |

## Security notes
- Master key lives in `~/securecloud-secrets/master_key` on the VM, outside this folder; mounted read-only at `/run/secrets/master_key` in `django-web` only.
- Encrypted files are named by random UUID and stored in a volume nginx cannot read.
- Other users' file IDs return 404; modified ciphertext fails the GCM tag check and the download is rejected.
