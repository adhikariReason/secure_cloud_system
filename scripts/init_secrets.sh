#!/usr/bin/env bash
# One-time setup: Django secret (outside the project) + TLS certificate for nginx.
# There is no file-encryption master key: each user's RSA key pair protects their files.
set -euo pipefail
cd "$(dirname "$0")/.."
SECRETS="$HOME/securecloud-secrets"
VM_IP=$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')

mkdir -p "$SECRETS" && chmod 700 "$SECRETS"
[ -f "$SECRETS/django_secret_key" ] || openssl rand -base64 48 > "$SECRETS/django_secret_key"
chmod 600 "$SECRETS"/*

mkdir -p nginx/certs
[ -f nginx/certs/server.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt -subj "/CN=securecloud" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${VM_IP}" 2>/dev/null
echo "secret in $SECRETS, cert for localhost + ${VM_IP}"
