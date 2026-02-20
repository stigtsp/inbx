#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_DIR="/opt/inbx"
SYSTEMD_DIR="/etc/systemd/system"
ENV_FILE="/etc/default/inbx"
SERVICE_UNIT="inbx.service"
NGINX_AVAILABLE="/etc/nginx/sites-available/inbx.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/inbx.conf"
SOCKET_PATH="/run/inbx/inbx.sock"
SERVER_NAME="${INBX_SERVER_NAME:-_}"

for f in inbx.pl inbx.service inbx.env.example; do
  if [[ ! -f "$REPO_DIR/$f" ]]; then
    echo "Missing required file: $REPO_DIR/$f" >&2
    exit 1
  fi
done

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found" >&2
  exit 1
fi

PACKAGES=(nginx libmojolicious-perl libcrypt-pbkdf2-perl curl)
MISSING=()
for pkg in "${PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    MISSING+=("$pkg")
  fi
done

if [[ "${#MISSING[@]}" -gt 0 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y "${MISSING[@]}"
fi

if ! command -v nginx >/dev/null 2>&1; then
  echo "nginx not found after package install" >&2
  exit 1
fi

install -d -m 0755 "$APP_DIR"
install -m 0755 "$REPO_DIR/inbx.pl" "$APP_DIR/inbx.pl"

install -m 0644 "$REPO_DIR/inbx.service" "$SYSTEMD_DIR/$SERVICE_UNIT"

if [[ -f "$ENV_FILE" ]]; then
  echo "Keeping existing $ENV_FILE"
else
  install -D -m 0640 "$REPO_DIR/inbx.env.example" "$ENV_FILE"
  echo "Installed new $ENV_FILE"
fi

if grep -Eq '^[[:space:]]*MOJO_LISTEN=' "$ENV_FILE"; then
  sed -i -E 's|^[[:space:]]*MOJO_LISTEN=.*$|MOJO_LISTEN=http+unix://%2Frun%2Finbx%2Finbx.sock|' "$ENV_FILE"
  echo "Updated MOJO_LISTEN in $ENV_FILE for unix socket mode"
else
  printf '\nMOJO_LISTEN=http+unix://%%2Frun%%2Finbx%%2Finbx.sock\n' >> "$ENV_FILE"
  echo "Added MOJO_LISTEN to $ENV_FILE for unix socket mode"
fi

install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
cat > "$NGINX_AVAILABLE" <<NGINX
server {
    listen 80;
    server_name ${SERVER_NAME};

    client_max_body_size 1m;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_pass http://unix:${SOCKET_PATH}:;
    }
}
NGINX

ln -sfn "$NGINX_AVAILABLE" "$NGINX_ENABLED"

systemctl daemon-reload

# Disable and remove old socket-activation unit if present.
systemctl disable --now inbx.socket >/dev/null 2>&1 || true
rm -f "$SYSTEMD_DIR/inbx.socket"
systemctl daemon-reload

systemctl enable "$SERVICE_UNIT"
systemctl restart "$SERVICE_UNIT"

nginx -t
systemctl reload nginx

if command -v curl >/dev/null 2>&1; then
  curl --silent --show-error --fail --unix-socket "$SOCKET_PATH" http://localhost/inbx >/dev/null
  echo "Health check passed via $SOCKET_PATH"
else
  echo "curl not found; skipping health check"
fi

echo "Deploy complete."
echo "Service unit: systemctl status $SERVICE_UNIT"
