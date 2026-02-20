# inbx

Small Mojolicious inbox service.

## What it does

- `POST /inbx` stores the raw request body as a text entry.
- Each entry gets a companion metadata file `<entry>.txt.meta.json`.
- `GET /inbx/view` shows entries (newest first) in plain text.
- Viewer uses HTTP Basic Auth (`INBX_USER` / `INBX_PASS`).
- If `INBX_PASS` is unset, a random viewer password is generated on first start.
- Post token is required when set (`X-Inbx-Token` header).
- Post token is auto-generated on first start and shown in `/inbx/view`.
- Token can be rotated or unset from `/inbx/view`.
- Keeps only newest `INBX_MAX_ENTRIES` (default 100).
- Max request size is 1 MiB.

Metadata JSON fields:

- `ip`
- `timestamp_utc`
- `sha256`
- `headers` (all request headers)

## Debian 13 packages

```bash
sudo apt update
sudo apt install -y libmojolicious-perl libcrypt-pbkdf2-perl nginx
```

## Install files

```bash
sudo mkdir -p /opt/inbx
sudo cp inbx.pl /opt/inbx/inbx.pl
sudo chmod 0755 /opt/inbx/inbx.pl

sudo cp inbx.env.example /etc/default/inbx
sudoedit /etc/default/inbx

sudo cp inbx.socket /etc/systemd/system/inbx.socket
sudo cp inbx.service /etc/systemd/system/inbx.service
sudo systemctl daemon-reload
sudo systemctl enable --now inbx.socket
```

Or run the deploy script (safe to rerun for redeploys):

```bash
sudo ./scripts/deploy.sh
```

## systemd notes

- Uses `DynamicUser=yes`.
- Uses systemd socket activation (`inbx.socket` + `inbx.service`).
- Listens on UNIX socket `/run/inbx.sock` (no TCP listener).
- Socket permissions are set for NGINX via `SocketGroup=www-data` and `SocketMode=0660`.
- Uses `StateDirectory=inbx`.
- Unit sets `INBX_STORAGE_PATH=%S/inbx` automatically.
- Includes sandboxing/hardening options.
- If `INBX_PASS` is unset, find generated viewer password with:

```bash
sudo journalctl -u inbx.service -b --no-pager | grep 'Generated viewer password'
```

If hardening blocks something, override with:

```bash
sudo systemctl edit inbx.service
sudo systemctl daemon-reload
sudo systemctl restart inbx.service
```

## nginx reverse proxy

```nginx
server {
    listen 80;
    server_name _;

    client_max_body_size 1m;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_pass http://unix:/run/inbx.sock:;
    }
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Usage

1. Open `/inbx/view` in a browser and log in.
2. Copy the shown curl command (it includes current token if set).

Manual example with token:

```bash
curl -sS -X POST \
  -H "X-Inbx-Token: <token>" \
  --data-binary @/tmp/some-info \
  http://localhost/inbx
```

Manual example with Basic Auth using token:

```bash
curl -sS -u "inbx:<token>" -X POST --data-binary @/tmp/some-info http://localhost/inbx
```

Manual example when token is unset:

```bash
curl -sS -X POST --data-binary @/tmp/some-info http://localhost/inbx
```

Pipe stdin (for example `dmesg`) to inbox:

```bash
dmesg | curl -sS -X POST -H "X-Inbx-Token: <token>" --data-binary @- http://localhost/inbx
```

Read entries:

```bash
curl -sS -u "$INBX_USER:$INBX_PASS" http://localhost/inbx/view
```
