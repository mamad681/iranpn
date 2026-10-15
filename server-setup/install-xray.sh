#!/usr/bin/env bash
# Run as root on a fresh Ubuntu 22.04/24.04 VPS.
# Usage: bash install-xray.sh DOMAIN PANEL_URL SYNC_KEY
#   DOMAIN     domain whose A record already points to this server
#   PANEL_URL  your Railway URL, e.g. https://xxx.up.railway.app
#   SYNC_KEY   same value as the SYNC_KEY variable in Railway
set -euo pipefail
DOMAIN="${1:?DOMAIN missing}"; PANEL_URL="${2:?PANEL_URL missing}"; SYNC_KEY="${3:?SYNC_KEY missing}"
PANEL_URL="${PANEL_URL%/}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx certbot curl jq unzip
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<'EOF'
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "services": ["StatsService"]},
  "stats": {},
  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}},
  "inbounds": [
    {"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
    {"tag": "vless-ws", "listen": "127.0.0.1", "port": 10001, "protocol": "vless",
     "settings": {"clients": [], "decryption": "none"},
     "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}},
    {"tag": "vless-grpc", "listen": "127.0.0.1", "port": 10002, "protocol": "vless",
     "settings": {"clients": [], "decryption": "none"},
     "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "grpc"}}}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]}
}
EOF

# TLS certificate
systemctl stop nginx || true
certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email

rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/vpn.conf <<'EOF'
server {
  listen 80;
  server_name DOMAIN_PLACEHOLDER;
  return 301 https://$host$request_uri;
}
server {
  listen 443 ssl http2;
  server_name DOMAIN_PLACEHOLDER;
  ssl_certificate     /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
  location /ws {
    proxy_pass http://127.0.0.1:10001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
  }
  location /grpc {
    grpc_pass grpc://127.0.0.1:10002;
    grpc_read_timeout 1h;
    grpc_send_timeout 1h;
    client_max_body_size 0;
  }
  location / { root /var/www/html; index index.html; }
}
EOF
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/conf.d/vpn.conf
nginx -t
systemctl enable --now nginx
systemctl restart nginx
(command -v ufw >/dev/null && ufw allow 80,443/tcp) || true

# sync agent
install -m 755 "$(dirname "$0")/sync.sh" /usr/local/bin/vpn-sync
cat > /etc/vpn-sync.env <<EOF
PANEL_URL=$PANEL_URL
SYNC_KEY=$SYNC_KEY
EOF
chmod 600 /etc/vpn-sync.env
cat > /etc/systemd/system/vpn-sync.service <<'EOF'
[Unit]
Description=Sync VPN users with panel
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-sync
EOF
cat > /etc/systemd/system/vpn-sync.timer <<'EOF'
[Unit]
Description=Run vpn-sync every minute
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now xray
systemctl enable --now vpn-sync.timer
/usr/local/bin/vpn-sync || true
echo
echo "Done. In the panel add a server: address=$DOMAIN, SNI=$DOMAIN, config 1 = ws 443 /ws, config 2 = grpc 443 grpc"
