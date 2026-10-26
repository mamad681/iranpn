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
apt-get install -y nginx certbot curl jq unzip strongswan xl2tpd ppp iptables-persistent
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

# L2TP/IPsec setup (UDP 500/4500 for IPsec, UDP 1701 for L2TP).
# Fetch the same pre-shared key configured in the panel; never use a fixed public key.
L2TP_PSK="$(curl -fsS -m 20 -H "x-sync-key: $SYNC_KEY" "$PANEL_URL/api/sync/config" | jq -r '.l2tpPsk // empty')"
if [[ -z "$L2TP_PSK" || "$L2TP_PSK" == "null" ]]; then
  echo "Could not read L2TP PSK from panel. Check PANEL_URL and SYNC_KEY." >&2
  exit 1
fi
cat > /etc/ipsec.conf <<'EOF'
config setup
    uniqueids=no

conn L2TP-PSK-NAT
    keyexchange=ikev1
    authby=secret
    type=transport
    keyingtries=%forever
    rekey=no
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    dpddelay=30s
    dpdtimeout=120s
    dpdaction=clear
    auto=add
EOF
printf '%%any %%any : PSK "%s"\\n' "$L2TP_PSK" > /etc/ipsec.secrets
chmod 600 /etc/ipsec.secrets

mkdir -p /etc/ppp
cat > /etc/xl2tpd/xl2tpd.conf <<'EOF'
[global]
port = 1701
access control = no

[lns default]
ip range = 10.20.30.10-10.20.30.250
local ip = 10.20.30.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
cat > /etc/ppp/options.xl2tpd <<'EOF'
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
name l2tpd
auth
mtu 1410
mru 1410
proxyarp
connect-delay 5000
lcp-echo-interval 30
lcp-echo-failure 4
ms-dns 1.1.1.1
ms-dns 8.8.8.8
EOF
touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets
# Enable IPv4 forwarding and NAT for VPN clients.
cat > /etc/sysctl.d/99-vpn-forwarding.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
EOF
sysctl --system >/dev/null
WAN_IF="$(ip -o -4 route show to default | awk '{print $5; exit}')"
if [[ -n "$WAN_IF" ]]; then
  iptables -C FORWARD -s 10.20.30.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.20.30.0/24 -j ACCEPT
  iptables -C FORWARD -d 10.20.30.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.20.30.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -t nat -C POSTROUTING -s 10.20.30.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.20.30.0/24 -o "$WAN_IF" -j MASQUERADE
  netfilter-persistent save >/dev/null 2>&1 || true
fi

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
(command -v ufw >/dev/null && ufw allow 80,443/tcp && ufw allow 500/udp && ufw allow 4500/udp && ufw allow 1701/udp) || true

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
systemctl enable --now strongswan-starter || systemctl enable --now strongswan || true
systemctl enable --now xl2tpd
systemctl enable --now vpn-sync.timer
/usr/local/bin/vpn-sync || true
echo
echo "L2TP/IPsec is configured. Ensure UDP 500, 4500 and 1701 are allowed by your cloud firewall/security group."
echo "Done. In the panel add a server: address=$DOMAIN, SNI=$DOMAIN, config 1 = ws 443 /ws, config 2 = grpc 443 grpc"
