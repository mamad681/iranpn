#!/usr/bin/env bash
# Pulls active users from the panel, writes them to Xray (and L2TP if installed),
# and reports traffic usage back to the panel. Runs every minute via systemd timer.
set -uo pipefail
source /etc/vpn-sync.env
CFG=/usr/local/etc/xray/config.json
STATE=/var/lib/vpn-sync; mkdir -p "$STATE"
H=(-H "x-sync-key: $SYNC_KEY")

users=$(curl -fsS -m 20 "${H[@]}" "$PANEL_URL/api/sync/users") || { echo "panel unreachable"; exit 0; }
echo "$users" | jq -e '.users' >/dev/null 2>&1 || { echo "bad response from panel"; exit 0; }

# Keep the L2TP/IPsec pre-shared key aligned with the panel's admin setting.
if command -v ipsec >/dev/null 2>&1; then
  cfg=$(curl -fsS -m 20 "${H[@]}" "$PANEL_URL/api/sync/config" 2>/dev/null || true)
  psk=$(echo "$cfg" | jq -r '.l2tpPsk // empty' 2>/dev/null || true)
  if [ -n "$psk" ] && ! grep -Fq "\"$psk\"" /etc/ipsec.secrets 2>/dev/null; then
    printf '%%any %%any : PSK "%s"\\n' "$psk" > /etc/ipsec.secrets.new
    chmod 600 /etc/ipsec.secrets.new
    mv /etc/ipsec.secrets.new /etc/ipsec.secrets
    systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || true
  fi
fi

# 1) report usage first (counters reset on xray restart)
raw=$(xray api statsquery -s 127.0.0.1:10085 -reset 2>/dev/null || echo '{}')
new=$(echo "$raw" | jq -c '[.stat[]? | select(.name|startswith("user>>>")) | {id:(.name|split(">>>")[1]), bytes:(.value|tonumber)}] | group_by(.id) | map({id:.[0].id, bytes:(map(.bytes)|add)})' 2>/dev/null || echo '[]')
old=$(cat "$STATE/pending.json" 2>/dev/null || echo '[]')
items=$(jq -cs 'add | group_by(.id) | map({id:.[0].id, bytes:(map(.bytes)|add)})' <(echo "$old") <(echo "$new") 2>/dev/null || echo '[]')
if [ "$items" != "[]" ]; then
  if curl -fsS -m 20 "${H[@]}" -H 'Content-Type: application/json' -d "{\"items\":$items}" "$PANEL_URL/api/sync/usage" >/dev/null; then
    rm -f "$STATE/pending.json"
  else
    echo "$items" > "$STATE/pending.json"
  fi
fi

# 2) Xray clients
clients=$(echo "$users" | jq -c '[.users[] | {id:.uuid, email:.id, level:0}]')
cur=$(jq -c '.inbounds[] | select(.tag=="vless-ws") | .settings.clients' "$CFG")
if [ "$clients" != "$cur" ]; then
  tmp=$(mktemp)
  jq --argjson c "$clients" '(.inbounds[] | select(.tag=="vless-ws" or .tag=="vless-grpc") | .settings.clients) = $c' "$CFG" > "$tmp" \
    && install -m 644 "$tmp" "$CFG" && systemctl restart xray
  rm -f "$tmp"
fi

# 3) L2TP users (only if xl2tpd is installed)
if command -v xl2tpd >/dev/null 2>&1 && [ -f /etc/ppp/chap-secrets ]; then
  { echo "# managed by vpn-sync"; echo "$users" | jq -r '.users[] | "\"\(.id)\" * \"\(.pw)\" *"'; } > /etc/ppp/chap-secrets.new \
    && chmod 600 /etc/ppp/chap-secrets.new && mv /etc/ppp/chap-secrets.new /etc/ppp/chap-secrets
fi
