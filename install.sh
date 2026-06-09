#!/usr/bin/env bash
#
# shorebridge installer.
#
# One-line install (Debian / Raspberry Pi OS, run as root):
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/bretterer/shorebridge/main/install.sh)"
#
# Re-running is safe: it updates the program and (with --reconfigure) the settings.
#
set -euo pipefail

RAW_BASE="${SB_RAW_BASE:-https://raw.githubusercontent.com/bretterer/shorebridge/main}"
PREFIX=/opt/shorebridge
ETC=/etc/shorebridge
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /tmp)"

c()  { printf "\033[1;36m%s\033[0m\n" "$*"; }
ok() { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
warn(){ printf "  \033[1;33m!\033[0m %s\n" "$*"; }
die(){ printf "\033[1;31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }
ask(){ # ask <prompt> <default> <varname> [secret]  (reads from the terminal even under curl|bash)
  local p="$1" d="$2" __v="$3" secret="${4:-}" envname="SB_$3" ans
  if [ -n "${!envname:-}" ]; then printf -v "$__v" '%s' "${!envname}"; return; fi  # non-interactive override: SB_<VAR>
  if [ "$secret" = "secret" ]; then
    read -rs -p "$p: " ans </dev/tty || ans=""; echo   # hidden input, no echo
  else
    read -r -p "$p [${d}]: " ans </dev/tty || ans=""
  fi
  printf -v "$__v" '%s' "${ans:-$d}"
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."
c "shorebridge installer"
echo

# ---- prerequisites ----
c "Checking prerequisites"
. /etc/os-release 2>/dev/null || true
command -v apt-get >/dev/null 2>&1 || warn "non-Debian system; install python3 + openssl yourself if missing"
need=""
command -v python3 >/dev/null 2>&1 || need="$need python3"
command -v openssl >/dev/null 2>&1 || need="$need openssl"
command -v curl    >/dev/null 2>&1 || need="$need curl"
if [ -n "$need" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq $need >/dev/null
    ok "installed:$need"
  else
    die "missing:$need"
  fi
fi
ok "python3 $(python3 -c 'import platform;print(platform.python_version())'), openssl present"

# ---- detect 3CX SBC (optional coexistence) ----
if systemctl is-active --quiet 3cxsbc 2>/dev/null || [ -x /usr/sbin/3cxsbc ] || dpkg -s 3cxsbc >/dev/null 2>&1; then
  ok "3CX SBC detected on this host"
else
  warn "No 3CX SBC found on this host."
  ask "  Install the 3CX SBC now? (y/N)" "N" INSTALL_SBC
  if [[ "${INSTALL_SBC,,}" == y* ]]; then
    c "Running 3CX SBC installer"
    bash -c "$(wget -qO- http://downloads-global.3cx.com/downloads/sbc/3cxsbc.zip)" || warn "3CX SBC installer returned non-zero; continuing"
  fi
fi

# ---- gather settings (or keep an existing config) ----
echo; c "Configuration"
if [ -f "$ETC/config.ini" ] && [ -z "${SB_RECONFIGURE:-}" ]; then
  KEEP_CONFIG=1
  BIND_IP="$(grep -E '^\s*bind_ip' "$ETC/config.ini" | head -1 | sed 's/.*=\s*//' | tr -d '[:space:]')"
  [ -n "$BIND_IP" ] || BIND_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ok "keeping existing $ETC/config.ini (set SB_RECONFIGURE=1 to re-prompt)"
else
  KEEP_CONFIG=0
  DEF_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
  [ -n "$DEF_IP" ] || DEF_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ask "Bridge LAN IP (phones point here)" "${DEF_IP:-auto}" BIND_IP
  ask "PBX / 3CX SBC IP (same box as SBC? use this host's LAN IP)" "$BIND_IP" SBC_IP
  ask "PBX SIP port"                      "5060"             SBC_PORT
  ask "Registrar domain (3CX: NNN.3cx.cloud; FreePBX: PBX IP)" "$SBC_IP" DOMAIN
  ask "Phone timezone"                    "Eastern Standard Time" TZ
  # Per-phone extension/auth/password are assigned later in the web UI, not here.
fi

# ---- lay out files ----
echo; c "Installing to $PREFIX"
mkdir -p "$PREFIX/tls" "$PREFIX/www/keystore/certs" "$PREFIX/www/fileserver/phoneconfig" "$ETC"

# program (prefer local copy when run from a clone, else download)
if [ -f "$SCRIPT_DIR/shorebridge.py" ]; then
  install -m 0755 "$SCRIPT_DIR/shorebridge.py" "$PREFIX/shorebridge.py"
  install -m 0644 "$SCRIPT_DIR/connectors.py" "$PREFIX/connectors.py"
else
  curl -fsSL "$RAW_BASE/shorebridge.py" -o "$PREFIX/shorebridge.py"; chmod 0755 "$PREFIX/shorebridge.py"
  curl -fsSL "$RAW_BASE/connectors.py"  -o "$PREFIX/connectors.py"
fi
mkdir -p "$PREFIX/connectors.d"   # drop third-party connector .py files here
ok "shorebridge.py + connectors"

# control CLI -> /usr/local/bin/shorebridge
if [ -f "$SCRIPT_DIR/bin/shorebridge" ]; then
  install -m 0755 "$SCRIPT_DIR/bin/shorebridge" /usr/local/bin/shorebridge
else
  curl -fsSL "$RAW_BASE/bin/shorebridge" -o /usr/local/bin/shorebridge; chmod 0755 /usr/local/bin/shorebridge
fi
ok "shorebridge CLI (try: shorebridge update)"

# ---- certificates: our own CA + a switch cert the phone will trust ----
c "Generating certificates (CA injection trust anchor)"
TLS="$PREFIX/tls"
if [ ! -f "$TLS/hq_ca.crt" ]; then
  openssl genrsa -out "$TLS/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -nodes -key "$TLS/ca.key" -sha256 -days 3650 \
    -subj "/CN=ShoreTel HQ CA/O=ShoreTel" -out "$TLS/hq_ca.crt" 2>/dev/null
  ok "created CA"
else
  ok "reusing existing CA"
fi
openssl genrsa -out "$TLS/switch.key" 2048 2>/dev/null
openssl req -new -key "$TLS/switch.key" -subj "/CN=$BIND_IP/O=ShoreTel" -out "$TLS/switch.csr" 2>/dev/null
printf "subjectAltName=IP:%s,DNS:%s\nextendedKeyUsage=serverAuth\n" "$BIND_IP" "$BIND_IP" > "$TLS/san.cnf"
openssl x509 -req -in "$TLS/switch.csr" -CA "$TLS/hq_ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
  -days 3650 -sha256 -extfile "$TLS/san.cnf" -out "$TLS/switch.crt" 2>/dev/null
cat "$TLS/switch.crt" "$TLS/hq_ca.crt" > "$TLS/switch_fullchain.crt"
cp "$TLS/hq_ca.crt" "$PREFIX/www/keystore/certs/hq_ca.crt"     # served to the phone over HTTP
chmod 600 "$TLS/"*.key
ok "switch cert for $BIND_IP (signed by our CA)"

# ---- config ----
if [ "$KEEP_CONFIG" = 1 ]; then
  ok "config preserved (no changes)"
else
  cat > "$ETC/config.ini" <<EOF
[bridge]
bind_ip = $BIND_IP
data_dir = $PREFIX
debug = false
ui_port = 8910

[pbx]
sbc_ip   = $SBC_IP
sbc_port = $SBC_PORT
domain   = $DOMAIN

[phone]
timezone = $TZ

[connector]
type = manual
EOF
  chmod 600 "$ETC/config.ini"
  ok "wrote $ETC/config.ini"
fi

# ---- port conflict check ----
for p in 80 5061 5448 5062; do
  if ss -ltnup 2>/dev/null | grep -q ":$p "; then warn "port $p is already in use (may conflict)"; fi
done

# ---- systemd ----
c "Installing systemd service"
if [ -f "$SCRIPT_DIR/systemd/shorebridge.service" ]; then
  install -m 0644 "$SCRIPT_DIR/systemd/shorebridge.service" /etc/systemd/system/shorebridge.service
else
  curl -fsSL "$RAW_BASE/systemd/shorebridge.service" -o /etc/systemd/system/shorebridge.service
fi
systemctl daemon-reload
systemctl enable shorebridge >/dev/null 2>&1
systemctl restart shorebridge
sleep 2
if systemctl is-active --quiet shorebridge; then ok "shorebridge service running"; else warn "service not active; check: journalctl -u shorebridge -e"; fi

echo
c "Done."
cat <<EOF

  Point each ShoreTel/Mitel IP480 at this bridge:
    1. Factory reset:  Mute + 25327#
    2. As it reboots, press any key when prompted to enter setup
       (or from idle:  Mute + 73887#, admin password 1234)
    3. Set Config Server to:  $BIND_IP
    4. Reboot / save:  Mute + 73738#

  Now add your phones (by MAC, with their PBX extension + auth) in the web UI:

    http://$BIND_IP:8910

  Point a phone's Config Server at $BIND_IP; it will appear there under
  "New phones seen" for one-click assignment.

  Manage it:
    shorebridge update     update to the latest version + restart
    shorebridge logs       follow the log
    shorebridge config     edit settings
    shorebridge ui         print the admin UI url

  Config:  $ETC/config.ini      Phones:  $ETC/phones.json (or the web UI)
EOF
