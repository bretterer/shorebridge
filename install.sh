#!/usr/bin/env bash
#
# shorebridge installer.
#
# One-line install (Debian / Raspberry Pi OS, run as root):
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/tpglitch/shorebridge/main/install.sh)"
#
# Re-running is safe: it updates the program and (with SB_RECONFIGURE=1) the settings.
#
# The PBX side of shorebridge uses the pjsua2 Python module. pjsua2 is not on PyPI,
# so this installer creates a virtualenv at /opt/shorebridge/venv and compiles
# pjsua2 into it. The first install takes a while (a few minutes on a PC, 10 to 30
# minutes on a Raspberry Pi). Later runs skip the build when pjsua2 is already there.
#
set -euo pipefail

BRANCH="${SB_BRANCH:-main}"
RAW_BASE="${SB_RAW_BASE:-https://raw.githubusercontent.com/tpglitch/shorebridge/$BRANCH}"
PREFIX=/opt/shorebridge
ETC=/etc/shorebridge
VENV="$PREFIX/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /tmp)"

c()   { printf "\033[1;36m%s\033[0m\n" "$*"; }
ok()  { printf "  \033[1;32m+\033[0m %s\n" "$*"; }
warn(){ printf "  \033[1;33m!\033[0m %s\n" "$*"; }
die() { printf "\033[1;31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }
ask() { # ask <prompt> <default> <varname> [secret]  (reads from the terminal even under curl|bash)
  local p="$1" d="$2" __v="$3" secret="${4:-}" envname="SB_$3" ans
  if [ -n "${!envname:-}" ]; then printf -v "$__v" '%s' "${!envname}"; return; fi  # Non-interactive override: SB_<VAR>
  if [ "$secret" = "secret" ]; then
    read -rs -p "$p: " ans </dev/tty || ans=""; echo   # Hidden input, no echo
  else
    read -r -p "$p [${d}]: " ans </dev/tty || ans=""
  fi
  printf -v "$__v" '%s' "${ans:-$d}"
}

# Install a file from the local clone when there is one, otherwise download it.
# Usage: fetch <path in repo> <destination> <mode>
fetch() {
  local rel="$1" dest="$2" mode="$3"
  if [ -f "$SCRIPT_DIR/$rel" ]; then
    install -m "$mode" "$SCRIPT_DIR/$rel" "$dest"
  else
    curl -fsSL "$RAW_BASE/$rel" -o "$dest.tmp" || die "could not download $rel"
    install -m "$mode" "$dest.tmp" "$dest"; rm -f "$dest.tmp"
  fi
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."
c "shorebridge installer"
echo

# ---- Prerequisites ----
c "Checking prerequisites"
. /etc/os-release 2>/dev/null || true

# Everything needed to run shorebridge and to compile pjsua2.
APT_PKGS="python3 python3-venv python3-pip python3-dev build-essential swig git curl openssl \
libssl-dev libasound2-dev pkg-config iproute2 ca-certificates"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  missing=""
  for p in $APT_PKGS; do
    dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"
  done
  if [ -n "$missing" ]; then
    echo "  installing:$missing"
    apt-get update -qq
    # libasound2-dev is optional, so a failure there should not stop the install.
    apt-get install -y -qq $missing >/dev/null \
      || apt-get install -y -qq ${missing/libasound2-dev/} >/dev/null \
      || die "apt-get could not install:$missing"
    ok "installed packages"
  else
    ok "system packages present"
  fi
else
  warn "non-Debian system: install these yourself: python3 (with venv, pip, headers), a C/C++ toolchain, make, swig, git, curl, openssl, openssl headers"
  for t in python3 gcc g++ make swig git curl openssl; do
    command -v "$t" >/dev/null 2>&1 || die "missing: $t"
  done
fi

PYVER="$(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "python 3.8 or newer is required (found $PYVER)"
python3 -c 'import venv, ensurepip' 2>/dev/null || die "python3-venv is missing (apt-get install python3-venv)"
ok "python3 $PYVER, openssl present"

# ---- Detect 3CX SBC (optional coexistence) ----
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

# ---- Gather settings (or keep an existing config) ----
echo; c "Configuration"
if [ -f "$ETC/config.ini" ] && [ -z "${SB_RECONFIGURE:-}" ]; then
  KEEP_CONFIG=1
  BIND_IP="$(grep -E '^\s*bind_ip' "$ETC/config.ini" | head -1 | sed 's/.*=\s*//' | tr -d '[:space:]')"
  if [ -z "$BIND_IP" ] || [ "$BIND_IP" = "auto" ]; then
    BIND_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
    [ -n "$BIND_IP" ] || BIND_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  ok "keeping existing $ETC/config.ini (set SB_RECONFIGURE=1 to re-prompt)"
else
  KEEP_CONFIG=0
  DEF_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
  [ -n "$DEF_IP" ] || DEF_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ask "Bridge LAN IP (phones point here)" "${DEF_IP:-auto}" BIND_IP
  ask "PBX / 3CX SBC IP (same box as SBC? use this host's LAN IP)" "$BIND_IP" SBC_IP
  ask "PBX SIP port"                      "5060"             SBC_PORT
  ask "Registrar domain (3CX: NNN.3cx.cloud; FreePBX: PBX IP)" "$SBC_IP" DOMAIN
  ask "Phone timezone"                    "Central Standard Time" TZ
  # Per-phone extension, auth ID and password are assigned later in the web UI, not here.
fi

# ---- Lay out files ----
echo; c "Installing to $PREFIX"
mkdir -p "$PREFIX/tls" "$PREFIX/www/keystore/certs" "$PREFIX/www/fileserver/phoneconfig" "$ETC"

# Program files
fetch shorebridge.py   "$PREFIX/shorebridge.py"   0755
fetch media.py         "$PREFIX/media.py"         0644
fetch pbx.py           "$PREFIX/pbx.py"           0644
fetch connectors.py    "$PREFIX/connectors.py"    0644
fetch build_pjsua2.sh  "$PREFIX/build_pjsua2.sh"  0755
fetch requirements.txt "$PREFIX/requirements.txt" 0644
mkdir -p "$PREFIX/connectors.d"   # Drop third-party connector .py files here
ok "shorebridge.py, media.py, pbx.py, connectors.py"

# Control CLI goes to /usr/local/bin/shorebridge
fetch bin/shorebridge /usr/local/bin/shorebridge 0755
ok "shorebridge CLI (try: shorebridge update)"

# ---- Python virtualenv ----
echo; c "Python environment ($VENV)"
# Recreate the venv when it is broken or was built for a different python
# (for example after an OS upgrade). The pjsua2 build is redone in that case.
if [ -d "$VENV" ]; then
  venv_ver="$("$VENV/bin/python" -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
  if [ "$venv_ver" != "$PYVER" ]; then
    warn "existing venv is unusable or built for python ${venv_ver:-?}; recreating"
    rm -rf "$VENV"
  fi
fi
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV" || die "could not create the virtualenv"
  ok "created venv"
else
  ok "reusing venv (python $PYVER)"
fi
"$VENV/bin/pip" install --quiet --upgrade pip setuptools wheel || die "could not upgrade pip in the venv"
# Pure python dependencies, if any are listed
if grep -qE '^[[:space:]]*[A-Za-z0-9]' "$PREFIX/requirements.txt"; then
  "$VENV/bin/pip" install --quiet -r "$PREFIX/requirements.txt" || die "pip could not install requirements.txt"
fi
ok "pip $("$VENV/bin/pip" --version | awk '{print $2}')"

# ---- pjsua2 ----
c "pjsua2 (PBX side)"
if "$VENV/bin/python" -c 'import pjsua2' 2>/dev/null && [ "${SB_FORCE_BUILD:-0}" != 1 ]; then
  ok "pjsua2 already installed"
else
  warn "building pjsua2 from source; this takes a few minutes on a PC and 10 to 30 minutes on a Raspberry Pi"
  bash "$PREFIX/build_pjsua2.sh" "$VENV" || die "pjsua2 build failed (see output above). Fix the problem and re-run the installer"
  ok "pjsua2 built and installed"
fi

# ---- Certificates: our own CA and a switch cert the phone will trust ----
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
cp "$TLS/hq_ca.crt" "$PREFIX/www/keystore/certs/hq_ca.crt"     # Served to the phone over HTTP
chmod 600 "$TLS/"*.key
ok "switch cert for $BIND_IP (signed by our CA)"

# ---- Config ----
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
; Local SIP port used by the bridge toward the PBX (pjsua2)
sip_port = 5062
; auto = use the PBX address as an outbound proxy only when it differs from the domain
outbound_proxy = auto

[phone]
timezone = $TZ

[connector]
type = manual
EOF
  chmod 600 "$ETC/config.ini"
  ok "wrote $ETC/config.ini"
fi

# ---- Port conflict check ----
for p in 80 5061 5448 5062 8910; do
  if ss -ltnup 2>/dev/null | grep -q ":$p "; then warn "port $p is already in use (may conflict)"; fi
done

# ---- systemd ----
c "Installing systemd service"
fetch systemd/shorebridge.service /etc/systemd/system/shorebridge.service 0644
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
    shorebridge update [--branch NAME]
                           update from NAME (default: main) + restart
    shorebridge repair     rebuild the venv and pjsua2, then restart
    shorebridge logs       follow the log
    shorebridge config     edit settings
    shorebridge ui         print the admin UI url

  Config:  $ETC/config.ini      Phones:  $ETC/phones.json (or the web UI)
  Python:  $VENV
EOF
