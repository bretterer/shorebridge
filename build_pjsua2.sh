#!/usr/bin/env bash
#
# Build and install the pjsua2 Python module into the shorebridge venv.
#
# Usage: build_pjsua2.sh [venv_dir]
#
# Environment:
#   PJSIP_VERSION   pjproject tag to build (default 2.17)
#   SB_FORCE_BUILD  set to 1 to rebuild even if pjsua2 already imports
#   SB_JOBS         parallel make jobs (default: number of CPUs, capped at 4)
#
# pjsua2 is not published on PyPI, so it has to be compiled from the pjproject
# sources. The build needs: git, swig (or the pip swig wheel), a C/C++ compiler,
# make, python3-dev and libssl-dev. install.sh installs those first.
#
set -euo pipefail

VENV="${1:-/opt/shorebridge/venv}"
PJSIP_VERSION="${PJSIP_VERSION:-2.17}"
PY="$VENV/bin/python"

log() { printf '  %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ -x "$PY" ] || die "venv python not found at $PY"

# Skip the build when the right version is already importable
have="$("$PY" -c 'import pjsua2; print(pjsua2.Endpoint().libVersion().full)' 2>/dev/null || true)"
if [ -n "$have" ] && [ "${SB_FORCE_BUILD:-0}" != 1 ]; then
  case "$have" in
    "$PJSIP_VERSION"*) log "pjsua2 $have already installed, skipping build"; exit 0 ;;
    *) log "pjsua2 $have is installed but $PJSIP_VERSION is wanted, rebuilding" ;;
  esac
fi

for tool in git make gcc g++; do
  command -v "$tool" >/dev/null 2>&1 || die "missing build tool: $tool"
done
[ -f "$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["include"])')/Python.h" ] \
  || die "Python.h not found (install python3-dev)"

# Build helpers inside the venv
"$VENV/bin/pip" install --quiet --upgrade pip setuptools wheel
if ! command -v swig >/dev/null 2>&1; then
  log "swig not found on PATH, installing the pip swig package"
  "$VENV/bin/pip" install --quiet swig
fi
export PATH="$VENV/bin:$PATH"

jobs="${SB_JOBS:-}"
if [ -z "$jobs" ]; then
  jobs="$(nproc 2>/dev/null || echo 2)"
  [ "$jobs" -le 4 ] || jobs=4
fi

work="$(mktemp -d /var/tmp/shorebridge-pjsip.XXXXXX)"
trap 'rm -rf "$work"' EXIT

log "Fetching pjproject $PJSIP_VERSION"
git clone --quiet --depth 1 --branch "$PJSIP_VERSION" https://github.com/pjsip/pjproject.git "$work/pjproject"
cd "$work/pjproject"

# Only audio is needed. The null sound device drives the media clock.
log "Configuring"
CFLAGS="-O2 -fPIC" CXXFLAGS="-O2 -fPIC" ./configure \
  --disable-video --disable-sdl --disable-ffmpeg --disable-v4l2 \
  --disable-openh264 --disable-vpx --disable-opencore-amr --disable-silk \
  --disable-opus --disable-bcg729 --disable-libyuv --disable-libwebrtc \
  --disable-darwin-ssl >"$work/configure.log" 2>&1 \
  || { tail -n 30 "$work/configure.log" >&2; die "configure failed"; }

log "Compiling pjproject (this can take 10 to 30 minutes on a Raspberry Pi)"
{ make dep && make -j"$jobs"; } >"$work/make.log" 2>&1 \
  || { tail -n 40 "$work/make.log" >&2; die "pjproject build failed"; }

log "Building the pjsua2 Python wheel"
cd pjsip-apps/src/swig/python
{ make PYTHON_EXE="$PY" wheel; } >"$work/wheel.log" 2>&1 \
  || { tail -n 40 "$work/wheel.log" >&2; die "pjsua2 wheel build failed"; }

wheel="$(ls dist/pjsua2-*.whl 2>/dev/null | head -n 1)"
[ -n "$wheel" ] || die "no wheel produced"
"$VENV/bin/pip" install --quiet --force-reinstall --no-deps "$wheel"

got="$("$PY" -c 'import pjsua2; print(pjsua2.Endpoint().libVersion().full)' 2>/dev/null || true)"
[ -n "$got" ] || die "pjsua2 installed but does not import"
log "Installed pjsua2 $got"
