#!/usr/bin/env sh
# upterm-2404-installer.sh — safe 1-liner-friendly installer for Upterm on Ubuntu 24.04+
# Requires: sh, uname, tar, install, and either curl or wget (busybox wget ok)
# Installs to: /usr/local/bin/upterm (overwrites if present)
#
# Usage:
#   sh upterm-2404-installer.sh
#   upterm --version
#
# Quick start (read-only share):
#   upterm host --read-only -- bash
#   upterm session current         # prints the join command
#
# Restrict by pubkey (only this user can join):
#   upterm host --read-only --authorized-key ~/.ssh/teammate.pub -- bash
#
# Use your own relay (self-hosted uptermd):
#   upterm host --server ssh://uptermd.your.domain:22 --read-only -- bash

set -eu

REPO="owenthereal/upterm"
BIN="upterm"
DEST="/usr/local/bin"
have() { command -v "$1" >/dev/null 2>&1; }
need() { if ! have "$1"; then echo "[-] required tool '$1' is missing" >&2; exit 1; fi; }

need uname
need tar
need install

OS="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m 2>/dev/null)"

if ! have curl && ! have wget; then
  echo "[-] either 'curl' or 'wget' is required" >&2
  exit 1
fi

if [ -z "$OS" ]; then
  echo "[-] failed to determine operating system via uname" >&2
  exit 1
fi

if [ "$OS" != "linux" ]; then
  echo "[-] only linux is supported by this installer (detected: $OS)" >&2
  exit 1
fi

case "$ARCH" in
  x86_64|amd64)  TARCH="amd64" ;;
  aarch64|arm64) TARCH="arm64" ;;
  *)
    echo "[-] unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

if [ ! -d "$DEST" ]; then
  echo "[*] creating $DEST"
  if ! mkdir -p "$DEST" 2>/dev/null; then
    echo "[-] failed to create $DEST (insufficient permissions?)" >&2
    exit 1
  fi
fi

if [ ! -w "$DEST" ]; then
  echo "[-] destination $DEST is not writable; rerun with sudo or as root" >&2
  exit 1
fi

# mktemp -d may not exist on some busybox builds; provide fallback
if TMP=$(mktemp -d 2>/dev/null); then
  :
else
  TMP="/tmp/upterm-installer-$$"
  mkdir -p "$TMP" || { echo "[-] failed to create temp dir" >&2; exit 1; }
fi
trap 'rm -rf "$TMP"' EXIT INT HUP TERM

latest_tag() {
  echo "[*] discovering latest release tag…" >&2
  if have curl; then
    curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" || return 1
  else
    wget -q --max-redirect=0 -S -O /dev/null "https://github.com/$REPO/releases/latest" 2>&1 | awk '/^  Location: /{u=$2} END{print u}'
  fi
}

LAST_URL="$(latest_tag)"
TAG="${LAST_URL##*/}"
if [ -z "$TAG" ]; then
  echo "[-] failed to detect latest tag" >&2
  exit 1
fi

tarball_name="${BIN}_${OS}_${TARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$tarball_name"

archive="$TMP/upterm.tar.gz"

fetch() {
  echo "[*] downloading $URL"
  if have curl; then
    curl -fsSL "$URL" -o "$archive"
  else
    wget -q "$URL" -O "$archive"
  fi
}

if ! fetch; then
  echo "[-] failed to download release tarball" >&2
  exit 1
fi

if [ ! -s "$archive" ]; then
  echo "[-] downloaded file is empty" >&2
  exit 1
fi

echo "[*] extracting"
if ! tar -xzf "$archive" -C "$TMP"; then
  echo "[-] failed to extract tarball" >&2
  exit 1
fi

if [ ! -f "$TMP/$BIN" ]; then
  echo "[-] expected binary '$BIN' not found in tarball" >&2
  ls -la "$TMP" >&2 || true
  exit 1
fi

echo "[*] installing to $DEST/$BIN"
if ! install -m 0755 "$TMP/$BIN" "$DEST/$BIN"; then
  echo "[-] failed to install binary" >&2
  exit 1
fi

echo "[+] installed: $DEST/$BIN"
if "$DEST/$BIN" --version >/dev/null 2>&1; then
  "$DEST/$BIN" --version
else
  echo "[*] installed binary does not support --version" >&2
fi

cat <<'EOS'

Usage examples:
  upterm host --read-only -- bash
  upterm session current
  upterm host --read-only --authorized-key ~/.ssh/teammate.pub -- bash
  upterm host --server ssh://uptermd.your.domain:22 --read-only -- bash

Security tips:
  • Prefer --authorized-key or --github-user/--gitlab-user for access control.
  • Use a self-hosted relay (uptermd) for internal shares.
EOS
