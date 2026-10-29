#!/bin/sh
# Install wt-agent on Linux or macOS from a release tarball.
#
# Usage: sh install.sh --base-url https://dl.example.com/wt-agent/1.2.3 --sha256 <hex of the tarball>
#
# The tarball is downloaded to a temp dir, its sha256 is checked against the value you pass (get
# it from the release page or a signed checksum file, not from the same download), and only then
# is it unpacked. Download and read this script before running it as root; do not pipe it from
# the network into a shell. This script never pipes anything into one either.
set -eu

base= sha=
while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) base=$2; shift 2 ;;
    --sha256) sha=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$base" ] && [ -n "$sha" ] || { echo "need --base-url and --sha256" >&2; exit 2; }
case "$base" in https://*) ;; *) echo "--base-url must be https" >&2; exit 2 ;; esac

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file="wt-agent-$os-$arch.tar.gz"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$tmp/$file" "$base/$file"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$file" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1); fi
[ "$got" = "$sha" ] || { echo "sha256 mismatch: expected $sha, got $got" >&2; exit 1; }

tar -xzf "$tmp/$file" -C "$tmp" wt-agent
install -m 0755 "$tmp/wt-agent" /usr/local/bin/wt-agent
if [ "$os" = darwin ] && ! dscl . -read /Users/_wtagent >/dev/null 2>&1; then
  # an unprivileged account for the LaunchDaemon (system accounts live below 500)
  id=$(dscl . -list /Users UniqueID | awk '$2 >= 300 && $2 < 400 { m = $2 } END { print (m ? m + 1 : 300) }')
  dscl . -create /Groups/_wtagent PrimaryGroupID "$id"
  dscl . -create /Users/_wtagent UniqueID "$id"
  dscl . -create /Users/_wtagent PrimaryGroupID "$id"
  dscl . -create /Users/_wtagent UserShell /usr/bin/false
  dscl . -create /Users/_wtagent RealName "Watchtower agent"
  mkdir -p /usr/local/var/wt-agent /usr/local/etc/wt-agent
  chown _wtagent:_wtagent /usr/local/var/wt-agent
fi
echo "installed /usr/local/bin/wt-agent. Next: write the config and token (docs/product/infra/agent.md)."
