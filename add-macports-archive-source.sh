#!/bin/bash
#
# add-macports-archive-source.sh -- trust a portserver instance on the local
# network as a MacPorts binary archive source.
#
# Given the Bonjour/mDNS hostname of a machine running portserver.py, this:
#   1. Fetches its public key over HTTP and validates it's actually a usable
#      RSA public key (not just "curl succeeded").
#   2. Installs the key under /opt/local/share/macports/keys/archives/.
#   3. Registers that key in /opt/local/etc/macports/pubkeys.conf.
#   4. Registers the server as an archive source in
#      /opt/local/etc/macports/archive_sites.conf.
#
# Safe to re-run: re-running with the same hostname replaces the previously
# fetched key and archive_sites.conf entry rather than duplicating them.
#
# Usage:
#   sudo ./add-macports-archive-source.sh <hostname> [port]
#
# Example:
#   sudo ./add-macports-archive-source.sh Spektr.local
#   sudo ./add-macports-archive-source.sh Spektr.local 6227
#
# NOTE: this trusts the fetched key on first use over plain HTTP -- there is
# no certificate pinning. That's an accepted tradeoff for a home-LAN setup,
# but the printed fingerprint lets you cross-check against the server
# itself (e.g. by running the same openssl command there) before trusting
# it, if you want that extra assurance.

set -euo pipefail

DEFAULT_PORT=6227

KEYS_DIR="/opt/local/share/macports/keys/archives"
PUBKEYS_CONF="/opt/local/etc/macports/pubkeys.conf"
ARCHIVE_SITES_CONF="/opt/local/etc/macports/archive_sites.conf"

usage() {
    echo "usage: $0 <hostname> [port]" >&2
    echo "  e.g.: $0 Spektr.local" >&2
    echo "        $0 Spektr.local 6227" >&2
    exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

HOSTNAME_ARG="$1"
PORT="${2:-$DEFAULT_PORT}"

case "$PORT" in
    ''|*[!0-9]*)
        echo "error: port must be numeric, got '$PORT'" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this needs root, to write under /opt/local. Re-run with sudo:" >&2
    echo "  sudo $0 $*" >&2
    exit 1
fi

for cmd in curl openssl; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "error: required command '$cmd' not found" >&2
        exit 1
    }
done

if [ ! -d "$(dirname "$PUBKEYS_CONF")" ]; then
    echo "error: $(dirname "$PUBKEYS_CONF") doesn't exist -- is MacPorts installed at /opt/local?" >&2
    exit 1
fi

BASE_URL="http://${HOSTNAME_ARG}:${PORT}"

# Slugify the hostname the same way as the worked example:
#   Spektr.local -> spektr-local -> spektr-local-pub.pem
KEY_SLUG="$(printf '%s' "$HOSTNAME_ARG" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')"
KEY_FILENAME="${KEY_SLUG}-pub.pem"
KEY_PATH="${KEYS_DIR}/${KEY_FILENAME}"

TMP_KEY="$(mktemp)"
trap 'rm -f "$TMP_KEY"' EXIT

echo "==> Checking ${BASE_URL}/pubkey.pem ..."
if ! curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
        "${BASE_URL}/pubkey.pem" -o "$TMP_KEY"; then
    echo "error: could not fetch ${BASE_URL}/pubkey.pem -- is portserver running on ${HOSTNAME_ARG}:${PORT}?" >&2
    exit 1
fi

if [ ! -s "$TMP_KEY" ]; then
    echo "error: fetched pubkey.pem was empty" >&2
    exit 1
fi

if ! openssl pkey -pubin -noout -in "$TMP_KEY" >/dev/null 2>&1; then
    echo "error: ${BASE_URL}/pubkey.pem did not return a valid public key" >&2
    exit 1
fi

FINGERPRINT="$(openssl pkey -pubin -in "$TMP_KEY" -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}')"
echo "==> Valid public key fetched. SHA-256 fingerprint: ${FINGERPRINT}"
echo "    (cross-check this against the key on ${HOSTNAME_ARG} itself if you want to be sure)"

echo "==> Installing key at ${KEY_PATH}"
mkdir -p "$KEYS_DIR"
install -m 0644 "$TMP_KEY" "$KEY_PATH"
chmod a+r "$KEY_PATH"

echo "==> Ensuring ${KEY_PATH} is listed in ${PUBKEYS_CONF}"
touch "$PUBKEYS_CONF"
if grep -Fxq "$KEY_PATH" "$PUBKEYS_CONF"; then
    echo "    already present"
else
    echo "$KEY_PATH" >> "$PUBKEYS_CONF"
    echo "    added"
fi

echo "==> Ensuring an archive_sites.conf entry for '${HOSTNAME_ARG}'"
touch "$ARCHIVE_SITES_CONF"

TMP_SITES="$(mktemp)"
trap 'rm -f "$TMP_KEY" "$TMP_SITES"' EXIT

# Drop any existing block for this hostname (so re-running with a new port
# replaces the old entry instead of leaving a stale duplicate), then append
# a fresh one.
awk -v target="$HOSTNAME_ARG" '
    BEGIN { skip = 0 }
    /^name[ \t]+/ {
        skip = ($2 == target) ? 1 : 0
    }
    { if (!skip) print }
' "$ARCHIVE_SITES_CONF" > "$TMP_SITES"

# Trim any trailing blank lines so we always add exactly one blank-line
# separator before the new block, regardless of what was there before.
# (Done in awk, not sed -i, since BSD sed on macOS and GNU sed on Linux
# take incompatible -i syntax.)
TMP_SITES_TRIMMED="$(mktemp)"
trap 'rm -f "$TMP_KEY" "$TMP_SITES" "$TMP_SITES_TRIMMED"' EXIT
awk '
    { lines[NR] = $0 }
    END {
        n = NR
        while (n > 0 && lines[n] == "") n--
        for (i = 1; i <= n; i++) print lines[i]
    }
' "$TMP_SITES" > "$TMP_SITES_TRIMMED"
mv "$TMP_SITES_TRIMMED" "$TMP_SITES"

{
    cat "$TMP_SITES"
    # Make sure there is exactly one blank line before our new block,
    # regardless of what the file ended with.
    [ -s "$TMP_SITES" ] && echo ""
    echo "name    ${HOSTNAME_ARG}"
    echo "urls    ${BASE_URL}/"
} > "$ARCHIVE_SITES_CONF"

echo "    done"
echo
echo "All set. '${HOSTNAME_ARG}' is now a trusted MacPorts archive source."