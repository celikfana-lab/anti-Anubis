#!/bin/bash
# Build and install the native messaging host for the Anubis Native Solver
# extension.  Works for both regular Firefox (~/.mozilla) and snap Firefox
# (~/snap/firefox/common/.mozilla).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NATIVE="$HERE/native"

echo "[*] building static native host"
make -C "$NATIVE" clean
make -C "$NATIVE"

# Snap Firefox can only execute files it can see inside its sandbox; this
# directory is part of the snap's home and is visible to both builds.
DEST="$HOME/snap/firefox/common/anubis-native"
mkdir -p "$DEST"
install -m 0755 "$NATIVE/anubis_native" "$DEST/anubis_native"

make_manifest() {
    local dir="$1"
    mkdir -p "$dir"
    sed "s|@HOST@|$DEST/anubis_native|" "$NATIVE/anubis_native.json.in" \
        > "$dir/anubis_native.json"
    echo "[*] wrote $dir/anubis_native.json"
}

make_manifest "$HOME/.mozilla/native-messaging-hosts"
make_manifest "$HOME/snap/firefox/common/.mozilla/native-messaging-hosts"

echo
echo "[+] host installed: $DEST/anubis_native"
echo "[+] extension ID:  anubis-native@flixbrute.local"
echo
echo "Load the extension:"
echo "  - temporary: Firefox -> about:debugging -> This Firefox ->"
echo "    Load Temporary Add-on -> select firefox-anubis/manifest.json"
echo "  - or:        npx web-ext run --source-dir \"$HERE\""
echo
echo "Then just browse to an Anubis-protected site.  If the native host fails,"
echo "the extension reloads the page and lets Anubis' own JS/WASM solver run."
