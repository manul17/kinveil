#!/bin/sh
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

if [ ! -f "$SCRIPT_DIR/kinveil" ]; then
    echo "error: expected '$SCRIPT_DIR/kinveil' next to install.sh" >&2
    exit 1
fi

mkdir -p "$PREFIX/bin" "$PREFIX/share/kinveil/artifacts"
install -m 0755 "$SCRIPT_DIR/kinveil" "$PREFIX/bin/kinveil"

if [ -d "$SCRIPT_DIR/artifacts" ]; then
    for f in "$SCRIPT_DIR/artifacts/"*; do
        if [ -f "$f" ]; then
            install -m 0755 "$f" "$PREFIX/share/kinveil/artifacts/$(basename -- "$f")"
        fi
    done
fi

printf 'Installed %s/bin/kinveil and bundled runtime binaries in %s/share/kinveil/artifacts\n' "$PREFIX" "$PREFIX"
case ":${PATH:-}:" in
    *":$PREFIX/bin:"*) ;;
    *) printf 'Note: add %s/bin to your PATH if it is not already present.\n' "$PREFIX" ;;
esac
