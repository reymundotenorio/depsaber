#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DEST_DIR="${DEPSABER_INSTALL_DIR:-$HOME/.local/bin}"
DEST="$DEST_DIR/depsaber"

mkdir -p "$DEST_DIR"
go build -trimpath -o "$DEST" "$ROOT/cmd/depsaber"
chmod 0755 "$DEST"

printf 'Installed DepSaber to %s\n' "$DEST"
printf 'Try: depsaber scan . --format text\n'
