#!/bin/sh
# Run in the guest desktop's process tree; failure is not a skip.
set -eu
: "${DBUS_SESSION_BUS_ADDRESS:?Run from the guest desktop terminal}"
: "${XDG_RUNTIME_DIR:?Run from the guest desktop terminal}"
app=${1:-org.chromium.Chromium}
work=$(mktemp -d "${TMPDIR:-/tmp}/md-document-portal.XXXXXXXX")
document_id=
cleanup() {
    if [ -n "$document_id" ]; then
        timeout 30 flatpak document-unexport --doc-id "$document_id" || :
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'document-before\n' > "$work/source.txt"
# EVENT_WAIT: portal export and sandbox process completion; expiry fails.
document=$(timeout 30 flatpak document-export --unique --transient \
    --app="$app" --allow-read --allow-write "$work/source.txt")
case "$document" in
    "$XDG_RUNTIME_DIR"/doc/*/source.txt) ;;
    *) echo "Unexpected document path: $document" >&2; exit 1 ;;
esac
document_id=${document#"$XDG_RUNTIME_DIR/doc/"}
document_id=${document_id%%/*}
test -f "$document"
timeout 45 flatpak run --command=sh "$app" -ec '
    test "$(cat "$1")" = document-before
    printf "document-after\n" > "$1"
    test "$(cat "$1")" = document-after
' sh "$document"
test "$(cat "$work/source.txt")" = document-after
timeout 30 flatpak document-unexport --doc-id "$document_id"
document_id=
test ! -e "$document"
echo 'PASS document export, sandbox read/write and revocation'
