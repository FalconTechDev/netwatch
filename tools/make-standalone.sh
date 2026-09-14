#!/usr/bin/env bash
# Build a standalone Linux installer: one file that carries netwatch inside it
# and installs without downloading anything.
#
#   tools/make-standalone.sh <netwatch-binary> [output]
#
# The result is `install.sh` with the release archive appended to it, base64'd.
# Keeping one copy of the install logic rather than two is the whole point: a
# second implementation would drift from the one people actually use, and the
# offline path is exactly the one nobody would notice had rotted.
#
# It must be run as a file, not piped into sh — it reads its own payload out of
# $0, and a pipe has no $0 to read.

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
bin=${1:-}
out=${2:-$here/dist/netwatch-standalone-installer.sh}

[ -n "$bin" ] || { echo "usage: $0 <netwatch-binary> [output]" >&2; exit 1; }
[ -x "$bin" ] || { echo "error: $bin is not an executable file" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The payload is the same archive shape install.sh already knows how to unpack,
# so the embedded installer needs no special case for having been handed one.
mkdir -p "$tmp/netwatch"
install -m 0755 "$bin" "$tmp/netwatch/netwatch"
[ -f "$here/README.md" ] && cp "$here/README.md" "$tmp/netwatch/"
[ -f "$here/LICENSE" ] && cp "$here/LICENSE" "$tmp/netwatch/"
tar -czf "$tmp/payload.tar.gz" -C "$tmp" netwatch

mkdir -p "$(dirname "$out")"
{
    cat <<'HEADER'
#!/usr/bin/env sh
# netwatch — standalone installer for Linux.
#
# Everything needed is inside this one file: the binary, the installer, and
# nothing to download. Run it as a file:
#
#   sh netwatch-standalone-installer.sh
#
# It installs to /usr/local/bin and grants CAP_BPF and CAP_PERFMON so netwatch
# runs without sudo afterwards. NETWATCH_DIR, NETWATCH_NO_CAPS and the rest of
# the usual variables still work.

set -eu

# A pipe has no file to read a payload out of, and the failure would otherwise
# be a confusing one about a corrupt archive.
case "${0:-}" in
    -|'' |sh|/dev/stdin|bash) printf 'error: run this as a file, not piped: sh %s\n' "netwatch-standalone-installer.sh" >&2; exit 1 ;;
esac
[ -r "$0" ] || { printf 'error: cannot read %s to unpack myself\n' "$0" >&2; exit 1; }

command -v base64 >/dev/null 2>&1 || { printf 'error: base64 is needed to unpack this installer\n' >&2; exit 1; }

_nw_tmp=$(mktemp -d)
trap 'rm -rf "$_nw_tmp"' EXIT INT TERM

# Split this file into its two halves: the installer, then the archive.
sed -e '1,/^__INSTALLER__$/d' -e '/^__ARCHIVE__$/,$d' "$0" > "$_nw_tmp/install.sh"
sed -e '1,/^__ARCHIVE__$/d' "$0" | base64 -d > "$_nw_tmp/netwatch-x86_64-unknown-linux-gnu.tar.gz"

NETWATCH_ARCHIVE_FILE="$_nw_tmp/netwatch-x86_64-unknown-linux-gnu.tar.gz" \
    sh "$_nw_tmp/install.sh"
exit $?
__INSTALLER__
HEADER
    cat "$here/install.sh"
    echo '__ARCHIVE__'
    base64 "$tmp/payload.tar.gz"
} > "$out"

chmod 0755 "$out"
echo "wrote $out ($(wc -c <"$out") bytes)"
