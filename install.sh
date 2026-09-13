#!/usr/bin/env sh
# Install netwatch on Linux.
#
#   curl -fsSL https://github.com/FalconTechDev/netwatch/releases/latest/download/install.sh | sh
#
# What this does, in as many words:
#   1. downloads the release archive and checks it against its checksum
#   2. puts netwatch in /usr/local/bin
#   3. grants it CAP_BPF and CAP_PERFMON, so it runs without sudo afterwards
#   4. creates /var/log/netwatch for the recorder to write to
#
# Step 3 is the one worth reading twice. netwatch reads which process sent
# which packet, and on Linux that means loading a program into the kernel,
# which is privileged. The alternative to these two capabilities is running the
# whole thing as root every time; these are the narrow rights that replaced
# blanket CAP_SYS_ADMIN in kernel 5.8, and they are what is asked for here.
#
#   NETWATCH_DIR=<path>       install somewhere else
#   NETWATCH_VERSION=v0.9.0   a particular release
#   NETWATCH_NO_CAPS=1        skip the capabilities; you will need sudo to run

set -eu

REPO='FalconTechDev/netwatch'
DIR="${NETWATCH_DIR:-/usr/local/bin}"
LOGDIR=/var/log/netwatch

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "netwatch's Linux build is for Linux; on Windows use install.ps1."
[ "$(uname -m)" = x86_64 ] || die "only x86_64 is built at the moment (this is $(uname -m))."

# A kernel that cannot answer the question is worth saying so about now,
# rather than after everything is installed.
if [ ! -r /sys/kernel/btf/vmlinux ]; then
    say "warning: this kernel has no BTF (/sys/kernel/btf/vmlinux)."
    say "         netwatch may fail to load its program. A kernel built with"
    say "         CONFIG_DEBUG_INFO_BTF is needed."
fi

# Root is needed to write to /usr/local/bin and to grant capabilities. Ask for
# it once, up front, rather than failing halfway through.
SUDO=''
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run this as root, or install sudo."
    SUDO='sudo'
fi

TAG="${NETWATCH_VERSION:-}"
if [ -z "$TAG" ]; then
    say 'Looking up the latest release...'
    TAG=$(
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1
    )
fi
[ -n "$TAG" ] || die 'could not work out the latest version; set NETWATCH_VERSION.'

ARCHIVE="netwatch-$TAG-x86_64-unknown-linux-gnu.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading netwatch $TAG..."
curl -fsSL "$BASE/$ARCHIVE" -o "$TMP/$ARCHIVE" || die "could not download $BASE/$ARCHIVE"

if curl -fsSL "$BASE/$ARCHIVE.sha256" -o "$TMP/sum" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        want=$(cut -d' ' -f1 <"$TMP/sum")
        got=$(sha256sum "$TMP/$ARCHIVE" | cut -d' ' -f1)
        [ "$want" = "$got" ] || die 'checksum mismatch - the download is not what the release published.'
        say 'Checksum matches.'
    fi
else
    say 'No checksum published for this release; skipping verification.'
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
BIN=$(find "$TMP" -type f -name netwatch -perm -u+x | head -n1)
[ -n "$BIN" ] || die 'the archive did not contain netwatch.'

$SUDO install -d -m 0755 "$DIR"
$SUDO install -m 0755 "$BIN" "$DIR/netwatch"
say "Installed $DIR/netwatch"

if [ "${NETWATCH_NO_CAPS:-}" = 1 ]; then
    say 'Skipped the capabilities (NETWATCH_NO_CAPS was set); run netwatch with sudo.'
elif command -v setcap >/dev/null 2>&1; then
    if $SUDO setcap cap_bpf,cap_perfmon=eip "$DIR/netwatch" 2>/dev/null; then
        say 'Granted CAP_BPF and CAP_PERFMON: netwatch runs without sudo.'
    else
        # Never claim to have done this. Someone believing they need no sudo,
        # on a filesystem that cannot carry capabilities, would just see a
        # permission error with no idea why.
        say 'Could not set capabilities (some filesystems cannot hold them).'
        say 'Run netwatch with sudo instead.'
    fi
else
    say 'setcap is not installed, so netwatch will need sudo to run.'
    say 'Install libcap2-bin (Debian/Ubuntu) or libcap (Fedora/Arch) and re-run this.'
fi

$SUDO install -d -m 0755 "$LOGDIR"
say "Log directory $LOGDIR"

say ''
say 'Try:'
say '    netwatch                    live view'
say '    netwatch top --seconds 10   watch for ten seconds, then print'
say '    netwatch record             record to the log, until stopped'
say '    netwatch report --hours 12  what used the connection while you were away'
