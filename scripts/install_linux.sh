#!/bin/sh
# Run from a saved file in MagicDesk's Shell console; stdin is used for questions.
set -eu

# Raise this floor only when recipes require newer APK behavior.
MIN_MAGICDESK_VERSION_CODE=224
MIN_MAGICDESK_VERSION_NAME=2.1.2
readonly MIN_MAGICDESK_VERSION_CODE MIN_MAGICDESK_VERSION_NAME

usage() {
    cat <<'HELP'
Usage: sh install_linux.sh [--distro ID] [OPTIONS]

Install an ARM64 Linux userspace in Shroot. Choose applications or a desktop
independently of the distribution. Installation output stays in this console.
New environments use software rendering unless Turnip is selected; SteamOS
defaults to automatic Turnip detection and a Wayland Plasma desktop.

  --distro ID   Debian 13 (default), Ubuntu 24.04, Alpine 3.23, Fedora 44,
                Arch Linux ARM, openSUSE Tumbleweed, openKylin 3.0, Deepin 25,
                Manjaro ARM, Void (glibc), Armtix (runit), or SteamOS ARM64
  --name NAME   Independent environment name (default: distribution name)
  --image REF   Alternative OCI reference for the SAME distribution/version
  --downloads DIR  Verified archive/wheel cache (default: $HOME/downloads)
  --gui MODE    none, apps (default), xfce, weston, plasma (Debian 13/SteamOS),
                gnome (Fedora devkit), keep
                apps: Mousepad, Thunar, Xfce Terminal; xfce: X11 desktop;
                weston: Wayland desktop; plasma: X11 and nested Wayland desktops;
                gnome: experimental nested shell
  --protocol P  x11, wayland, both (default); installer application entries
  --gpu keep    Retain the graphics profile (default)
  --gpu auto    Try Turnip when KGSL is accessible, otherwise use software
  --gpu software  Use the distribution's software renderer
  --gpu turnip  Build private Mesa/Zink/Turnip for a supported Adreno KGSL GPU
  --libc MODE   shroot (default: prepare/reuse shared libc), keep, base (disable selection)
                On-device musl/glibc source build; original libc stays installed
  --prepare-libc NAME_OR_IMAGE [--jobs N]  Prepare libc only; no GUI/package setup
  --jobs N      libc/Mesa/KWin compiler jobs, 1-8 (default: 2)
  --locale L    UTF-8 locale, e.g. ru_RU.UTF-8, or keep (default)
  --timezone Z  IANA zone, system (Android zone), or keep (default)
  --create-user USER  Create an optional guest account, with a locked password
                Select it later with login --user or the shortcut User field;
                this does not change the image account or grant Android root
  --fonts F    basic (default), cjk (also Chinese/Japanese/Korean), keep
  --package P   Additional repository package (repeatable)
  --cache C     keep (default), clean (package downloads only, not Mesa work)
  --dns POLICY  auto (default: current network), preserve (image DNS), or IP[,IP...]
                auto/system copies the current network's DNS once; VPN is allowed
                Android Private DNS needs an explicit guest DNS choice
  --yes         Accept the selected configuration without questions
  --resume      Continue in --name NAME; detect distribution, preserve GUI by default
  --list        Show available distribution/profile combinations
  --print-system-setup  Print the guest setup script without running it
  --print-graphics-setup  Print the guest graphics setup script without running it
  --print-weston-setup  Print the guest Weston compatibility recipe
  --print-libc-setup  Print the guest libc setup script without running it
  --print-mesa-patch  Print the embedded patch without running the installer
  --print-flatpak-gl-helper  Print the embedded Flatpak GL publisher
  --print-snap-gpu-helper  Print the embedded Snap GPU publisher
  --print-kwin-patch [6.3.6|6.2.5]  Print the matching embedded KWin patch
  --print-recovery-reader  Print the embedded SteamOS image converter

Turnip builds inside Linux, needs several GB of free space and can take a while.
The source version and SHA-256 are pinned; no Android or distribution drivers are replaced.
Failed builds retain the previous profile and can be resumed. New launches use
the selected profile; already running programs are not restarted.
Void: set FORCE_IPV4=1 before this command if the network has no working IPv6.

No Termux or Android root is required. Use trusted images: Shroot is not a
security sandbox. The current shell/root identity is never changed.
GUI profiles include PipeWire audio, SDL gamepad discovery and Wayland decorations.
Graphical Shroot launches receive Android gamepads automatically; no host device binds.
GNOME devkit needs a working Linux system bus; this installer does not boot system services.
SteamOS retains its supplied applications, fonts and system drivers. The default
--gui plasma --gpu auto adds a nested desktop and a private graphics profile.
It needs about 35 GB free during conversion, not a booted recovery/VR session.
Its packages are updated from the image's configured repositories before first use.
HELP
    printf '\nRequires MagicDesk %s or newer (versionCode %s).\n' \
        "$MIN_MAGICDESK_VERSION_NAME" "$MIN_MAGICDESK_VERSION_CODE"
}

configurations() {
    printf '%s\n' 'Distribution  Version     Source                                   GUI' \
        'debian        13          Debian official slim rootfs               none/apps/xfce/weston/plasma' \
        'ubuntu        24.04       Ubuntu Base official rootfs               none/apps/xfce/weston' \
        'alpine        3.23        Alpine official minirootfs                none/apps/xfce/weston' \
        'fedora        44          registry.fedoraproject.org/fedora:44       none/apps/xfce/weston/gnome' \
        'arch          rolling     Arch Linux ARM official rootfs            none/apps/xfce/weston' \
        'opensuse      Tumbleweed  openSUSE official LXC rootfs               none/apps/xfce/weston' \
        'openkylin     3.0         openkylin/openkylin:latest                 none/apps/xfce/weston' \
        'deepin        25          linuxdeepin/deepin:crimson-arm64            none/apps/xfce/weston' \
        'manjaro       rolling     Manjaro ARM official rootfs               none/apps/xfce/weston' \
        'void          rolling     Void official glibc rootfs                none/apps/xfce/weston' \
        'armtix        rolling     Armtix official runit rootfs              none/apps/xfce/weston' \
        'steamos       0.3.0       Valve Steam Frame recovery                plasma/keep (supplied applications)'
    printf '%s\n' 'GUI profiles include Android audio and gamepad client libraries.' \
        'GNOME devkit requires a Linux system bus.'
}

# BEGIN GENERATED LIBC INTEGRATION
libc_entry_abi() { printf "%s\n" "6"; }
libc_build() {
    cat <<'LIBC_BUILD'
# Emitted by the guest recipe with its package-manager and payload helpers.
# The writable work directory and read-only cache are explicit launch bindings.
set -eu
case "$jobs" in [1-8]) ;; *) echo 'Invalid compiler job count' >&2; exit 1 ;; esac
work=/run/shroot-libc-build
cache=/run/shroot-libc-cache
target=${SHROOT_LIBC_BUILD_TARGET:-installed}
case "$target" in installed|image) ;; *) echo 'Invalid libc build target' >&2; exit 1 ;; esac

identify_libc() {
    if [ -f /lib/ld-musl-aarch64.so.1 ]; then
        kind=musl
        interpreter=/lib/ld-musl-aarch64.so.1
        original_libc=$interpreter
        version=$("$interpreter" 2>&1 | sed -n 's/^Version \([0-9.]*\)$/\1/p')
        runtime_loader=lib/libc.so
    elif [ -f /lib/ld-linux-aarch64.so.1 ]; then
        kind=glibc
        interpreter=/lib/ld-linux-aarch64.so.1
        # Upstream glibc ends its version sentence with a period; some distro banners do not.
        version=$(LC_ALL=C "$interpreter" --version | sed -n '1{s/\.$//;s/.* \([0-9][0-9.]*\)$/\1/p;}')
        original_libc=
        for library in /lib/aarch64-linux-gnu/libc.so.6 /lib64/libc.so.6 /usr/lib/libc.so.6 /lib/libc.so.6; do
            if [ -f "$library" ]; then original_libc=$library; break; fi
        done
        runtime_loader=lib/ld-linux-aarch64.so.1
    else
        echo 'No supported AArch64 musl/glibc loader; retaining Shroot Base.' >&2
        exit 1
    fi
    case "$version" in ''|*[!0-9.]*|.*|*.|*..*)
        printf 'Cannot identify libc version from %s (parsed: %s)\n' "$interpreter" "$version" >&2
        exit 1 ;;
    esac
    [ -n "$original_libc" ] || { echo 'Cannot locate the installed libc' >&2; exit 1; }
    loader_hash=$(sha256sum "$interpreter"); loader_hash=${loader_hash%% *}
    libc_hash=$(sha256sum "$original_libc"); libc_hash=${libc_hash%% *}
    manifest=$(printf 'shroot-libc-1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
        "$abi" "$kind" "$version" "$recipe" "$interpreter" "$original_libc" \
        "$loader_hash" "$libc_hash" "$runtime_loader")
    key=$(printf '%s\n' "$manifest" | sha256sum); key=${key%% *}
    prefix=/opt/shroot/libc/$key
}

identify_libc
if [ "$mode" = identify ]; then printf '%s\n' "$manifest"; exit 0; fi
cd "$work"
reuse_libc() {
    printf '%s\n' "$manifest" > manifest
    if [ -f "$cache/$key/manifest" ] && cmp -s manifest "$cache/$key/manifest"; then
        printf '%s\n' "$key" > result
        printf 'Reusing Shroot %s %s: %s\n' "$kind" "$version" "$key"
        return 0
    fi
    return 1
}
if reuse_libc; then exit 0; fi
trap 'status=$?; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Installing libc build dependencies...\n'
install_libc_tools
# Named environments now build in place; package upgrades may change their
# libc. An OCI preparation instead targets the unchanged source image.
if [ "$target" = installed ]; then identify_libc; fi
if reuse_libc; then exit 0; fi
mkdir -p "$work/tmp"
TMPDIR=$work/tmp
export TMPDIR
extract_integration
case "$kind" in
    musl) source_url=https://musl.libc.org/releases/musl-$version.tar.gz ;;
    glibc) source_url=https://ftp.gnu.org/gnu/glibc/glibc-$version.tar.xz ;;
esac
source_sha=
case "$kind:$version" in
    musl:1.2.5) source_sha=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 ;;
    glibc:2.41) source_sha=a5a26b22f545d6b7d7b3dd828e11e428f24f4fac43c934fb071b6a7d0828e901 ;;
esac
printf 'Building private %s %s from upstream sources; distribution libc stays installed.\n' "$kind" "$version"
archive=$work/${source_url##*/}
curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 30 -o "$archive.part" "$source_url"
if [ -n "$source_sha" ]; then printf '%s  %s\n' "$source_sha" "$archive.part" | sha256sum -c -
else printf 'Experimental source revision (HTTPS download): '; sha256sum "$archive.part"; fi
mv "$archive.part" "$archive"
mkdir source objects
# Sources belong to the builder, not archive UIDs; work may be an Android bind.
tar --no-same-owner -xf "$archive" -C source --strip-components=1
if [ "$kind" = musl ]; then
    python3 integration/libc/integrate_musl.py source
else
    python3 integration/libc/integrate_glibc.py source --library-path "$prefix/lib"
fi
cd objects
if [ "$kind" = musl ]; then
    CFLAGS='-O2 -mno-outline-atomics' ../source/configure --prefix="$prefix" --syslibdir="$prefix/lib"
else
    ../source/configure --prefix="$prefix" --libdir="$prefix/lib" --sysconfdir=/etc --disable-werror --enable-kernel=5.15
    # Keep user data in the distribution; only ABI-coupled runtime modules
    # belong to the private build. Makeconfig supplies these overridable paths.
    printf '%s\n' 'complocaledir = /usr/lib/locale' 'localedir = /usr/share/locale' \
        'i18ndir = /usr/share/i18n' 'zonedir = /usr/share/zoneinfo' > configparms
    # glibc BZ 31928: -Wp bypasses GCC driver defaults on e.g. Ubuntu.
    # Preserve configure's default (no fortification of libc itself), using
    # driver-level flags. This does not change flags for guest applications.
    printf '%s\n' 'no-fortify-source = -U_FORTIFY_SOURCE' \
        'fortify-source = -U_FORTIFY_SOURCE' >> configparms
fi
make -j"$jobs"
# Check exported symbols before staging: a runnable shell alone does not prove
# that compiler defaults preserved glibc's public ABI.
if [ "$kind" = glibc ]; then make -j"$jobs" check-abi; fi
if [ "$kind" = musl ]; then make install DESTDIR="$work/stage"
else make install install_root="$work/stage"; fi
cd "$work"
mkdir -p candidate/lib
for library in "$work/stage$prefix/lib/"*.so*; do
    [ ! -f "$library" ] || cp -L "$library" candidate/lib/
done
if [ "$kind" = glibc ]; then
    # iconv modules use glibc-private symbols and cannot be borrowed from the OS.
    cp -RL "$work/stage$prefix/lib/gconv" candidate/lib/
fi
cp manifest candidate/manifest
loader=$work/candidate/$runtime_loader
cat > probe.c <<'PROBE'
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cooperative_entry.h"
int main(int argc,char **argv) {
    unsigned (*abi)(void)=dlsym(RTLD_DEFAULT,"shroot_libc_entry_abi");
    if (!abi || abi()!=MD_ENTRY_VERSION || argc!=2) return 1;
    if (!md_entry_api_valid((const void *)getauxval(MD_AT_COOPERATIVE))) {
        fputs("No compatible Shroot direct-entry runtime\n",stderr); return 3;
    }
    struct stat st;
    int fd=open(argv[1],O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
    if (fd<0 || write(fd,"ok",2)!=2 || fstat(fd,&st) || st.st_size!=2 || close(fd) || unlink(argv[1])) return 2;
    puts("PASS private libc: entry ABI and file lifecycle"); return 0;
}
PROBE
cc -O2 -Iintegration/src probe.c -ldl -o probe
# EVENT_WAIT: probe and shell completion; timeout rejects publication.
timeout 30 "$loader" --library-path "$work/candidate/lib:/lib:/usr/lib" "$work/probe" "$work/probe-file"
timeout 30 "$loader" --library-path "$work/candidate/lib:/lib:/usr/lib" /bin/sh -ec 'id; printf "PASS private libc shell\n"'
if [ "$target" = installed ]; then
    built_manifest=$manifest
    identify_libc
    [ "$manifest" = "$built_manifest" ] || {
        echo 'Installed libc changed during compilation; retry preparation. Build not published.' >&2
        exit 1
    }
fi
printf '%s\n' "$key" > result
LIBC_BUILD
}
libc_integration() {
    cat <<'LIBC_INTEGRATION'
import base64, json, sys, zlib
from pathlib import Path
root = Path(sys.argv[1])
sources = json.loads(zlib.decompress(base64.b64decode('''
eNrdfQlb20i26F+pLBNLYMs2WwiM00PASXObQD4g3bcH0/pkSQZ1ZEkjyQSa5r+/s1RJpcWE9Mx977uvF2zXXuecOludqrp/HgZT
tz9dBKFnZdfPd8TzF2I8D/Lc98T0TuTXvrha+FkuUt8NEl98DfJrEeSZSBz3i3Pl9+ZOBB+pcCIP0u7C2PHEtR8mfppZk+iFOIcW
vqZB7kxD+BKnX4QXQFt5nN5RndR3vF4chXfCdVwo66S+8G+TMHCDXITOInKvxTSIvCC6wgYzPxc9fzGJXCfzxeT5y9/jaTZ5LoJI
XAx725em2N0VK6bw3etYdA6jGycMPOHG8yQIYZRQGn4sorwj3r5a24WeoJch1vEzx51EOMBRP11E/ew6jeO8h+DpEXiwSxhgM5eS
J1HupFd+Pnp5f/bj6cnJuX10+G7ffvf58OjAPt87/TA+3+kFUZY7Yeh7D+X4uRrPoMj/M5gDUNvngn0KGpHgukumMokCz4/yYHZn
YxXDFPeTSMA/wUxciN5M9CG5H3q9+SILe46TutdbG1YWW0NxuYuIj7g4/vMFEDDCcmVSEOV+mqQ+/B0tbaksHqfBVRA5IY1l9FKr
XZa5AZoJ4mj00gC46CWei7W3r4biT5EBVfYi0cn6v/3MhcVkYlwMem+sy5XJxHzZn0yG/aRjlo0CtvJg7ttImDBUGikMAYbHZfyw
Do8wiBa3TwHIFTb0OESabZXlX4jPSZYD/c8FtST8yMtobUlAwHShyciVq84RsKiC2NsVWTz3YRlB5VhMnSiC4sKLRRTnVhs0j/bt
vaOj0b5ogLXXU12VsB3eZwBF62W/v5v1rRUF4MsGlHcfdDhXEVymz+IUSTZ1YL0DiRNgJDwkdK6ihUKJtUUFtjb0hEWW9jW0yTLl
z12Ye9mfTuEwX9k1zFXisE6JssCumAImvuyKWVC25cWR/zglLcewH2ZaXV7Cx7HIFkkSp8hd9/aoisBF02cC4JZ3gSfmThABxxNn
xGfEO2AWFq1zrUla7/xbDVoxFYlV5iqdzp8rF88Ye39aK3+uWPCftaLhLkmBLGaisw+0BL0pvsGsRlHILI3n4m+ZMBInBVrZge/m
ZBJ1mlRVGUDLmIFHSRgRo8JvF0h6UK+CHESa+PNPcS/BJ4cXxq6T+ySaCoZJQ60wwl3xwE0zUO1rJ7uGtZBdO2ubW9li3hi2uVst
eq/9+tvfxIpqDjpqbaw2dGyuLHpffNeaAtEZzEC2QksKA7pcGQJ0/5Z9xx9AxaSENQzJmQaMDmRXdcTAD5bp/L2Bwjoqam1r0OHy
xQxl25XVAvDg2l/8O226atjPXypYQGVgRQquAESqcA9/NcDBMGfB7agfJ7mUxMQN+i+h2CR6aMg++IkcAbuJPZzvqKRxxRYeG5Kk
qQFzB9fDXNQUJs8nUeovMr8mYR+d3tsC71VxDKVIk6BZ9LUKl+LVK+HOE9HLiqpLS9cFVXMoCCMcRepnizBvljyFCWmsB1b83zJc
7EX9dlqiZjVm6eeLNBKDKn+SqUNCEky8BJ7Egg7nPHUSWBG5ky+y0csfdpXKabuh70SLRGIF+uYyk+cd7I+rMRNYH3TE4fF5NXFj
vSPOx6cfJ5Ga8iGzEZy1pl15fgISGeRv4GeWZeH8YdBclMZs53EcZqjkHjtz4EF+dBOkcTQHyspAGH+V7QALTkLH9YsJiEVylcKq
QHSC2nvtRFfEzoIU2yK5JvYicbJ/iJQO7NbJkQFj16AsS60vIwaI6jFW90AnWKSgKZDiaJUEX6iXI41ZKpqvLBIG+reQMv8C6rvo
JWoJ9PN5gng///jp4PB0VKZFoMSDoBOcgT8BB25uI5+54hmVSrCkqUASLopEU87IXqTh6DrPk2yn38cMiwAUp1f91AdCyPyMknuK
HC2YsnX1RyFkSLS2tjbLEwuUD2oLlRAqyX+rrd1yayyuZEPAo0bVCexUxG45k52htWZtFiPAis4bZzjcnk797Q1v+/XWhucMfGfg
rW1P153p+syB9NevZ+5rf2Owvem9GQwHa9PtzTdbkOS+3vQ3qpPbWbM2htX2N521rena2mxzY9Pbmr72Xk/XPW97bdsfDv2Nte3Z
2sZsY+a4G+vum/WN2XTwejjdcl57AywC3WnTVWvkHdIyrhBIuEH5S4yBtYKF0mN5CNkuK6fBdEGES2sKaO8uK2nQeoSdTCLUpoIb
X5LTy/sSeS9erPTReoKvoL0maZyDYsAY7aiEXuojkZbJsyPIAt4DKug6fHNjUJndvIfyKV7kYn0gejHJS+7WgiWX85jKjnFYzKoj
LQOAramWJbMVGsOsFG32ook70XNFDwAPqmPR1vgWtX7kKU6oFnnq3wSkkxk/np9/OgM99WuEctbcEZ1dUdFKqp3JNXzTPlmZgjPl
ZS67i6e/A7iI0Z0xgsXUD2OgBQA+ciHic37aRQtEyFbE58MDIASy+JHNTcG0j4CteWkMRixa9BbZzICPKO5lwEB7MAsw0Xu3s8pg
RG9fDaTXQ6pKemjOg2oObHY0LFmdpKQRLbqqyZbc5ddxtC405sMag0rwbWItyZ3sipHw5Mq0DMvaMFBpVvQSByw3GByrLFgPwSvV
iAKwT5jC/vujvQ9no07vZE305gAyoFyQWH7PyeN54AKZW1afu+8Dgc+Cq0Xq04ogXakYAll92V0GIwEUjxpDK+f9He21N8YdYWXM
7Ps5UHcPOAO6gnpf/TSNEft+RL+/+Cn0Pdq0hpvc/Qvxk+8nAmRRKjwnd1COIrHprGVXkOdo790h0MQiQdkm9U4Bmt4i9DPVVpVg
FQ9jv5f46HzxeY5kn4Ug8LEYrMIYmFIaeOS8QlRmVquG10GKRLskJM4z0oxWSoQSjVxYpqlf5OvadScYbkeNkpgI7fwBhN/Iw8Qg
msVgAQmeCKzqeTF5ti7f/VOsD9+sbe+I3i+JmN4lTgbCU3zY3xcewAPB7M8c0AkzgKrwrStLfJ4CNBeWaucT6Ix+Cmu7IIhOpioJ
I4rR2Ad9InBZYYlnzPqDPPPDmdkVpFiqxrjPXujf+KGYhc5VZonz6wA9GX5GnERqRpRHfgT2RDqIIe5iGTpgefBQ7npyRY5E77P9
/uT0/PD9r/bZyefT/XEN6E+p8LYGXuKmQDyi93vhikQ2uX/tu18Ea0Com93Np6ApAhFCJz6KQrCsrnaEg9RK5A9M2w9D4QCR+iUA
QJoBB4T28msnL52YBZoSiQ+PMQzISBZTgA0uCKuFqzAdKGlVHzjAG0bdA6OxUAWXMyWuLcW5OBifnaP6p5RCnKGvuEm1qFKg0bio
l2+zrwqF03VgTQAj8Im5RDW/UqUljQv1J89XrCxeKZ1EF+JZ0zeEbgYXLKyjanqlz/4kYofQ43BV9B0ApdwoNoRsjIv1FO9RRIFO
cJc9GyAjpzGwxa+AUVKskFednEkix/GdHi2f6RV22DJogmlSmo5lfmmISp8Wt1wWqFvxoO/mwGKALqe+5Yq//73z6fTk3RjsohdB
5IYLzxd/98KZG1nXb/U0SMnDWlqWe0FcT7vL+s7i9qYlGW28WvIiAlHgVRMnz904Bo0J2MONb4OKkN5Z16S7RTmAIIgM/AJGkdsF
9pKKlRX4flNY7osoC66AwQpjBdaBadyAsmKOvBCQZZyeHx3YB+P3e5+PzruT5+x4YEOQ+rHJ3WLuFma98QxSkLLgwzCfjT4e2OPj
89Nf7Z/Hp2eHJ8eUBSN5NlozC9NYrz73VMtJYJP33zAAyYBDHJdYMcG0Q3A5oQFt753b+ycnn8ane+eHP49Ns5gUWeDJIs+MyfPj
mPgIgAe5jrTxeUemR30pAQqscfK8C/AFAWjuquGty+FJRwxI4oWbI0PDP2roAOCZNwIsRAYC92J42T2x90/He+d/ntjj/94/go/T
g19O4WP/6GT83+P97mBrMNAhN/P+PkDw4M6RD78A3jGwg+4agHENM2bYJ2a8ynITE7LcynI7C/7wZQk3jDOsSrmLCHSlL2o4ZgHu
NdmnhM6nvbOzQjkg00owUICh0kKdAQOGjJnv3rmhT14+5enYJacGrQdYJ6DqoKJ2qCuNWeoWS6cXeiFaHfQbWfz4Z6AN+5e9w/Md
TqT+WCyQduGzwqOMltQn3VFyfOoAFerSpCl8dEpDq+ijtYUO2Tv8RyoubBFQKR5i7XcPIYHr6j/ZYx/MAtBoRM93QQnydpVcb0EM
Q4aItPM0bwcjGjW+3C49rzVfXNVryOKi6r4b4e9qK4Wfuu7vP6y4p4Vy1XiLFA1plucOo5WtU83dYwmyuFkPQBzDhL3H9gAemNN/
2+H3vCuea54OQIkLoOROAVku7QL3ej3h9KMkD/uVAgCV1dVVMW3P+sc/RG992N0Sq/D3jfjHP2hopHkjV+AR8JKTrCPJr3EHWKwk
HoD2/EfgEgf22fjoPZaCvoRghreA+lsbNrAZZruA6Oxi6xLq3DvDrnDW4P91+H8D/t+E/7cedqk2MhPblpXcxEYoGxGYqlo7XfGK
RwZ84QodCqo4Lzvfw6Zo0P0VcTgT+qxFwKoaWzFeFzJhwaLcRtMHvzNzDXm32wmzYq8KNRg5+9xP50EERg41CSNwiMFTfRg9t2R7
sc1di6/XuPoiRQS+C9YQUhQ7RgXQmRfiBrwQK33GysYbxMrmWve1wgpPGQBYdsCt22h6C+NV4vXecgq1Bx2AgQ+Qa4E34irHf8s9
OGcLGj779Wx/7+jI3t873h8fvbb3Tvd/hD8fXpsSvXVI72hgRiAqUJOKLAH61cl4rzVdJDJM4ezwA3dBQIY1ce0gWhSEMljXPX8G
XDvvyiapdQn9oIlSiU4JQFS+rgFSbGqTMmSnfujcoqLQAiecXW2VSd5VX2BgF/W9sIctlkurlojoG755vQkLapU+1yQOCz4ww7XT
G0qYvghmYCGIsx/3TscH+FuUilSxvVSwZlKfVrkdgDuGazATl6DMmHeB7k8WiM+KKZopZDx3BdhvERCkT9Z50RRSQGmnlWa1E4nT
T3vnP4okBhwi0YLqgLhQ203S/30Cdr3eWI6WIfUIVo6y8Xke2CwwQhif9BAoOVEEmliERdkYq32S8CJnjqbeHOgqdoWB6gNYrYYe
woGjNcWqwKKhH5m7RUvIWyrtjMTx56MjUxu37YU2apROaLO/wxgfn3wcf+xSc10qD39t0D2kDUAjkVKOjBtEEigaWr/AOt3krtJ3
V9SHDJy/z9qoVgtgXa2Ff7UyREiouNlgmuPuWLV0D1b+q9m0qyOm9o+knR92xIcjAyYfZeYF6NTepQVf2YzwHqt/tAfc/xSngZPo
ov3kY6fxIvLsGLCb2m7oZMCzZ8BL/Ro2YPzPcCXoKIAlHko0a5Mp67HDqyg+S32/Mm3q4oUPesusWHCwUH6RFC+deMRx8Ofp52MC
P7pj0jlT/1e06aNOTlagE90Ru+R1oHh0r5yEBKGkJlQsOKX3NrSx1YuDc1v2ctmkOQmGEYIBNw7/WnMmDfGeB8p8AdZfwFNkgYMM
soNbWIkwAuLWqY8lgDWYMCn0qcGyT31yXsiG4B+CheB9/PgLrn5g1/nXwPUlJKqMs84w3YyDRXqgWaV5yTOb6aSLrK+RMgIfhTYC
i5KNNnJ32FA+8pzUs2deJgySS4xsnPUzZqIsBAjE/i0Inojtr0KvCCKYgyHtSRPmxA5K374OPNAomdZqpV+RLYLmH/AWMEl0HWNf
6RBYNAC77w9AYDyTzC0Ge2LeRUQDKSkJVWP6Qmk+pKkGke3fJkilxoej0xNcl54/XVyBBpt9McUrcXAEhu27zx/sw4+fUGCfdcUA
aaAUUjLcKtNlVJkm9b510vs2FKQ/MDM6Pfx573yM2jGRaKvdLM0w8ULMFpFLrj1cLLR5Squ+5PVVJPpOGt4RSHfVcEkzVWwU0Ot+
qWmtjTwc/uZwmzQk+ChUJNRDCgwQ9KHiFwD5Lz6s9xsfNTUvZtkEw46BbHDo0P4d6BwYuEUiUfHfIAyncRoptcONF6DfT5WSA5Ml
ta7oh5YbrKKo1EJQ1aCskTgCteroZP8n+/D48Pxw7+jwn+NTJjQspPQqkLkR6niGVLcLjwLnmPeDh12lSUjpD9Ydyvo50O8tQD0D
DQC1VhH5MEKY8FQnS0/Nrj79qe86yO1IiZNqKSu8SML+TRAvMkEIELTtU0Ge52dual1XkFakIbLWNhFX8Feiquoqyu8SPyO9Rsu4
TnC/DxSOegZO0WbX0mqZ2uJFqlWLv5LrmiiilieNGliQ9RxQ62CEnp9QBml2W69xLsOtKt2xJxznHCSgwnRQDYu+oGMeIfjhSOAi
JvjZuE5M0J8UKuqZqUloLKmIZ0wfTDHtxCEqRFQlEyLgwwPRQ5oF3TiQROKA3Z7xgpBUXs5BGMBp1SBJXChvuAtMCGfRIV+/kohE
DwytjGnAfh+n2mJuzyNetEFsf6MEKXLDJCC5OFCRb6W9XjdGcb+iYY4qPQry/toCE60spbHeoIecNGOpzvLOmAQ0qBksS6c+6B/o
/8+VPwHLzhAIxJ+kkCUhRyuP9M+sWJiozVRFraRzF4UtDPMDbbawa1sFl5TOLFAdfdwyYo0Oc2K1uduRJgP0uXd6zrr3C1gLAdgM
Uks93ftF2YZn6L9oLJ1PNVdv+3Is8wEnTfeyWn96Yqo4wIu6UVTxZWCJSWSfoUXu2rhRluZGPJsBuONZA9dOEnRBPs9AHppIYcOt
LqjfWGs+BV5IOYJrs0r+XQ0X1jnGrVP7axuV9imj0v4kYq9JS3tipVBE2LXZoq1kNDpy2UhDGBIL13irAGdPubhX7tC6r5vCMWHi
dtmdbRgRGIG4iW2aQvaJvqJJxCRv47QN8h6h36HmCELHfQZLmVax7PXw+Hx8erx3VDgejvfPbPxCLh/yGQ0u5Zeh+rKmvqyrLxvq
yybpZTRyULAU9X48OYBepFOjgBaPXKcim6fxtBk8iQWxc32ZL8J4xbyp6Yxg/nd2ePzhaGzLJj+hKfBMunwkmkGHJXe5Sr0NkBFh
qlkJ4NPxoyDL/cgCrT6l9vGRU6kav938599AnTLdJhEp7XVyR5rUFHOlxWuxfApDEkYAe96kkSUTSNBKUxbyW2NXrCS7YnU1MbUt
HbTC54mxkuAKlvSk7dqMBmjqa10NyvbG4QzIBvd7iHYWtyh25EaQkaAVYe4KSO69dWxUgbBv+Kn1rmUiG2nuGSk0aJ7sRxgJ/imH
IBtfRJaDe1W72sEI6LplKwu+wVRr3AgIOwm0uhyVr34/KFJ+Vq1Whxit2Mq6DAD7X/zHl2K3nJ8k8Jki9S5bfMYK067cGPzetYsD
VwOFVWY8fQ2Djcbs5vzXT2P73eH5x72zn1oXZW09NtQSNC3pz0jcW9FiPkXfAIHEkorGqJizJX2lI8kQSJURc3/uJncGNmIx2Pgv
O8/KdJNH4EMnZf/xIicvovoclVkSRVXMdl+16Ftd8Qp7KTlb0dqoFDyfj386PvnlGClMGcEYBWxU+FRbxYPx/tHhMVj9PzRAKnYI
dlaxkUGERkT1CF+RrPC7JJkEhuq5q7Ncdhs+QTLRVvfycfF2yLfWBGWvyA0SOcg6JZc71aTrABnXsEjtFxDm8R0Bzzk5LvdiB08Q
cNqSapdzK8W2xpNFGy+iH0Sb6C4wz4V2mnhpqdUFkpO8wEYvg+QZOt0Nq7KpTREH5XBundGJTN26VbbjJAIdfYzbIOg4wPNhR3gS
CTq4AhsCT4Q5M/iQuyghxg2RLYBGPFod0oVO+MIAEzb+Zyl6SsmbnnFsHYoeiVRqJ1OaP2a4GK/UT3Hf/Ypnxuo+oVnbeFPKAEzJ
VJEDibhde9MVt+uDrrjIQB6+6G1tXD6TsS6zwHa838Ewst2ZY7NuK4ytDbPMB6IoMqipwbJM7GJbZs7jG+44S7SRQIHboRrHcOtS
HySOUWWtr+lZoIbfbqqsje1LrQdscJt/O55Hjcu25T50KOrQkeeLvBpgQKF5sbWhzyzL0W7GOZttyes6HFqA2CugCChDXB0sxVSN
LmWmxeeE2eNo23tnZ+OP747Gp7aNgQzAGw7P7MNjYVDgPSaJqvV3cKL08yICz/FSmPabbk0d2C0KhF5K+Rf4ZyeMh2s71aKXZVl3
+geVffNmOKu28HU4kE28WNvQa8yh922kgUGZOLWus5Y2ilEgnVSyplr7t9taXg4DoqwXg/qoWtcBNPxMG1w7GodbZrVMy3p4pACv
CW22TYJEItAn2EKYw616FxpxLstarw+sjUgr05sC1NYk1AB+OyK7ccVA/V7bQSLjfZzHiI0qUVHmui9UlRrJ4rbJM27Fa/NYUC/f
cE3IfYJ/ywyXbZAAruNGkNhuymzzkYZQtDZiIdqbUWK/tbkGjPdOP5zZAzz/NnhYlj00nAEUMFQfpsCEpcXXIBdDDZpVuqKSMFze
xrpsA8MVntBOLWFtecMbWsMYB/FXGq8lrC/vbbPWG0Zd/Ed6rCVsLB/CVssQMPDjf2YYtYTN6rgaPh5YmobczZZamWVZpuQdxr1c
P2pHF60dKg7dqESpzpfx4BWLVWk/DZ22bFPTbU9ODw6P905/NU09vPy+vsLsRhyTDu8XL6LUYCOuEqReGzEH79T4gj4qvRdo6qFs
jAKzG63JMfwEAB5XAFxttjQxywbrsHww25jyU5G3dCC1wmaFndeU6eb5HNJbnlHEIYYa+tGNOt2DgYT476GqU5zPlx5wFXwEJmRC
2jWGbUuFuggIFddx/CWzuCmwv+Z0BBIGSmfmJxHFzmBAB7QpZO4njO9QRVNVSB4a0zzuqvxhmTRGl35XHso61A9WTiIMtQKMdtQm
ySIKbnHH5KZPNxaoOxj6nUn0/vBofIbLguqsqjrWdacrtCRS/c60NNzixzDQju6+6+DOcJnDv9VOMf7Wd/OK37Ut2WqLbfs8WLO+
54/XUeC/qJZSqJBN6DDy1PfNHamKwXcw36/8W6M+0rTzW5qHHrS2mE59+JQB+iMkcqTzTtNNGTrzqeeIOQYp7PDHxeASgSPqni3Z
iGgu2aU5qIAVnZuNCTTxgHMAWvwXXtoxmbyEv9kCT2ZNJmZ3HmQufH7vPBj4dhpjiKGfiVUVRiPDxfUfPRgvH5OuNd/h02s9vbDl
Ylu9mX/r+gnv+PdmTnYXuVAoihdZbxF9DSKvR5EmmQSBwm/oXznuna1b3xU8vxAneCSxuFmF2hB689WYPyfFCCOKdysi0RTNqxZP
6VoOPowz9zGaN0AFGc1pJDTgcW5IMOJ9/KbDDrdJQbstGvyZg6ymMVjvBWNRx7zjGcYQ4fEz2tuDqiBC6Aw1h+A56mYO2Rza4xTn
BEM0OtXIS1wtDdYrsxTEKAwetD3UFEdISGrPriOD3+Aj7RBhWeo/8+I3wAteChMZP+wUP4hgzRX5WyMHxBwxTYNITO9ail1FehZt
ahkdCiHhkYKh+evxvjDMjolRXkPcYHys+On4bHwujMxVexBx6KHrW9XfaW46pE4AYrHOYY3OIvoSxV8jSXVVypki4TjpnX4ZjuaV
VSMsM3UWVOfOiu1KRHQZWhrd09Fm3y1YRJW7Xfsc6yUanHwi49+xDbVxaEuaayJjGnt3XbmvCLTgW8BGIiPtGD/Mzd+MC2Av+eWK
CfYUf10F5A/+HNwOTJn1svOtHR2kpGHDRIOZK3iZlf0DHkoL1pZgbNa5Z1g87AgOfQIxjUGraAPCAoEuqT+zcWNFpxkuW7g93lJI
/SqBRwFUwyb3SEz4hQQELyEJJdkpXqj0lGXTBGEdcWbJmZgq2GWn/M1rZifD6JqinsQrxQXQSUN04enb3iWNKAn0/y+JlCpNO4ko
6UzCqoVQlhBBm8IEBEHGwWSSraBMlv4+YJ+QMpmcXa788Nuns/FnmOX4+KBRqgVSNfSYj9Gi0UqMZqsq/sMIem7rUEdGUyvvmE9Z
DAvkYLL7eu+PUEVVN3nK+tQIRPHNwhYwWLPuqvhqG9Xx0TFGre4UO6V6njrhgUVI68cfQO+zRRhSR0D0jZuILvZ6/3R6fwx6b2yr
d7mKiZ1ql/paWkahgbzyTzv4RCHhRWC7gjsdTUcNfoV0eaVVV4/ndDCK3WC1tzhe0OmajQmTbWiYGk7RNKwbGQUgqfPCu+6x/jCN
49BAruDTzj9QgU3GTIqh8NXYAEnvAB8iH9Rks4vWCVx2EfAfzXJLG3HBfe5UBeyjIzZWaMxdsUT+lhurrcK2PElWsTCUCE6xc7Tq
DNvGydi2iRuGcXjjGyZetwEcpUAbyHdE3AVV64uOFvTcuSym2ZiirGnh6o88o1K75USXohPErNbKUiVaW82O5yEh0orrt4ZKAeJm
nVqAV2UjUtwD5g2eg/mg2TI1wquhsLXr6tGVtq71ExD3evMPYJKXfX8TipUTO52lIGlx/8KoqC2Ja2wyS93WkkgZtEt4mxcLjnbc
pA3Slbc9kVJvdCpxeqjUVw2qjvktmVppgncY6830OPXJTRXcV2uoTDPNNqxKIclzk9ACMKlZt0FF8gYwua5p+SLiNP5OR7tVX+Rt
QTVYeV6svfRqgdE5nyjHUEGpeD+mbXuxC2tUr4qDRKcZ1QFNgfgGMigwH0a4tB8rXT36CrXwOtxR55M6leQnYXyHRZfzc3RtwfBl
8/RBPjzDLI5YS2lGHjPF1+hHRcgwgALcpkMTzrYx0qFj2wgu2+7sqIsIEXitnjN5Lc5fcZzRdRH/a/1mKLYKJ1nhj4GfZExVXGbd
iguG1roSdX0VBwCDoCVS8WtBQYBkXx5lIC8WYUaubchO0tj1s6z0etXrc/NFN8yZy/p08UIfT3RV3WOPm5E1dbareQOk+lYe7YT/
xiC9b0tnwBNUuG/d1tDqQ+L9J/G9O2u7j7ZW2RNT0TC8+/WUv2LFxPZbu1itGyoZhmyP0ANkmLo9vtTGctIgv6Oz7Dln4t0FuvjC
aA2K9RjJvtYurSwJA+BCXV3Q4donNaOmt6LqRfFxk2zVkDqrfTmZfF0xMQsdESbJo4RuMSz6u6xYXjxMNJl8ul8X9IqI/PQZOVo4
e5UdNvKIo8x+sjGPZAim/CIqLLUiwvSe2n8QdMwyxzuJtInjiEjiUKE2iCQA03KKlFydHU4GUcYjphlp84OKnerWR6do53tnh1cL
hYFLsf+Kb5Ywr+CTYvawj4pnSckgnBhyAOv3OJAjvRjuoDv3ojPoXIoVYWyJHiPGbFq2hu7/JerOK3toKvqtjehBH4Pibftnje2z
+yh9aNs4w+331oYr65Rr3xdThh+vqgMsI8tqA++YS+x2YnQcNoorgmPT8ZtaIwXR4ZXYW5emNF2Mi9/MS1wyMuG+hQXKRS5dJqPX
pQpMq+YZ84UUb4gwXptPsA5LugFuKs/P18WtmDnzILzrPGII6zz/UaOJRN5TDKPvsYBKfboiNf/zSnW1Iyk1C/FO5EFSszACUHsp
NO1vKaR6pdJg+H+rm/4lHfKvKozlxMujukonUse1yt90RGur+1qs0l86onV08u6/UKN6aZABh792rHhkhTGO98P4GLWyePp7Xxle
0yDPcN9QnvZr5hVGiKxvHx6fyzYqxKa2UaBc7/Djpx9pEABkvloLvkNpIHez3xWVenSBlVTsxCNKXzWPL/xrz0LTH9G3+j3DaFkB
/7fGicfajg5oa0+Myu/23ufzE0yQR/iWq7nFSb7HitApSTrQB3+3i6svZHg/xeV7i/n8bihPIoDKco8HBb76zhfbCQMnMzgfowvx
jIedZYk8b70q1cDmeW66C4IiquT5PeVm2Pv83/Y+UNL6NqUTLdPR4Y1Bt7yYY5LLvnJgjngKY1dPhAEY2rmJiz0MMDs+OPkoz4Hn
1aHgmQ81DBaustLnw4PL0Uj+GOMvFJ7y94dKJv6S17RgeJtMPhvvfz4dXypJuavjTLcddERV0yV2tgk7W3L++UMxWLoMTN0yY9Pd
Em5iIB/gSA663ZHvecAp9nh+M+/taEDXF/Dtj69EcVcYnUvHaZTCGGwRm0YFzXkgqWBa5+8P4MtBUamAXuOAEiTgLWFY4EGf/pJV
okNiaRE6o0xHlIsTypJ67E8yhB2W+JH9oySt+vHH2mnkpZfa6Qef6ZaR+nljP02juHnieQ78sTiBvMkH398U1JvfxOjbC+nAp/gS
hHTIGfRkpmE+94QXDIEaYk8Xs11ZCcmZmQ2Wz5iSv+Ns8STvr4DaALY63tLMR8XjLODYAL7+ABShWeCHXibwSACCQ+QxH4hd4bsp
Ik/dlMA9L/hWCrYanZBvtZF4o3sy9cPGTYtbR3cjq8KZJPTuizX6DCjLlL8neXEgQMjTQeUZAUww5MKf5H/tfHFRMQ88/U4nWhug
WdqQboM0ATUM77uybdk3nQVHdJnVZvhUMmVboMCrk2jtBdB7ikYLFyphucQ5ocN0aRHiq3SKu3HIf/K8tt6eV3NLwf+cr+1os/W1
wy/db/+RYkA2JCNyebCG2dWPOyboVW2kuYbiQLW6cqIDUoaGhXiju1KQ/WX5aKRYhoxrODg823t3NMbDLFE6GiGC6a5DeWlLk8XR
aZVFV9x0xdeuuO0KML7+kOMBTppW7wDjCVSOoXG8XVsLq5LU62CF8ovuTfdr97Z71/2j+yrFwRF5/zu9yYUFk+6NQZk7RQhF6bMS
BJigNwW/C2jq6fISarS62oFbgJJGq5C1W9N4ayfm9/mCXuQveOMYOUB5tx3vblDHdN4BOwvodHzl7HxxUv4xKn/KRadaCT5CVUvG
k/EwA3mISFL0d3jT/sdOh1cXV41CCpHEYuYJSxaxVdXuyrNYPJ7d2ilR8djh7cfO7LUde5aEXefyBZFXDj2r483qdLM63KzONquj
zfVD6d9gbDhuPpzIH1P+cPnD4w+fP2bdtoN+QlTl1qhFahVnm7UDgfpio6C7eqJcgVU3yVNOEsKUnnSO8JGjryN18HUEjdFR1dG9
05123a7X9buzBw0x8kzsqO2UnzwdO9IJ60G9bPXYodfRXznyqp14rZx5HY2aJ14d202d7Np4vLg659oAnKSBkX7UtXZw8Yk3OYjm
RQ4E+G+uJj7DyG3cbgNxw2Ky8Za82+3Jc3PErey2lh7opfE4/UiurvbiQ734sCg+XFJ8TS++VhRfW1J8XS++XhRfX1J8Qy++URTf
WFJ8Uy++WRTfVMVlrlDME4rxGajnYgfEw2o6eW7cDkz6Qd+3za78Niy+rRXf1otvG8W3Ta499+cx3pgOya5bXoItieZ2UGNYj5jb
ZOsWlMB0Ii0OZhne6MrP/ejGaLs/oexaMqPRM0PVQ+VAfQdyGI06gw4f9VKJfA2b2oM36DaFG6Qc+rKK13RL4/uGGmheoPD0mxNG
mv1/U5Lbd96XMFp+W8KDxpmX3JYwGjwmSP6TUuSv82LFgTVO8tAidFC5UHyrdjtJeSGBxsUUeJ4u3hoi7a92yfesZfzUbRRHlXCa
Ht2LWmyXW9qbG3rQMfLYIpJnRTi8+xWqm3/pxR3ExO/zRCROlnMAOZ3utuigd7aA5m+CDOgcBhikxb16K/RkDzZBS5pvZ8uug0S9
XuH5IT7cQVe3qm7xYje+wjiEocWJpa4a+18mCDWJ9whKl0vJ6it3vLgKi6EZmiADKzjsYV8GRci7tvLUibLiClF8/yQM6WGIKd4k
Lfxbx83xJSvckxCLKJgFvscBTfUwijh7YgCF/JpdL0BYlD8XU+n4KJJyf56wJ5+umsL7WJv7U6d8wwD9KDc/sJWyUmO3aafcFZeu
UpsWXldUow139C3ecGYVj7bQrpPcyyj3nGqlixMeI/YU63noiMxqGfrRCuq/trNLUZOjykj6VKFxvIHC1oIMzIQ5PUhgqj1xyij3
yKCIcnDZeWxoLVdrQDlEhGE+/TDDrHOPQ9MD4x1FdPS8AVqp8uo53OOqn2uoQPACm7qkbSYaf7FJ1lKHIFutQI84mPhwA2aKV2IQ
v379uoYRCghV4FUdW26c3FXDKFKfnlmU9MLeZeZZXb4Lo0E1vPPLJVPf8sF0S3yD65hdFbVi78jq1c6wqt5VcWRDjmNOF9Xwbu9Q
7xrAjl44ZOMUOC/f9TG0BqyPn4/OD5EpaYCEBb8gmsXwA/S7GWVLuBHpBVDdKEHGoDbNapi8bOXZiIf25BiFOs3cU/UH/U5AdRQm
8PF6ZjpPdc/dPXTMNqQWxKBNBNiNUYFgY0KVoyyeV0ECMcQor51p+tbixEBiubw1isOYECRSvg2Fl2pj/X4v/HRw0WpzQlw1d/LO
lV26InoGwLhWjyl2qvj7Pmbx7wyPY8FpTfC9z4Vk8v1v4FOioY21FmUG8dbGho5LuZfO6CxCPHcas2f5ZNF9mEZH7rY/8czHh+PP
LCRxTyD1/7UI8GS3fEvK1aevz/CF+Bk1cAxupJuZa6IZtxTomh0VhcE9xLNZj4IEyobIAaikp3Xuozh10rsDFf9pyNf1Ku9Ad0CP
ycoY0dpM6RkoT0m+olSNASsJVqyQKq1bwDrmWasUkfHHI9VRm2Ary8noDIte7TL4RzY6TxfQM1G4HX+hn+bSFujJH5YiajU35yJx
GKkQ7paBAzbmiJmRuJBE0hWdXm9afoWGvjqpJ38s/vhjNPjGoaQOPVY5ddwvi6QXzHrzIJsX7SVD+gjgL5g7BuGDOtYUEfOyJbAJ
5sO7nBjkfQF9eOldL11EeN7h4rINKUJ/v6NU0CyoZFysyJnDIqJmoRX3qzdi/HUFQpYx8q1LF2tHjnIPVOeR1tunw09jnCs+EaWn
n50fnHw+/87mwaIf3a+sxJklL1MEWB7t23jia0d09jsPZnt79GAxQsJitdsFJrOzvOulHJDWP5MVP63ke7s6xyufWt6ZgFkr+2Sg
PNR1pEJU3ydWhTUTDkzLyWzc2bw1tOhKzrPSqzCeGp2VDvkaklLDe2gok6Uox9CxcjV/hzKoT1s9TySl3yKnTQy+hr6UCurRo+Zx
V0mOJEp2hFHhF5UAqoo+XQ77QWe4pYXsBRnAirZr+D1tKRd5Z4WHpz+zRG9nH57ojc2cIMR9YHlRsvZklpIBwMQrUlfI56rLQ5FL
uaikhHYOSuF9utp6JSNJ6R5f2Uor88LHURY1Plvy4m9YGv8eM86VXIKejunFw0puQwQ1JRu9h16It/dIvyj8R52vwBzxMdjKALvo
UwC5OXpPT3qgtAPqSxb5knWsj4+4LJe2CK7tVWQJfk6uXaxUWrbcaxiwUVdbHq2i7A+eW11oBXQvfsuM8O2MYkLaWcNvTd6Sb9qB
DMJnVTVcosdhSWykvLiNwhI/HuiuS+kL+bG8q3tpfuUJxygvryNUR1zQpVncVtCFReL5GCLg0y3V/L4Bsh2Kvjgv7ydM6X6FDC9h
oAsJCzP97Od9WuToQ6S7x3kE/OQV3kDIbqiedLzwswKZD6wqD9ysegN5w2crBrcb3sbGYDAYfj6qlKs+1rg1idqdWffNq0P1uy5P
Pn46Gp9X0qR/SkrIsuiP4/2f5KaWVloet8XTFlrqscTK+/fj/XPxQPuybREibRkAbkjGwEmkg/ZZGStFUpb7iT2LzCUxKGKl2+re
pZAJ1Qm5hbU2iwt2TQ7BaNxjtmTcxUOdqqS8QKl8e5JSK/44SFxfg8TKrtFCpao3dHcL7+xJws9YSLqkd8k9IkLJluUDfXtMxotM
2Uco0jLgMMQNC38q35OiNkdBhKj9hq56wJcv+y/om33AGL0dhPiRxCCu7qyiwUMctOvDspZ3dFbez5I70OqaTgcSIiiAW3JoXYTB
1XVe+meX3nhcgmNfhwId3aLx0TNcNFN8/tEpbhTdl5eIyqcq+Eafor+2a5TLrs6A0iSv7hannuWb3fKNanzI+yuzjeKpb+cOlOAs
odgvejdMucVzdpXiO2RBrtiMFOvimOBDXJtcqs7UoQd+vRqaG6CS60HgvXq7lWnxG3Om2trRM2WeLV22GhUmeWrnlT55ww/XNMDk
fXArr16F0eIViqBWlboP2aLolO1kvCkgYDYAQUv8009jAAdoCImvHhoktkrvENLdsPhaxK6kE6A/9Oz00a9G0HApuo43FJBq6aVx
fKzJcdM4U+97ZHx37KlPoOkH0bWPMtaTFTN1KY7aPdCfKxWSD+I4pgHF9CEuGOJLeM19HW5x4vxr4fOOKkKMuNl981gJXtu+5Api
yFpr5aC4V3dfYxcyWpyvu95dQhn0nddhSdyH8zm/miUfwgnwAW+ymEQwB6TuSiuQDwBMC7FYfXUjzjXGcoWQxauZ2F3lLGAx4qEe
AG2EHkJ1Z68UrUgxQVqRqyV5Sw6s4nh4z5UftaizzMqLFF2dgz7o8UGEd3p3ubmZ+fjmaLGPKiU6pmNgcxL03koEjJrPKasSiJm3
I3kdOTVXqlKqjIahIo0nS1vC9Fuf16PTUqEqj0+qqwdAFHDGR8SXTNcoClE8E9f8O09RxwCV1WZwwSUvX1HbPPpqeBoJrn55NXSX
9Xe8/Yov3RJzIBjPyR0LbEY8QwJTX4RAEQ4t98peZEyMxIWGZV1mKMQl+MVHXqN1CaHWuQ7Wdl2kvk34DThrbsclCovcSmxXW2h/
UWHk8f3LOikZsmF9i5JDCXYroQGtooR2EntvNalCUwDM4HOssstqhIGT+e3qY9MMNZ5x8zIwEkOtsCezEZInmfJutQW9smHu1t5l
qA9FU1mXj4T1jO8bgLbnqhowJNhkYBH90PdpKz23T7nQ0WtVHp9kRQNfPk2W+38R4FzZ0H8oDaIFCaBoOwCendrrBloJzceiaDgi
T2uTbh+Ib3zztDX8aNiZu9plnA//B5RTDGw=
''')))
for name, content in sources.items():
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
LIBC_INTEGRATION
}
# END GENERATED LIBC INTEGRATION

libc_setup() {
    printf 'abi=%s\n' "$(libc_entry_abi)"
    cat <<'LIBC_SETUP'
set -eu
mode=$1
jobs=$2
recipe=$3
case "$mode" in shroot|base|identify) ;; *) echo 'Invalid libc mode' >&2; exit 1 ;; esac
case "$recipe" in ''|*[!a-f0-9]*) exit 1 ;; esac
[ "${#recipe}" = 64 ] || exit 1
if [ "$mode" = base ]; then
    mkdir -p /etc/shroot
    : > /etc/shroot/libc-base
    echo 'Shroot Base selected for new launches; shared builds retained.'
    exit 0
fi
LIBC_SETUP
    distribution_support libc
    cat <<'LIBC_SETUP'
install_libc_tools() {
    refresh_packages
    case "$family" in
        apk) packages ca-certificates build-base python3 curl linux-headers patch tar ;;
        apt) packages ca-certificates build-essential python3 curl gawk bison texinfo linux-libc-dev patch xz-utils ;;
        dnf) packages ca-certificates gcc gcc-c++ make python3 curl gawk bison texinfo kernel-headers glibc-devel patch tar xz ;;
        zypper) packages ca-certificates gcc gcc-c++ make python3 curl gawk bison texinfo linux-glibc-devel glibc-devel patch tar xz ;;
        pacman|recovery) packages ca-certificates base-devel python curl linux-api-headers ;;
        xbps) packages ca-certificates base-devel python3 curl linux-headers patch ;;
        *)
            for tool in cc make python3 curl patch tar; do
                command -v "$tool" >/dev/null 2>&1 || {
                    echo "Missing $tool: install build tools in this image first." >&2; exit 1;
                }
            done ;;
    esac
}
extract_integration() {
    python3 - "$work/integration" <<'LIBC_PAYLOAD'
LIBC_SETUP
    libc_integration
    cat <<'LIBC_SETUP'
LIBC_PAYLOAD
}
LIBC_SETUP
    libc_build
}

# Package-manager differences stay here; setup and the Mesa recipe share them.
distribution_support() {
    cat <<'DISTRO'
set -eu
umask 022
[ ! -r /etc/os-release ] || . /etc/os-release
ID=${ID:-unknown}
case "$ID" in
    debian|ubuntu|openkylin|deepin) family=apt ;;
    alpine) family=apk ;;
    fedora) family=dnf ;;
    arch|archarm|manjaro-arm|manjaro|artix) family=pacman ;;
    opensuse-tumbleweed) family=zypper ;;
    void) family=xbps ;;
    steamos) family=recovery ;;
DISTRO
    if [ "${1:-}" = libc ]; then
        cat <<'DISTRO'
    *)
        family=unknown
        for pair in 'apt-get:apt' 'apk:apk' 'dnf:dnf' 'zypper:zypper' 'xbps-install:xbps' 'pacman:pacman'; do
            if command -v "${pair%:*}" >/dev/null 2>&1; then family=${pair#*:}; break; fi
        done ;;
DISTRO
    else
        printf '%s\n' '    *) echo "Unsupported distribution: $ID" >&2; exit 1 ;;'
    fi
    cat <<'DISTRO'
esac
packages() {
    case "$family" in
        apt) apt-get install -y --no-install-recommends "$@" </dev/null ;;
        apk) apk add "$@" </dev/null ;;
        dnf) dnf -y --setopt=install_weak_deps=False install "$@" </dev/null ;;
        zypper) zypper --non-interactive install --no-recommends "$@" </dev/null ;;
        xbps) xbps-install -y "$@" </dev/null ;;
        pacman|recovery) pacman -S --needed --noconfirm "$@" </dev/null ;;
        *) echo 'Package setup is unavailable for this image.' >&2; exit 1 ;;
    esac
}
refresh_packages() {
    case "$family" in
        apt) apt-get update </dev/null ;;
        apk) apk update </dev/null ;;
        zypper) zypper --non-interactive refresh </dev/null ;;
        xbps)
            # XBPS must upgrade itself before the rest of a rolling rootfs.
            xbps-install -Suy xbps </dev/null
            xbps-install -uy </dev/null ;;
        pacman)
            case "$ID" in
                manjaro|manjaro-arm) keyrings='archlinuxarm manjaro manjaro-arm' ;;
                artix) keyrings=artix ;;
                arch|archarm) keyrings=archlinuxarm ;;
                *) keyrings= ;;
            esac
            if [ -n "$keyrings" ]; then
                pacman-key --init </dev/null
                pacman-key --populate $keyrings </dev/null
            fi
            # Rolling repositories require a complete userspace upgrade.
            pacman -Syu --noconfirm </dev/null ;;
        recovery)
            # Retain the image repository branch, keyring and signature policy.
            printf 'Updating SteamOS packages from the image repositories...\n'
            printf 'Kernel/service hooks may warn about the non-booted environment. Android is not updated.\n'
            pacman -Syu --noconfirm </dev/null ;;
    esac
}
package_cleanup() {
    # pacman-key's service is scoped to the package keyring, not a user's GPG home.
    if { [ "$family" = pacman ] || [ "$family" = recovery ]; } && command -v gpgconf >/dev/null 2>&1; then
        gpgconf --homedir /etc/pacman.d/gnupg --kill all || {
            echo 'Could not stop the package-keyring GPG services.' >&2
        }
    fi
}
DISTRO
}

mesa_patch() {
    cat <<'PATCH'
Mesa 26.2.3: explicitly selected Zink uses Kopper without a DRM render node.
Non-DRM EGL devices follow the actual Gallium renderer's acceleration and UUID,
including surfaceless contexts. Software drivers remain software devices.
KGSL calibrated timestamps use the kernel timestamp ioctl when available;
unsupported kernels do not advertise that extension. Queue queries are unchanged.
GLX loader capabilities follow the effective backend when Kopper is disabled.
Zink retains GPU rendering with sw_winsys readback presentation when the client
disables Kopper or the X server lacks DRI3. Direct Vulkan presentation is unchanged.
Readback requires a presenting winsys; Kopper's loader-less DRI winsys does not
advertise that callback, so offscreen flushes retain their original no-op behavior.

--- a/src/glx/drisw_glx.c
+++ b/src/glx/drisw_glx.c
@@ -634,6 +634,12 @@

    /* this is only relevant if zink bits are set */
    glx_driver &= (GLX_DRIVER_ZINK_INFER | GLX_DRIVER_ZINK_YES);
+   /* Without DRI3, use the frontend's readback presentation, not Vulkan WSI. */
+   if (glx_driver && !kopper_disable) {
+      int opcode, event, error;
+      kopper_disable = !XQueryExtension(priv->dpy, "DRI3", &opcode, &event, &error);
+   }
+
    const char *driver = glx_driver && !kopper_disable ? "zink" : "swrast";

    psc = calloc(1, sizeof *psc);
@@ -642,7 +648,7 @@
    psc->kopper = !strcmp(driver, "zink");
    psc->base.driverName = strdup(driver);

-   if (glx_driver)
+   if (psc->kopper)
       loader_extensions_local = kopper_extensions_noshm;
 #ifdef HAVE_SYS_SHM_H
    else if (!x11_xcb_display_supports_xshm(XGetXCBConnection(priv->dpy), &xshm_opcode))
@@ -650,7 +656,7 @@
 #endif
    else
       loader_extensions_local = loader_extensions_shm;
-   priv->driver = glx_driver ? GLX_DRIVER_ZINK_YES : GLX_DRIVER_SW;
+   priv->driver = psc->kopper ? GLX_DRIVER_ZINK_YES : GLX_DRIVER_SW;

    if (!dri_screen_init(&psc->base, priv, screen, -1, loader_extensions_local, driver_name_is_inferred)) {
       if (!glx_driver || !driver_name_is_inferred)
@@ -664,7 +670,7 @@
    psp->createDrawable = driswCreateDrawable;
    psp->swapBuffers = driswSwapBuffers;

-   if (!glx_driver)
+   if (!psc->kopper)
       psp->copySubBuffer = drisw_copy_sub_buffer;

    if (psc->kopper) {
--- a/src/egl/drivers/dri2/platform_wayland.c
+++ b/src/egl/drivers/dri2/platform_wayland.c
@@ -3297,7 +3297,7 @@ dri2_initialize_wayland_swrast(_EGLDisplay *disp)
 EGLBoolean
 dri2_initialize_wayland(_EGLDisplay *disp)
 {
-   if (disp->Options.ForceSoftware)
+   if (disp->Options.ForceSoftware || disp->Options.Zink)
       return dri2_initialize_wayland_swrast(disp);
    else
       return dri2_initialize_wayland_drm(disp);
--- a/src/egl/main/egldevice.h
+++ b/src/egl/main/egldevice.h
@@ -60,6 +60,9 @@
 _EGLDevice *
 _eglFindDevice(int fd, bool software);

+_EGLDevice *
+_eglFindNonDrmDevice(const unsigned char uuid[16]);
+
 enum _egl_device_extension {
    _EGL_DEVICE_SOFTWARE,
    _EGL_DEVICE_DRM,
--- a/src/egl/main/egldevice.c
+++ b/src/egl/main/egldevice.c
@@ -78,8 +78,8 @@
       dev_list = dev_list->Next;

 #ifdef HAVE_LIBDRM
-      assert(_eglDeviceSupports(dev, _EGL_DEVICE_DRM));
-      drmFreeDevice(&dev->device);
+      if (dev->device)
+         drmFreeDevice(&dev->device);
 #endif
       free(dev->device_info.vendor_name);
       free(dev->device_info.renderer_name);
@@ -113,6 +113,32 @@
    .EXT_device_drm_render_node = EGL_TRUE,
 };

+/* A render-capable driver can have a physical device without a DRM node.
+ * Retain its real UUID for identity; do not advertise unavailable DRM APIs.
+ */
+_EGLDevice *
+_eglFindNonDrmDevice(const unsigned char uuid[16])
+{
+   simple_mtx_lock(_eglGlobal.Mutex);
+   _EGLDevice *dev = _eglGlobal.DeviceList;
+   while (dev->Next) {
+      dev = dev->Next;
+      if (!dev->MESA_device_software && !dev->EXT_device_drm &&
+          !memcmp(dev->device_info.device_uuid, uuid, EGL_UUID_SIZE)) {
+         simple_mtx_unlock(_eglGlobal.Mutex);
+         return dev;
+      }
+   }
+   dev->Next = calloc(1, sizeof(*dev));
+   dev = dev->Next;
+   if (dev) {
+      memcpy(dev->device_info.device_uuid, uuid, EGL_UUID_SIZE);
+      dev->extensions = "";
+   }
+   simple_mtx_unlock(_eglGlobal.Mutex);
+   return dev;
+}
+
 #ifdef HAVE_LIBDRM
 extern const _EGLDriver _eglDriver;
 /*
@@ -143,8 +169,8 @@
    while (dev->Next) {
       dev = dev->Next;

-      assert(_eglDeviceSupports(dev, _EGL_DEVICE_DRM));
-      if (drmDevicesEqual(device, dev->device) != 0)
+      if (_eglDeviceSupports(dev, _EGL_DEVICE_DRM) &&
+          drmDevicesEqual(device, dev->device) != 0)
          return 1;
    }

@@ -328,10 +354,8 @@
 {
 #ifdef HAVE_LIBDRM
    drmDevicePtr device = _eglDeviceDrm(dev);
-   /* Software device does not have render node. */
-   const char *render_node =
-      _eglDeviceSupports(dev, _EGL_DEVICE_SOFTWARE) ?
-      "" : device->nodes[DRM_NODE_RENDER];
+   /* Software and non-DRM devices do not have a render node. */
+   const char *render_node = device ? device->nodes[DRM_NODE_RENDER] : "";
 #endif

    switch (name) {
@@ -434,6 +458,11 @@
    assert(_eglDeviceSupports(dev, _EGL_DEVICE_SOFTWARE));
    count++;

+   for (_EGLDevice *other = dev->Next; other; other = other->Next) {
+      if (!_eglDeviceSupports(other, _EGL_DEVICE_DRM))
+         count++;
+   }
+
 #ifdef HAVE_LIBDRM
    drmDevicePtr devices[64];
    int num_devs, ret;
--- a/src/egl/drivers/dri2/egl_dri2.c
+++ b/src/egl/drivers/dri2/egl_dri2.c
@@ -47,6 +47,7 @@
 #include <sys/stat.h>
 #include <sys/types.h>
 #include "dri_screen.h"
+#include "pipe/p_screen.h"

 #ifdef HAVE_WAYLAND_PLATFORM
 #include "linux-dmabuf-unstable-v1-client-protocol.h"
@@ -831,6 +832,21 @@
    _EGLDevice *dev;
    int render_fd;

+   /* A Gallium screen can use a non-DRM device even with a swrast loader. */
+   if (dri2_dpy->fd_render_gpu < 0 && dri2_dpy->dri_screen_render_gpu) {
+      struct pipe_screen *screen = dri2_dpy->dri_screen_render_gpu->base.screen;
+      dev = NULL;
+      if (!screen->caps.accelerated) {
+         dev = _eglFindDevice(-1, true);
+      } else if (screen->get_device_uuid) {
+         unsigned char uuid[16];
+         screen->get_device_uuid(screen, (char *)uuid);
+         dev = _eglFindNonDrmDevice(uuid);
+      }
+      disp->Device = dev;
+      return dev != NULL;
+   }
+
    /* If we're not software, we need a DRM node FD */
    assert(software || dri2_dpy->fd_render_gpu >= 0);

--- a/src/egl/drivers/dri2/platform_surfaceless.c
+++ b/src/egl/drivers/dri2/platform_surfaceless.c
@@ -343,17 +343,10 @@
 surfaceless_probe_device_sw(_EGLDisplay *disp)
 {
    struct dri2_egl_display *dri2_dpy = dri2_egl_display(disp);
-   struct _egl_device *device = _eglFindDevice(dri2_dpy->fd_render_gpu, true);
+   _EGLDevice *requested_device = disp->Device;

    dri2_dpy->fd_render_gpu = -1;

-   if (_eglHasAttrib(disp, EGL_DEVICE_EXT) && disp->Device != device) {
-      return false;
-   }
-
-   disp->Device = device;
-   assert(disp->Device);
-
    dri2_dpy->driver_name = strdup(disp->Options.Zink ? "zink" : "swrast");
    if (!dri2_dpy->driver_name)
       return false;
@@ -374,6 +367,14 @@
       return false;
    }

+   if (!dri2_setup_device(disp, true))
+      return false;
+
+   if (_eglHasAttrib(disp, EGL_DEVICE_EXT) && disp->Device != requested_device) {
+      disp->Device = requested_device;
+      return false;
+   }
+
    return true;
 }

--- a/src/freedreno/vulkan/tu_knl.h
+++ b/src/freedreno/vulkan/tu_knl.h
@@ -128,6 +128,7 @@
    VkResult (*device_init)(struct tu_device *dev);
    void (*device_finish)(struct tu_device *dev);
    int (*device_get_gpu_timestamp)(struct tu_device *dev, uint64_t *ts);
+   bool (*can_query_gpu_timestamp)(const struct tu_physical_device *dev);
    int (*device_get_suspend_count)(struct tu_device *dev, uint64_t *suspend_count);
    VkResult (*device_check_status)(struct tu_device *dev);
    int (*submitqueue_new)(struct tu_device *dev, struct tu_queue *queue);
--- a/src/freedreno/vulkan/tu_device.cc
+++ b/src/freedreno/vulkan/tu_device.cc
@@ -39,6 +39,7 @@
 #include "tu_descriptor_set.h"
 #include "tu_dynamic_rendering.h"
 #include "tu_image.h"
+#include "tu_knl.h"
 #include "tu_pass.h"
 #include "tu_query_pool.h"
 #include "tu_queue.h"
@@ -192,6 +193,9 @@
                       struct vk_device_extension_table *ext)
 {
    bool has_gralloc = vk_android_get_ugralloc() != NULL;
+   bool has_calibrated_timestamps = device->info->props.has_persistent_counter &&
+      (!device->instance->knl->can_query_gpu_timestamp ||
+       device->instance->knl->can_query_gpu_timestamp(device));
    /* device->has_raytracing contains the value of the SW fuse. If the
     * device doesn't have a fuse (i.e. a740), we have to ignore it because
     * kgsl returns false. If it does have a fuse, enable raytracing if the
@@ -207,7 +211,7 @@
       .KHR_acceleration_structure = has_raytracing,
       .KHR_bind_memory2 = true,
       .KHR_buffer_device_address = true,
-      .KHR_calibrated_timestamps = device->info->props.has_persistent_counter,
+      .KHR_calibrated_timestamps = has_calibrated_timestamps,
       .KHR_compute_shader_derivatives = true,
       .KHR_copy_commands2 = true,
       // TODO workaround for https://github.com/KhronosGroup/VK-GL-CTS/issues/525
@@ -304,7 +308,7 @@
       .EXT_attachment_feedback_loop_dynamic_state = true,
       .EXT_attachment_feedback_loop_layout = true,
       .EXT_border_color_swizzle = true,
-      .EXT_calibrated_timestamps = device->info->props.has_persistent_counter,
+      .EXT_calibrated_timestamps = has_calibrated_timestamps,
       .EXT_color_write_enable = true,
       .EXT_conditional_rendering = true,
       .EXT_conservative_rasterization = device->info->chip >= 7,
--- a/src/freedreno/vulkan/tu_knl_kgsl.cc
+++ b/src/freedreno/vulkan/tu_knl_kgsl.cc
@@ -1703,10 +1703,28 @@
 }

 static int
+kgsl_read_gpu_timestamp(int fd, uint64_t *ts)
+{
+   uint32_t domain = KGSL_CALIBRATED_TIME_DOMAIN_DEVICE;
+   struct kgsl_read_calibrated_timestamps request = {
+      .sources = (uintptr_t)&domain,
+      .ts = (uintptr_t)ts,
+      .count = 1,
+   };
+   return safe_ioctl(fd, IOCTL_KGSL_READ_CALIBRATED_TIMESTAMPS, &request);
+}
+
+static bool
+kgsl_can_query_gpu_timestamp(const struct tu_physical_device *dev)
+{
+   uint64_t timestamp;
+   return kgsl_read_gpu_timestamp(dev->local_fd, &timestamp) == 0;
+}
+
+static int
 kgsl_device_get_gpu_timestamp(struct tu_device *dev, uint64_t *ts)
 {
-   UNREACHABLE("");
-   return 0;
+   return kgsl_read_gpu_timestamp(dev->fd, ts);
 }

 static int
@@ -1754,6 +1772,7 @@
       .device_init = kgsl_device_init,
       .device_finish = kgsl_device_finish,
       .device_get_gpu_timestamp = kgsl_device_get_gpu_timestamp,
+      .can_query_gpu_timestamp = kgsl_can_query_gpu_timestamp,
       .device_get_suspend_count = kgsl_device_get_suspend_count,
       .device_check_status = kgsl_device_check_status,
       .submitqueue_new = kgsl_submitqueue_new,
--- a/src/gallium/drivers/zink/zink_screen.c
+++ b/src/gallium/drivers/zink/zink_screen.c
@@ -34,6 +34,9 @@
 #include "zink_public.h"
 #include "zink_query.h"
 #include "zink_resource.h"
+#include "frontend/sw_winsys.h"
+#include "util/u_inlines.h"
+#include "util/u_surface.h"
 #include "zink_state.h"
 #include "nir_to_spirv/nir_to_spirv.h" // for SPIRV_VERSION

@@ -1892,6 +1895,45 @@
 }

 static void
+zink_present_readback(struct zink_screen *screen, struct pipe_context *pipe,
+                      struct pipe_resource *pres, unsigned level, unsigned layer,
+                      void *drawable, unsigned nboxes, struct pipe_box *boxes)
+{
+   struct sw_winsys *ws = screen->winsys;
+   struct zink_resource *res = zink_resource(pres);
+   if (!ws || !ws->displaytarget_display || !(pres->bind & PIPE_BIND_DISPLAY_TARGET))
+      return;
+
+   if (res->sw_dt && res->sw_level != level) {
+      ws->displaytarget_destroy(ws, res->sw_dt);
+      res->sw_dt = NULL;
+   }
+   unsigned width = u_minify(pres->width0, level);
+   unsigned height = u_minify(pres->height0, level);
+   if (!res->sw_dt) {
+      res->sw_dt = ws->displaytarget_create(ws, pres->bind, pres->format,
+                                           width, height, 64, NULL, &res->sw_stride);
+      res->sw_level = level;
+      if (!res->sw_dt)
+         return;
+   }
+   struct pipe_transfer *transfer = NULL;
+   void *pixels = pipe_texture_map(pipe, pres, level, layer, PIPE_MAP_READ,
+                                  0, 0, width, height, &transfer);
+   if (!pixels)
+      return;
+   void *output = ws->displaytarget_map(ws, res->sw_dt, PIPE_MAP_WRITE);
+   if (output) {
+      util_copy_rect(output, pres->format, res->sw_stride, 0, 0, width, height,
+                     pixels, transfer->stride, 0, 0);
+      ws->displaytarget_unmap(ws, res->sw_dt);
+   }
+   pipe_texture_unmap(pipe, transfer);
+   if (output)
+      ws->displaytarget_display(ws, res->sw_dt, drawable, nboxes, boxes);
+}
+
+static void
 zink_flush_frontbuffer(struct pipe_screen *pscreen,
                        struct pipe_context *pctx,
                        struct pipe_resource *pres,
@@ -1904,9 +1946,12 @@
    struct zink_resource *res = zink_resource(pres);
    struct zink_context *ctx = zink_context(pctx);

-   /* if the surface is no longer a swapchain, this is a no-op */
-   if (!zink_is_swapchain(res))
+   /* A non-Kopper frontend owns presentation; Vulkan still renders the image. */
+   if (!zink_is_swapchain(res)) {
+      zink_present_readback(screen, pctx, pres, level, layer,
+                            winsys_drawable_handle, nboxes, sub_box);
       return;
+   }

    ctx = zink_tc_context_unwrap(pctx);

@@ -3862,9 +3907,10 @@
    struct zink_screen *ret = zink_internal_create_screen(config, -1, -1, 0);
    if (ret) {
       ret->drm_fd = -1;
-   }
-
-   return &ret->base;
+      ret->winsys = winsys;
+   }
+
+   return ret ? &ret->base : NULL;
 }

 static inline int
--- a/src/gallium/drivers/zink/zink_types.h
+++ b/src/gallium/drivers/zink/zink_types.h
@@ -1268,6 +1268,9 @@
 struct zink_resource {
    struct threaded_resource base;

+   struct sw_displaytarget *sw_dt;
+   unsigned sw_stride, sw_level;
+
    enum pipe_format internal_format:16;

    struct zink_resource_object *obj;
@@ -1367,6 +1370,8 @@

 struct zink_screen {
    struct pipe_screen base;
+
+   struct sw_winsys *winsys;

    const char *vendor_name;
    const char *device_name;
--- a/src/gallium/drivers/zink/zink_resource.c
+++ b/src/gallium/drivers/zink/zink_resource.c
@@ -47,6 +47,7 @@
 #include "util/u_upload_mgr.h"
 #include "util/os_file.h"
 #include "frontend/winsys_handle.h"
+#include "frontend/sw_winsys.h"

 #if !defined(__APPLE__)
 #define ZINK_USE_DMABUF
@@ -254,6 +255,9 @@
    struct zink_resource *res = zink_resource(pres);
    /* prevent double-free when unrefing internal surfaces */
    res->base.b.reference.count = 999;
+
+   if (res->sw_dt)
+      screen->winsys->displaytarget_destroy(screen->winsys, res->sw_dt);

 #ifdef HAVE_LIBDRM
    if (res->ro_scanout)
--- a/src/gallium/winsys/sw/dri/dri_sw_winsys.c
+++ b/src/gallium/winsys/sw/dri/dri_sw_winsys.c
@@ -428,7 +428,8 @@
    ws->base.displaytarget_map = dri_sw_displaytarget_map;
    ws->base.displaytarget_unmap = dri_sw_displaytarget_unmap;

-   ws->base.displaytarget_display = dri_sw_displaytarget_display;
+   /* Kopper supplies no readback loader; its offscreen flushes cannot present. */
+   ws->base.displaytarget_display = lf ? dri_sw_displaytarget_display : NULL;

    return &ws->base;
 }
PATCH
}

kwin_patch() {
    case "${1:-6.3.6}" in 6.2.5|6.3.6) ;; *) return 1 ;; esac
    cat <<'PATCH'
KWin: nested DMA-BUF v3/EGL rendering without a DRM device.

--- a/src/backends/wayland/CMakeLists.txt
+++ b/src/backends/wayland/CMakeLists.txt
@@ -1,4 +1,5 @@
 target_sources(kwin PRIVATE
+    dmaheapgraphicsbufferallocator.cpp
     wayland_backend.cpp
     wayland_display.cpp
     wayland_egl_backend.cpp
--- a/src/backends/wayland/dmaheapgraphicsbufferallocator.cpp
+++ b/src/backends/wayland/dmaheapgraphicsbufferallocator.cpp
@@ -0,0 +1,78 @@
+/* SPDX-License-Identifier: GPL-2.0-or-later */
+#include "dmaheapgraphicsbufferallocator.h"
+#include "core/graphicsbuffer.h"
+#include "utils/drm_format_helper.h"
+
+#include <drm_fourcc.h>
+#include <fcntl.h>
+#include <limits>
+#include <linux/dma-heap.h>
+#include <sys/ioctl.h>
+
+namespace KWin::Wayland
+{
+
+class DmaHeapGraphicsBuffer : public GraphicsBuffer
+{
+public:
+    explicit DmaHeapGraphicsBuffer(DmaBufAttributes &&attributes)
+        : m_attributes(std::move(attributes))
+    {
+    }
+
+    QSize size() const override { return {m_attributes.width, m_attributes.height}; }
+    bool hasAlphaChannel() const override { return alphaChannelFromDrmFormat(m_attributes.format); }
+    const DmaBufAttributes *dmabufAttributes() const override { return &m_attributes; }
+
+private:
+    DmaBufAttributes m_attributes;
+};
+
+DmaHeapGraphicsBufferAllocator::DmaHeapGraphicsBufferAllocator()
+    : m_heap(open("/dev/dma_heap/system", O_RDONLY | O_CLOEXEC))
+{
+}
+
+bool DmaHeapGraphicsBufferAllocator::isValid() const
+{
+    return m_heap.isValid();
+}
+
+GraphicsBuffer *DmaHeapGraphicsBufferAllocator::allocate(const GraphicsBufferOptions &options)
+{
+    if (!isValid() || options.software || options.size.isEmpty()
+        || !options.modifiers.contains(DRM_FORMAT_MOD_LINEAR)) {
+        return nullptr;
+    }
+    switch (options.format) {
+    case DRM_FORMAT_XRGB8888:
+    case DRM_FORMAT_ARGB8888:
+    case DRM_FORMAT_XBGR8888:
+    case DRM_FORMAT_ABGR8888:
+        break;
+    default:
+        return nullptr;
+    }
+    const uint64_t stride = (uint64_t(options.size.width()) * 4 + 255) & ~uint64_t(255);
+    const uint64_t length = stride * options.size.height();
+    if (stride > std::numeric_limits<uint32_t>::max() || length > std::numeric_limits<int32_t>::max()) {
+        return nullptr;
+    }
+    dma_heap_allocation_data allocation{};
+    allocation.len = length;
+    allocation.fd_flags = O_RDWR | O_CLOEXEC;
+    if (ioctl(m_heap.get(), DMA_HEAP_IOCTL_ALLOC, &allocation) < 0) {
+        return nullptr;
+    }
+    DmaBufAttributes attributes;
+    attributes.width = options.size.width();
+    attributes.height = options.size.height();
+    attributes.format = options.format;
+    attributes.modifier = DRM_FORMAT_MOD_LINEAR;
+    attributes.planeCount = 1;
+    attributes.fd[0] = FileDescriptor(allocation.fd);
+    attributes.pitch[0] = stride;
+    return new DmaHeapGraphicsBuffer(std::move(attributes));
+}
+
+}
--- a/src/backends/wayland/dmaheapgraphicsbufferallocator.h
+++ b/src/backends/wayland/dmaheapgraphicsbufferallocator.h
@@ -0,0 +1,21 @@
+/* SPDX-License-Identifier: GPL-2.0-or-later */
+#pragma once
+
+#include "core/graphicsbufferallocator.h"
+#include "utils/filedescriptor.h"
+
+namespace KWin::Wayland
+{
+
+class DmaHeapGraphicsBufferAllocator : public GraphicsBufferAllocator
+{
+public:
+    DmaHeapGraphicsBufferAllocator();
+    bool isValid() const;
+    GraphicsBuffer *allocate(const GraphicsBufferOptions &options) override;
+
+private:
+    FileDescriptor m_heap;
+};
+
+}
--- a/src/backends/wayland/wayland_backend.cpp
+++ b/src/backends/wayland/wayland_backend.cpp
@@ -431,7 +431,7 @@
         return false;
     }

-    if (WaylandLinuxDmabufV1 *dmabuf = m_display->linuxDmabuf()) {
+    if (WaylandLinuxDmabufV1 *dmabuf = m_display->linuxDmabuf(); dmabuf && !dmabuf->mainDevice().isEmpty()) {
         m_drmDevice = DrmDevice::open(dmabuf->mainDevice());
         if (!m_drmDevice) {
             qCWarning(KWIN_WAYLAND_BACKEND) << "Failed to open drm render node" << dmabuf->mainDevice();
@@ -550,7 +550,7 @@
 QList<CompositingType> WaylandBackend::supportedCompositors() const
 {
     QList<CompositingType> ret;
-    if (m_display->linuxDmabuf() && m_drmDevice) {
+    if (m_display->linuxDmabuf() && !m_display->linuxDmabuf()->formats().isEmpty()) {
         ret.append(OpenGLCompositing);
     }
     ret.append(QPainterCompositing);
--- a/src/backends/wayland/wayland_display.cpp
+++ b/src/backends/wayland/wayland_display.cpp
@@ -281,7 +281,9 @@
     };
     zwp_linux_dmabuf_v1_add_listener(m_dmabuf, &dmabufListener, this);

-    m_defaultFeedback = std::make_unique<WaylandLinuxDmabufFeedbackV1>(zwp_linux_dmabuf_v1_get_default_feedback(m_dmabuf));
+    if (version >= 4) {
+        m_defaultFeedback = std::make_unique<WaylandLinuxDmabufFeedbackV1>(zwp_linux_dmabuf_v1_get_default_feedback(m_dmabuf));
+    }
 }

 WaylandLinuxDmabufV1::~WaylandLinuxDmabufV1()
@@ -296,12 +298,12 @@

 QByteArray WaylandLinuxDmabufV1::mainDevice() const
 {
-    return m_defaultFeedback->mainDevice;
+    return m_defaultFeedback ? m_defaultFeedback->mainDevice : QByteArray();
 }

 QHash<uint32_t, QList<uint64_t>> WaylandLinuxDmabufV1::formats() const
 {
-    return m_defaultFeedback->formats;
+    return m_defaultFeedback ? m_defaultFeedback->formats : m_formats;
 }

 void WaylandLinuxDmabufV1::format(void *data, struct zwp_linux_dmabuf_v1 *zwp_linux_dmabuf_v1, uint32_t format)
@@ -311,7 +313,12 @@

 void WaylandLinuxDmabufV1::modifier(void *data, struct zwp_linux_dmabuf_v1 *zwp_linux_dmabuf_v1, uint32_t format, uint32_t modifier_hi, uint32_t modifier_lo)
 {
-    // Not sent in v4 and onward.
+    auto *self = static_cast<WaylandLinuxDmabufV1 *>(data);
+    const uint64_t modifier = (uint64_t(modifier_hi) << 32) | modifier_lo;
+    auto &modifiers = self->m_formats[format];
+    if (!modifiers.contains(modifier)) {
+        modifiers.append(modifier);
+    }
 }

 WaylandDisplay::WaylandDisplay()
@@ -460,8 +467,8 @@
         display->m_xdgDecorationManager = std::make_unique<KWayland::Client::XdgDecorationManager>();
         display->m_xdgDecorationManager->setup(static_cast<zxdg_decoration_manager_v1 *>(wl_registry_bind(registry, name, &zxdg_decoration_manager_v1_interface, std::min(version, 1u))));
     } else if (strcmp(interface, zwp_linux_dmabuf_v1_interface.name) == 0) {
-        if (version < 4) {
-            qWarning("zwp_linux_dmabuf_v1 v4 or newer is needed");
+        if (version < 3) {
+            qWarning("zwp_linux_dmabuf_v1 v3 or newer is needed");
             return;
         }
         display->m_linuxDmabuf = std::make_unique<WaylandLinuxDmabufV1>(registry, name, std::min(version, 4u));
--- a/src/backends/wayland/wayland_display.h
+++ b/src/backends/wayland/wayland_display.h
@@ -55,6 +55,7 @@

     zwp_linux_dmabuf_v1 *m_dmabuf;
     std::unique_ptr<WaylandLinuxDmabufFeedbackV1> m_defaultFeedback;
+    QHash<uint32_t, QList<uint64_t>> m_formats;
 };

 class WaylandDisplay : public QObject
--- a/src/backends/wayland/wayland_egl_backend.h
+++ b/src/backends/wayland/wayland_egl_backend.h
@@ -98,6 +98,9 @@

     WaylandBackend *backend() const;
     DrmDevice *drmDevice() const override;
+    GraphicsBufferAllocator *graphicsBufferAllocator() const override;
+    bool acquireBuffer(GraphicsBuffer *buffer);
+    bool releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence);

     std::unique_ptr<SurfaceTexture> createSurfaceTextureWayland(SurfacePixmap *pixmap) override;

@@ -121,6 +124,7 @@
     };

     WaylandBackend *m_backend;
+    std::unique_ptr<GraphicsBufferAllocator> m_allocator;
     std::map<Output *, Layers> m_outputs;
 };

--- a/src/opengl/egldisplay.cpp
+++ b/src/opengl/egldisplay.cpp
@@ -7,6 +7,9 @@
     SPDX-License-Identifier: GPL-2.0-or-later
 */
 #include "egldisplay.h"
+#include "eglnativefence.h"
+#include <linux/dma-buf.h>
+#include <sys/ioctl.h>
 #include "core/drmdevice.h"
 #include "core/graphicsbuffer.h"
 #include "opengl/eglutils_p.h"
@@ -24,6 +27,54 @@
 namespace KWin
 {

+void EglDisplay::setDmaBufSyncRequired(bool required)
+{
+    m_dmaBufSyncRequired = required;
+}
+
+bool EglDisplay::dmaBufSyncRequired() const
+{
+    return m_dmaBufSyncRequired;
+}
+
+bool EglDisplay::acquireDmaBuf(GraphicsBuffer *buffer, bool write)
+{
+    const auto attributes = buffer->dmabufAttributes();
+    if (!m_dmaBufSyncRequired || !attributes) {
+        return true;
+    }
+    for (int plane = 0; plane < attributes->planeCount; ++plane) {
+        dma_buf_export_sync_file sync{.flags = uint32_t(write ? DMA_BUF_SYNC_RW : DMA_BUF_SYNC_READ), .fd = -1};
+        if (ioctl(attributes->fd[plane].get(), DMA_BUF_IOCTL_EXPORT_SYNC_FILE, &sync) < 0) {
+            return false;
+        }
+        // This is a GPU dependency; it does not block the compositor thread.
+        auto fence = EGLNativeFence::importFence(this, FileDescriptor(sync.fd));
+        if (!fence.waitSync()) {
+            return false;
+        }
+    }
+    return true;
+}
+
+bool EglDisplay::releaseDmaBuf(GraphicsBuffer *buffer, const FileDescriptor &fence, bool write)
+{
+    const auto attributes = buffer->dmabufAttributes();
+    if (!m_dmaBufSyncRequired || !attributes) {
+        return true;
+    }
+    if (!fence.isValid()) {
+        return false;
+    }
+    for (int plane = 0; plane < attributes->planeCount; ++plane) {
+        dma_buf_import_sync_file sync{.flags = uint32_t(write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ), .fd = fence.get()};
+        if (ioctl(attributes->fd[plane].get(), DMA_BUF_IOCTL_IMPORT_SYNC_FILE, &sync) < 0) {
+            return false;
+        }
+    }
+    return true;
+}
+
 bool EglDisplay::shouldUseOpenGLES()
 {
     if (qstrcmp(qgetenv("KWIN_COMPOSE"), "O2ES") == 0) {
--- a/src/opengl/egldisplay.h
+++ b/src/opengl/egldisplay.h
@@ -22,6 +22,8 @@

 struct DmaBufAttributes;
 class GLTexture;
+class GraphicsBuffer;
+class FileDescriptor;

 class KWIN_EXPORT EglDisplay
 {
@@ -45,6 +47,10 @@

     bool supportsBufferAge() const;
     bool supportsNativeFence() const;
+    void setDmaBufSyncRequired(bool required);
+    bool dmaBufSyncRequired() const;
+    bool acquireDmaBuf(GraphicsBuffer *buffer, bool write);
+    bool releaseDmaBuf(GraphicsBuffer *buffer, const FileDescriptor &fence, bool write);

     QHash<uint32_t, QList<uint64_t>> nonExternalOnlySupportedDrmFormats() const;
     QHash<uint32_t, DrmFormatInfo> allSupportedDrmFormats() const;
@@ -72,6 +78,7 @@
     const bool m_supportsBufferAge;
     const bool m_supportsNativeFence;
     QHash<uint32_t, DrmFormatInfo> m_importFormats;
+    bool m_dmaBufSyncRequired = false;

     struct
     {
--- a/src/platformsupport/scenes/opengl/abstract_egl_backend.cpp
+++ b/src/platformsupport/scenes/opengl/abstract_egl_backend.cpp
@@ -94,6 +94,12 @@
     setSupportsBufferAge(m_display->supportsBufferAge());
 }

+GraphicsBufferAllocator *AbstractEglBackend::graphicsBufferAllocator() const
+{
+    const auto device = drmDevice();
+    return device ? device->allocator() : nullptr;
+}
+
 void AbstractEglBackend::initWayland()
 {
     if (!WaylandServer::self()) {
@@ -192,6 +198,19 @@
         LinuxDmaBufV1ClientBufferIntegration *dmabuf = waylandServer()->linuxDmabuf();
         dmabuf->setRenderBackend(this);
         dmabuf->setSupportedFormatsWithModifiers(m_tranches);
+    } else if (m_display->dmaBufSyncRequired()) {
+        QHash<uint32_t, QList<uint64_t>> formats;
+        const auto supported = m_display->allSupportedDrmFormats();
+        for (auto it = supported.constBegin(); it != supported.constEnd(); ++it) {
+            if (!it->nonExternalOnlyModifiers.isEmpty()) {
+                formats.insert(it.key(), it->nonExternalOnlyModifiers);
+            }
+        }
+        if (!formats.isEmpty()) {
+            auto *dmabuf = waylandServer()->linuxDmabuf(false);
+            dmabuf->setRenderBackend(this);
+            dmabuf->setSupportedFormatsWithModifiers(formats);
+        }
     }
     waylandServer()->setRenderBackend(this);
 }
--- a/src/platformsupport/scenes/opengl/abstract_egl_backend.h
+++ b/src/platformsupport/scenes/opengl/abstract_egl_backend.h
@@ -23,6 +23,7 @@

 struct DmaBufAttributes;
 class Output;
+class GraphicsBufferAllocator;

 class KWIN_EXPORT AbstractEglBackend : public OpenGLBackend
 {
@@ -36,6 +37,7 @@
     EglDisplay *eglDisplayObject() const override;
     EglContext *openglContext() const override;
     std::shared_ptr<EglContext> openglContextRef() const;
+    virtual GraphicsBufferAllocator *graphicsBufferAllocator() const;

     bool testImportBuffer(GraphicsBuffer *buffer) override;
     QHash<uint32_t, QList<uint64_t>> supportedFormats() const override;
--- a/src/plugins/qpa/eglplatformcontext.cpp
+++ b/src/plugins/qpa/eglplatformcontext.cpp
@@ -15,6 +15,7 @@
 #include "offscreensurface.h"
 #include "opengl/eglcontext.h"
 #include "opengl/egldisplay.h"
+#include "opengl/eglnativefence.h"
 #include "opengl/glutils.h"
 #include "swapchain.h"
 #include "window.h"
@@ -84,7 +85,7 @@
         }

         GraphicsBuffer *buffer = swapchain->acquire();
-        if (!buffer) {
+        if (!buffer || !m_eglDisplay->acquireDmaBuf(buffer, true)) {
             return false;
         }

@@ -158,6 +159,13 @@

         glFlush(); // We need to flush pending rendering commands manually

+        if (m_eglDisplay->dmaBufSyncRequired()) {
+            EGLNativeFence fence{m_eglDisplay};
+            if (!m_eglDisplay->releaseDmaBuf(m_current->buffer, fence.fileDescriptor(), true)) {
+                qFatal("Could not publish internal window DMA-BUF completion");
+            }
+        }
+
         internalWindow->present(InternalWindowFrame{
             .buffer = m_current->buffer,
             .bufferDamage = QRect(QPoint(0, 0), m_current->buffer->size()),
--- a/src/plugins/qpa/window.cpp
+++ b/src/plugins/qpa/window.cpp
@@ -12,10 +12,10 @@
 #include "utils/drm_format_helper.h"

 #include "compositor.h"
-#include "core/drmdevice.h"
 #include "core/renderbackend.h"
 #include "core/shmgraphicsbufferallocator.h"
 #include "internalwindow.h"
+#include "platformsupport/scenes/opengl/abstract_egl_backend.h"
 #include "swapchain.h"
 #include "window.h"

@@ -57,7 +57,11 @@
             static ShmGraphicsBufferAllocator shmAllocator;
             allocator = &shmAllocator;
         } else {
-            allocator = Compositor::self()->backend()->drmDevice()->allocator();
+            const auto backend = qobject_cast<AbstractEglBackend *>(Compositor::self()->backend());
+            allocator = backend ? backend->graphicsBufferAllocator() : nullptr;
+        }
+        if (!allocator) {
+            return nullptr;
         }

         for (auto it = formats.begin(); it != formats.end(); it++) {
--- a/src/plugins/screencast/screencaststream.cpp
+++ b/src/plugins/screencast/screencaststream.cpp
@@ -920,7 +920,7 @@
 std::optional<ScreenCastDmaBufTextureParams> ScreenCastStream::testCreateDmaBuf(const QSize &size, quint32 format, const QList<uint64_t> &modifiers)
 {
     AbstractEglBackend *backend = qobject_cast<AbstractEglBackend *>(Compositor::self()->backend());
-    if (!backend) {
+    if (!backend || !backend->drmDevice()) {
         return std::nullopt;
     }

--- a/src/scene/itemrenderer_opengl.cpp
+++ b/src/scene/itemrenderer_opengl.cpp
@@ -11,6 +11,7 @@
 #include "core/renderviewport.h"
 #include "core/syncobjtimeline.h"
 #include "effect/effect.h"
+#include "opengl/egldisplay.h"
 #include "opengl/eglnativefence.h"
 #include "platformsupport/scenes/opengl/openglsurfacetexture.h"
 #include "scene/decorationitem.h"
@@ -53,6 +54,13 @@

     if (m_eglDisplay) {
         EGLNativeFence fence(m_eglDisplay);
+        for (auto *buffer : m_dmaBufReads) {
+            if (!m_eglDisplay->releaseDmaBuf(buffer, fence.fileDescriptor(), false)) {
+                qFatal("Could not publish DMA-BUF read completion");
+            }
+            buffer->unref();
+        }
+        m_dmaBufReads.clear();
         if (fence.isValid()) {
             for (const auto &releasePoint : m_releasePoints) {
                 releasePoint->addReleaseFence(fence.fileDescriptor());
@@ -197,6 +205,7 @@
                     .colorDescription = item->colorDescription(),
                     .renderingIntent = item->renderingIntent(),
                     .bufferReleasePoint = surfaceItem->bufferReleasePoint(),
+                    .buffer = pixmap->buffer(),
                 });
             }
         }
@@ -339,6 +348,16 @@
             continue;
         }

+        if (m_eglDisplay && m_eglDisplay->dmaBufSyncRequired() && renderNode.buffer
+            && renderNode.buffer->dmabufAttributes() && !m_dmaBufReads.contains(renderNode.buffer)) {
+            if (!m_eglDisplay->acquireDmaBuf(renderNode.buffer, false)) {
+                qCWarning(KWIN_OPENGL) << "Could not acquire client DMA-BUF for reading";
+                continue;
+            }
+            renderNode.buffer->ref();
+            m_dmaBufReads.insert(renderNode.buffer);
+        }
+
         setBlendEnabled(renderNode.hasAlpha || renderNode.opacity < 1.0);

         ShaderTraits traits = baseShaderTraits;
--- a/src/scene/itemrenderer_opengl.h
+++ b/src/scene/itemrenderer_opengl.h
@@ -32,6 +32,7 @@
         ColorDescription colorDescription;
         RenderingIntent renderingIntent;
         std::shared_ptr<SyncReleasePoint> bufferReleasePoint;
+        GraphicsBuffer *buffer = nullptr;
     };

     struct RenderContext
@@ -65,6 +66,7 @@
     bool m_blendingEnabled = false;
     EglDisplay *const m_eglDisplay;
     std::unordered_set<std::shared_ptr<SyncReleasePoint>> m_releasePoints;
+    std::unordered_set<GraphicsBuffer *> m_dmaBufReads;

     struct
     {
--- a/src/wayland/linuxdmabufv1clientbuffer.cpp
+++ b/src/wayland/linuxdmabufv1clientbuffer.cpp
@@ -23,11 +23,10 @@

 namespace KWin
 {
-static const int s_version = 4;
-
-LinuxDmaBufV1ClientBufferIntegrationPrivate::LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display)
-    : QtWaylandServer::zwp_linux_dmabuf_v1(*display, s_version)
+LinuxDmaBufV1ClientBufferIntegrationPrivate::LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display, bool deviceFeedback)
+    : QtWaylandServer::zwp_linux_dmabuf_v1(*display, deviceFeedback ? 4 : 3)
     , q(q)
+    , deviceFeedback(deviceFeedback)
     , defaultFeedback(new LinuxDmaBufV1Feedback(this))
 {
 }
@@ -289,9 +288,9 @@
     return true;
 }

-LinuxDmaBufV1ClientBufferIntegration::LinuxDmaBufV1ClientBufferIntegration(Display *display)
+LinuxDmaBufV1ClientBufferIntegration::LinuxDmaBufV1ClientBufferIntegration(Display *display, bool deviceFeedback)
     : QObject(display)
-    , d(new LinuxDmaBufV1ClientBufferIntegrationPrivate(this, display))
+    , d(new LinuxDmaBufV1ClientBufferIntegrationPrivate(this, display, deviceFeedback))
 {
 }

@@ -328,6 +327,12 @@
     }
 }

+void LinuxDmaBufV1ClientBufferIntegration::setSupportedFormatsWithModifiers(const QHash<uint32_t, QList<uint64_t>> &formats)
+{
+    Q_ASSERT(!d->deviceFeedback);
+    d->supportedModifiers = formats;
+}
+
 void LinuxDmaBufV1ClientBuffer::buffer_destroy_resource(wl_resource *resource)
 {
     if (LinuxDmaBufV1ClientBuffer *buffer = LinuxDmaBufV1ClientBuffer::get(resource)) {
--- a/src/wayland/linuxdmabufv1clientbuffer.h
+++ b/src/wayland/linuxdmabufv1clientbuffer.h
@@ -66,13 +66,14 @@
     Q_OBJECT

 public:
-    explicit LinuxDmaBufV1ClientBufferIntegration(Display *display);
+    explicit LinuxDmaBufV1ClientBufferIntegration(Display *display, bool deviceFeedback = true);
     ~LinuxDmaBufV1ClientBufferIntegration() override;

     RenderBackend *renderBackend() const;
     void setRenderBackend(RenderBackend *renderBackend);

     void setSupportedFormatsWithModifiers(const QList<LinuxDmaBufV1Feedback::Tranche> &tranches);
+    void setSupportedFormatsWithModifiers(const QHash<uint32_t, QList<uint64_t>> &formats);

 private:
     friend class LinuxDmaBufV1ClientBufferIntegrationPrivate;
--- a/src/wayland/linuxdmabufv1clientbuffer_p.h
+++ b/src/wayland/linuxdmabufv1clientbuffer_p.h
@@ -31,9 +31,10 @@
 class LinuxDmaBufV1ClientBufferIntegrationPrivate : public QtWaylandServer::zwp_linux_dmabuf_v1
 {
 public:
-    LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display);
+    LinuxDmaBufV1ClientBufferIntegrationPrivate(LinuxDmaBufV1ClientBufferIntegration *q, Display *display, bool deviceFeedback);

     LinuxDmaBufV1ClientBufferIntegration *q;
+    const bool deviceFeedback;
     std::unique_ptr<LinuxDmaBufV1Feedback> defaultFeedback;
     std::unique_ptr<LinuxDmaBufV1FormatTable> table;
     dev_t mainDevice;
--- a/src/wayland_server.cpp
+++ b/src/wayland_server.cpp
@@ -521,10 +521,10 @@
     return m_drm;
 }

-LinuxDmaBufV1ClientBufferIntegration *WaylandServer::linuxDmabuf()
+LinuxDmaBufV1ClientBufferIntegration *WaylandServer::linuxDmabuf(bool deviceFeedback)
 {
     if (!m_linuxDmabuf) {
-        m_linuxDmabuf = new LinuxDmaBufV1ClientBufferIntegration(m_display);
+        m_linuxDmabuf = new LinuxDmaBufV1ClientBufferIntegration(m_display, deviceFeedback);
     }
     return m_linuxDmabuf;
 }
@@ -823,7 +823,7 @@

 void WaylandServer::setRenderBackend(RenderBackend *backend)
 {
-    if (backend->drmDevice()->supportsSyncObjTimelines()) {
+    if (const auto device = backend->drmDevice(); device && device->supportsSyncObjTimelines()) {
         // ensure the DRM_IOCTL_SYNCOBJ_EVENTFD ioctl is supported
         const auto linuxVersion = linuxKernelVersion();
         if (linuxVersion.majorVersion() < 6 && linuxVersion.minorVersion() < 6) {
--- a/src/wayland_server.h
+++ b/src/wayland_server.h
@@ -131,7 +131,7 @@
     bool isKeyboardShortcutsInhibited() const;

     DrmClientBufferIntegration *drm();
-    LinuxDmaBufV1ClientBufferIntegration *linuxDmabuf();
+    LinuxDmaBufV1ClientBufferIntegration *linuxDmabuf(bool deviceFeedback = true);

     InputMethodV1Interface *inputMethod() const
     {
PATCH
    case "${1:-6.3.6}" in
        6.2.5) cat <<'PATCH'
--- a/src/backends/wayland/wayland_egl_backend.cpp
+++ b/src/backends/wayland/wayland_egl_backend.cpp
@@ -9,6 +9,7 @@
 */

 #include "wayland_egl_backend.h"
+#include "dmaheapgraphicsbufferallocator.h"
 #include "core/drmdevice.h"
 #include "core/gbmgraphicsbufferallocator.h"
 #include "opengl/eglswapchain.h"
@@ -71,7 +72,7 @@
             if (it == formatTable.constEnd()) {
                 continue;
             }
-            m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
             if (m_swapchain) {
                 break;
             }
@@ -83,7 +84,7 @@
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -103,6 +104,9 @@
     // Flush rendering commands to the dmabuf.
     glFlush();
     EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }

     m_presentationBuffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
@@ -170,28 +174,24 @@
     const QSize bufferSize(std::ceil(tmp.width()), std::ceil(tmp.height()));
     if (!m_swapchain || m_swapchain->size() != bufferSize) {
         const QHash<uint32_t, QList<uint64_t>> formatTable = m_backend->backend()->display()->linuxDmabuf()->formats();
-        uint32_t format = DRM_FORMAT_INVALID;
-        QList<uint64_t> modifiers;
         for (const uint32_t &candidateFormat : {DRM_FORMAT_ARGB2101010, DRM_FORMAT_ARGB8888}) {
             auto it = formatTable.constFind(candidateFormat);
-            if (it != formatTable.constEnd()) {
-                format = it.key();
-                modifiers = it.value();
+            if (it == formatTable.constEnd()) {
+                continue;
+            }
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), bufferSize, it.key(), it.value());
+            if (m_swapchain) {
                 break;
             }
         }
-        if (format == DRM_FORMAT_INVALID) {
-            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable render format";
-            return std::nullopt;
-        }
-        m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), bufferSize, format, modifiers);
         if (!m_swapchain) {
+            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable cursor format";
             return std::nullopt;
         }
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -212,12 +212,16 @@
     // Flush rendering commands to the dmabuf.
     glFlush();

+    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }
+
     wl_buffer *buffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     Q_ASSERT(buffer);

     static_cast<WaylandOutput *>(m_output)->cursor()->update(buffer, scale(), hotspot().toPoint());

-    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
     return true;
 }
@@ -259,6 +263,21 @@
     return m_backend->drmDevice();
 }

+GraphicsBufferAllocator *WaylandEglBackend::graphicsBufferAllocator() const
+{
+    return m_allocator ? m_allocator.get() : AbstractEglBackend::graphicsBufferAllocator();
+}
+
+bool WaylandEglBackend::acquireBuffer(GraphicsBuffer *buffer)
+{
+    return eglDisplayObject()->acquireDmaBuf(buffer, true);
+}
+
+bool WaylandEglBackend::releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence)
+{
+    return eglDisplayObject()->releaseDmaBuf(buffer, fence, true);
+}
+
 void WaylandEglBackend::cleanupSurfaces()
 {
     m_outputs.clear();
@@ -278,14 +297,19 @@
     initClientExtensions();

     if (!m_backend->sceneEglDisplayObject()) {
-        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), QByteArrayLiteral("EGL_KHR_platform_gbm")}) {
+        const auto platform = drmDevice() ? QByteArrayLiteral("EGL_KHR_platform_gbm") : QByteArrayLiteral("EGL_KHR_platform_wayland");
+        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), platform}) {
             if (!hasClientExtension(extension)) {
                 qCWarning(KWIN_WAYLAND_BACKEND) << extension << "client extension is not supported by the platform";
                 return false;
             }
         }

-        m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, m_backend->drmDevice()->gbmDevice(), nullptr)));
+        if (drmDevice()) {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, drmDevice()->gbmDevice(), nullptr)));
+        } else {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_WAYLAND_KHR, m_backend->display()->nativeDisplay(), nullptr)));
+        }
     }

     const auto display = m_backend->sceneEglDisplayObject();
@@ -293,6 +317,22 @@
         return false;
     }
     setEglDisplay(display);
+    if (!drmDevice()) {
+        for (const auto &extension : {QByteArrayLiteral("EGL_EXT_image_dma_buf_import_modifiers"),
+                                     QByteArrayLiteral("EGL_ANDROID_native_fence_sync"),
+                                     QByteArrayLiteral("EGL_KHR_wait_sync")}) {
+            if (!display->hasExtension(extension)) {
+                qCWarning(KWIN_WAYLAND_BACKEND) << "DMA heap rendering requires" << extension;
+                return false;
+            }
+        }
+        auto allocator = std::make_unique<DmaHeapGraphicsBufferAllocator>();
+        if (!allocator->isValid()) {
+            return false;
+        }
+        m_allocator = std::move(allocator);
+        display->setDmaBufSyncRequired(true);
+    }
     return true;
 }

@@ -307,6 +347,20 @@
         return;
     }

+    if (m_allocator) {
+        // Validate allocation, EGL import and both synchronization directions before
+        // advertising GPU composition or DMA-BUF to nested clients.
+        const auto formats = m_backend->display()->linuxDmabuf()->formats();
+        auto probe = EglSwapchain::create(m_allocator.get(), openglContext(), QSize(64, 64),
+                                          DRM_FORMAT_XRGB8888, formats.value(DRM_FORMAT_XRGB8888));
+        auto slot = probe ? probe->acquire() : nullptr;
+        EGLNativeFence fence{eglDisplayObject()};
+        if (!slot || !acquireBuffer(slot->buffer()) || !releaseBuffer(slot->buffer(), fence.fileDescriptor())) {
+            setFailed("DMA heap buffer import or synchronization is unavailable");
+            return;
+        }
+    }
+
     initWayland();
 }

--- a/src/compositor_wayland.cpp
+++ b/src/compositor_wayland.cpp
@@ -167,7 +167,7 @@
             break;
         } else if (qEnvironmentVariableIsSet("KWIN_COMPOSE")) {
             qCCritical(KWIN_CORE) << "Could not fulfill the requested compositing mode in KWIN_COMPOSE:" << type << ". Exiting.";
-            qApp->quit();
+            break;
         }
     }

@@ -176,7 +176,8 @@

         qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
         qCCritical(KWIN_CORE) << "We are going to quit KWin now as it is broken";
-        qApp->quit();
+        // Startup may run before exec(); queue the failure for the event loop.
+        QMetaObject::invokeMethod(qApp, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
         return;
     }

PATCH
            ;;
        6.3.6) cat <<'PATCH'
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -7,7 +7,7 @@
 set(CMAKE_CXX_STANDARD 23)
 set(CMAKE_CXX_STANDARD_REQUIRED ON)

-set(PROJECT_DEP_VERSION "6.3.6")
+set(PROJECT_DEP_VERSION "6.3.4")
 set(QT_MIN_VERSION "6.7.0")
 set(KF6_MIN_VERSION "6.10.0")
 set(KDE_COMPILERSETTINGS_LEVEL "5.82")
--- a/src/backends/wayland/wayland_egl_backend.cpp
+++ b/src/backends/wayland/wayland_egl_backend.cpp
@@ -9,6 +9,7 @@
 */

 #include "wayland_egl_backend.h"
+#include "dmaheapgraphicsbufferallocator.h"
 #include "core/drmdevice.h"
 #include "core/gbmgraphicsbufferallocator.h"
 #include "opengl/eglswapchain.h"
@@ -71,7 +72,7 @@
             if (it == formatTable.constEnd()) {
                 continue;
             }
-            m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), nativeSize, it.key(), it.value());
             if (m_swapchain) {
                 break;
             }
@@ -83,7 +84,7 @@
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -103,6 +104,9 @@
     // Flush rendering commands to the dmabuf.
     glFlush();
     EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }

     static_cast<WaylandOutput *>(m_output)->setPrimaryBuffer(m_backend->backend()->importBuffer(m_buffer->buffer()));
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
@@ -159,28 +163,24 @@
     const QSize bufferSize(std::ceil(tmp.width()), std::ceil(tmp.height()));
     if (!m_swapchain || m_swapchain->size() != bufferSize) {
         const QHash<uint32_t, QList<uint64_t>> formatTable = m_backend->backend()->display()->linuxDmabuf()->formats();
-        uint32_t format = DRM_FORMAT_INVALID;
-        QList<uint64_t> modifiers;
         for (const uint32_t &candidateFormat : {DRM_FORMAT_ARGB2101010, DRM_FORMAT_ARGB8888}) {
             auto it = formatTable.constFind(candidateFormat);
-            if (it != formatTable.constEnd()) {
-                format = it.key();
-                modifiers = it.value();
+            if (it == formatTable.constEnd()) {
+                continue;
+            }
+            m_swapchain = EglSwapchain::create(m_backend->graphicsBufferAllocator(), m_backend->openglContext(), bufferSize, it.key(), it.value());
+            if (m_swapchain) {
                 break;
             }
         }
-        if (format == DRM_FORMAT_INVALID) {
-            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable render format";
-            return std::nullopt;
-        }
-        m_swapchain = EglSwapchain::create(m_backend->drmDevice()->allocator(), m_backend->openglContext(), bufferSize, format, modifiers);
         if (!m_swapchain) {
+            qCWarning(KWIN_WAYLAND_BACKEND) << "Could not find a suitable cursor format";
             return std::nullopt;
         }
     }

     m_buffer = m_swapchain->acquire();
-    if (!m_buffer) {
+    if (!m_buffer || !m_backend->acquireBuffer(m_buffer->buffer())) {
         return std::nullopt;
     }

@@ -201,12 +201,16 @@
     // Flush rendering commands to the dmabuf.
     glFlush();

+    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
+    if (!m_backend->releaseBuffer(m_buffer->buffer(), releaseFence.fileDescriptor())) {
+        return false;
+    }
+
     wl_buffer *buffer = m_backend->backend()->importBuffer(m_buffer->buffer());
     Q_ASSERT(buffer);

     static_cast<WaylandOutput *>(m_output)->cursor()->update(buffer, scale(), hotspot().toPoint());

-    EGLNativeFence releaseFence{m_backend->eglDisplayObject()};
     m_swapchain->release(m_buffer, releaseFence.takeFileDescriptor());
     return true;
 }
@@ -248,6 +252,21 @@
     return m_backend->drmDevice();
 }

+GraphicsBufferAllocator *WaylandEglBackend::graphicsBufferAllocator() const
+{
+    return m_allocator ? m_allocator.get() : AbstractEglBackend::graphicsBufferAllocator();
+}
+
+bool WaylandEglBackend::acquireBuffer(GraphicsBuffer *buffer)
+{
+    return eglDisplayObject()->acquireDmaBuf(buffer, true);
+}
+
+bool WaylandEglBackend::releaseBuffer(GraphicsBuffer *buffer, const FileDescriptor &fence)
+{
+    return eglDisplayObject()->releaseDmaBuf(buffer, fence, true);
+}
+
 void WaylandEglBackend::cleanupSurfaces()
 {
     m_outputs.clear();
@@ -267,14 +286,19 @@
     initClientExtensions();

     if (!m_backend->sceneEglDisplayObject()) {
-        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), QByteArrayLiteral("EGL_KHR_platform_gbm")}) {
+        const auto platform = drmDevice() ? QByteArrayLiteral("EGL_KHR_platform_gbm") : QByteArrayLiteral("EGL_KHR_platform_wayland");
+        for (const QByteArray &extension : {QByteArrayLiteral("EGL_EXT_platform_base"), platform}) {
             if (!hasClientExtension(extension)) {
                 qCWarning(KWIN_WAYLAND_BACKEND) << extension << "client extension is not supported by the platform";
                 return false;
             }
         }

-        m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, m_backend->drmDevice()->gbmDevice(), nullptr)));
+        if (drmDevice()) {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_GBM_KHR, drmDevice()->gbmDevice(), nullptr)));
+        } else {
+            m_backend->setEglDisplay(EglDisplay::create(eglGetPlatformDisplayEXT(EGL_PLATFORM_WAYLAND_KHR, m_backend->display()->nativeDisplay(), nullptr)));
+        }
     }

     const auto display = m_backend->sceneEglDisplayObject();
@@ -282,6 +306,22 @@
         return false;
     }
     setEglDisplay(display);
+    if (!drmDevice()) {
+        for (const auto &extension : {QByteArrayLiteral("EGL_EXT_image_dma_buf_import_modifiers"),
+                                     QByteArrayLiteral("EGL_ANDROID_native_fence_sync"),
+                                     QByteArrayLiteral("EGL_KHR_wait_sync")}) {
+            if (!display->hasExtension(extension)) {
+                qCWarning(KWIN_WAYLAND_BACKEND) << "DMA heap rendering requires" << extension;
+                return false;
+            }
+        }
+        auto allocator = std::make_unique<DmaHeapGraphicsBufferAllocator>();
+        if (!allocator->isValid()) {
+            return false;
+        }
+        m_allocator = std::move(allocator);
+        display->setDmaBufSyncRequired(true);
+    }
     return true;
 }

@@ -296,6 +336,20 @@
         return;
     }

+    if (m_allocator) {
+        // Validate allocation, EGL import and both synchronization directions before
+        // advertising GPU composition or DMA-BUF to nested clients.
+        const auto formats = m_backend->display()->linuxDmabuf()->formats();
+        auto probe = EglSwapchain::create(m_allocator.get(), openglContext(), QSize(64, 64),
+                                          DRM_FORMAT_XRGB8888, formats.value(DRM_FORMAT_XRGB8888));
+        auto slot = probe ? probe->acquire() : nullptr;
+        EGLNativeFence fence{eglDisplayObject()};
+        if (!slot || !acquireBuffer(slot->buffer()) || !releaseBuffer(slot->buffer(), fence.fileDescriptor())) {
+            setFailed("DMA heap buffer import or synchronization is unavailable");
+            return;
+        }
+    }
+
     initWayland();
 }

--- a/src/compositor_wayland.cpp
+++ b/src/compositor_wayland.cpp
@@ -120,7 +120,7 @@
     return true;
 }

-void WaylandCompositor::createRenderer()
+bool WaylandCompositor::createRenderer()
 {
     // If compositing has been restarted, try to use the last used compositing type.
     const QList<CompositingType> availableCompositors = kwinApp()->outputBackend()->supportedCompositors();
@@ -161,9 +161,16 @@
             break;
         } else if (qEnvironmentVariableIsSet("KWIN_COMPOSE")) {
             qCCritical(KWIN_CORE) << "Could not fulfill the requested compositing mode in KWIN_COMPOSE:" << type << ". Exiting.";
-            qApp->quit();
+            break;
         }
     }
+    if (m_backend) {
+        return true;
+    }
+    qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
+    // Startup may run before exec(); queue the failure for the event loop.
+    QMetaObject::invokeMethod(qApp, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
+    return false;
 }

 void WaylandCompositor::createScene()
@@ -191,16 +198,8 @@
     Q_EMIT aboutToToggleCompositing();
     m_state = State::Starting;

-    if (!m_backend) {
-        createRenderer();
-    }
-
-    if (!m_backend) {
+    if (!m_backend && !createRenderer()) {
         m_state = State::Off;
-
-        qCCritical(KWIN_CORE) << "The used windowing system requires compositing";
-        qCCritical(KWIN_CORE) << "We are going to quit KWin now as it is broken";
-        qApp->quit();
         return;
     }

--- a/src/compositor_wayland.h
+++ b/src/compositor_wayland.h
@@ -23,7 +23,7 @@
     static WaylandCompositor *create(QObject *parent = nullptr);
     ~WaylandCompositor() override;

-    void createRenderer();
+    bool createRenderer();

     void start() override;
     void stop() override;
--- a/src/main_wayland.cpp
+++ b/src/main_wayland.cpp
@@ -142,7 +142,9 @@
     createTabletModeManager();

     auto compositor = WaylandCompositor::create();
-    compositor->createRenderer();
+    if (!compositor->createRenderer()) {
+        return;
+    }
     createWorkspace();
     createColorManager();
     createPlugins();
PATCH
            ;;
    esac
}

build_support() {
    cat <<'BUILD_SUPPORT'
build_phase=${MAGICDESK_BUILD_PHASE:-all}
case "$build_phase" in
    all|dependencies|build) ;;
    *) echo 'Invalid source-build phase.' >&2; exit 1 ;;
esac
BUILD_SUPPORT
}

weston_setup() {
    distribution_support
    build_support
    cat <<'WESTON'
jobs=$1
recipe=$2
[ -f /usr/local/share/applications/magicdesk-weston.desktop ] || exit 0
# 13.0.0 dereferences popup shell data during focus handoff. Use the official
# maintenance release, not a compositor fork or a browser-specific workaround.
case "$(/usr/bin/weston --version)" in
    'weston 13.0.'[0-3]) ;;
    *) rm -f /etc/magicdesk/weston.sh; exit 0 ;;
esac
version=13.0.4
archive_sha=66252c9c5bbc45ab402e2518b76e6d824f09ebc1d0040ee2f51b096a1bc585b1
prefix=/opt/magicdesk/weston/$version-$recipe
work=/var/cache/magicdesk/weston/$version-$recipe
mkdir -p /var/lib/magicdesk /etc/magicdesk "$work"
exec 9>/var/lib/magicdesk/installer.lock
flock -n 9 || { echo 'Another graphics setup is running in this environment.' >&2; exit 1; }
candidate=/etc/magicdesk/weston.sh.new
trap 'status=$?; rm -f "$candidate"; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
if [ ! -f "$prefix/.complete" ]; then
    if [ "$build_phase" != build ]; then
        case "$family" in
            apt) packages build-essential meson ninja-build pkg-config curl xz-utils \
                libwayland-dev wayland-protocols libxkbcommon-dev libpixman-1-dev \
                libinput-dev libevdev-dev libudev-dev libdrm-dev libcairo2-dev \
                libpango1.0-dev libpng-dev libegl-dev libgles-dev libxcb-composite0-dev \
                libxcb-shape0-dev libxcb-xfixes0-dev libxcb-cursor-dev libxcursor-dev ;;
            apk) packages build-base meson ninja pkgconf curl xz wayland-dev wayland-protocols \
                libxkbcommon-dev pixman-dev libinput-dev libevdev-dev eudev-dev libdrm-dev \
                cairo-dev pango-dev libpng-dev libglvnd-dev libxcb-dev xcb-util-cursor-dev libxcursor-dev ;;
            dnf) packages gcc gcc-c++ meson ninja-build pkgconf-pkg-config curl xz \
                wayland-devel wayland-protocols-devel libxkbcommon-devel pixman-devel \
                libinput-devel libevdev-devel systemd-devel libdrm-devel cairo-devel \
                pango-devel libpng-devel libglvnd-devel libxcb-devel xcb-util-cursor-devel libXcursor-devel ;;
            pacman|recovery) packages base-devel meson ninja pkgconf curl xz wayland wayland-protocols \
                libxkbcommon pixman libinput libevdev libdrm cairo pango libpng libglvnd libxcb xcb-util-cursor libxcursor ;;
            zypper) packages gcc gcc-c++ make meson ninja pkgconf-pkg-config curl xz \
                wayland-devel wayland-protocols-devel libxkbcommon-devel pixman-devel \
                libinput-devel libevdev-devel libudev-devel libdrm-devel cairo-devel \
                pango-devel libpng-devel libglvnd-devel libxcb-devel xcb-util-cursor-devel libXcursor-devel ;;
            xbps) packages base-devel meson ninja pkg-config curl xz wayland-devel wayland-protocols \
                libxkbcommon-devel pixman-devel libinput-devel libevdev-devel eudev-libudev-devel \
                libdrm-devel cairo-devel pango-devel libpng-devel libglvnd-devel libxcb-devel xcb-util-cursor-devel libXcursor-devel ;;
        esac
    fi
    [ "$build_phase" != dependencies ] || exit 0
    mkdir -p /var/cache/magicdesk/weston/downloads
    archive=/var/cache/magicdesk/weston/downloads/weston-$version.tar.xz
    if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
        # EVENT_WAIT: download progress; a stalled connection fails and curl retries it.
        curl --fail --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 --output "$archive.part" \
            "https://gitlab.freedesktop.org/wayland/weston/-/releases/$version/downloads/weston-$version.tar.xz"
        printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum -c -
        mv "$archive.part" "$archive"
    fi
    source=$work/weston-$version
    if [ ! -f "$source/.extracted" ]; then
        rm -rf "$source" "$work/build" "$work/unpack"
        mkdir "$work/unpack"
        tar --no-same-owner -xJf "$archive" -C "$work/unpack"
        touch "$work/unpack/weston-$version/.extracted"
        mv "$work/unpack/weston-$version" "$source"
        rmdir "$work/unpack"
    fi
    set -- --prefix="$prefix" --libdir=lib --buildtype=release --wrap-mode=nodownload \
        -Dbackend-default=wayland -Dbackend-drm=false -Dbackend-drm-screencast-vaapi=false \
        -Dbackend-pipewire=false -Dbackend-rdp=false -Dbackend-vnc=false -Dbackend-x11=false \
        -Dbackend-wayland=true -Dbackend-headless=true -Drenderer-gl=true -Dxwayland=true \
        -Dsystemd=false -Dscreenshare=false -Dremoting=false -Dpipewire=false \
        -Dshell-fullscreen=false -Dshell-ivi=false -Dshell-kiosk=false \
        -Dcolor-management-lcms=false -Dimage-jpeg=false -Dimage-webp=false \
        -Ddemo-clients=false -Dsimple-clients= -Dtools=terminal -Dwcap-decode=false -Dtest-junit-xml=false
    if [ -f "$work/build/build.ninja" ]; then
        meson setup --reconfigure "$work/build" "$source" "$@" </dev/null
    else
        meson setup "$work/build" "$source" "$@" </dev/null
    fi
    ninja -C "$work/build" -j "$jobs" </dev/null
    rm -rf "$work/stage"
    meson install -C "$work/build" --no-rebuild --destdir "$work/stage" </dev/null
    [ -x "$work/stage$prefix/bin/weston" ] || exit 1
    mkdir -p /opt/magicdesk/weston
    [ ! -e "$prefix" ] || { echo "Incomplete prefix exists: $prefix" >&2; exit 1; }
    printf '%s\n' "$recipe" > "$work/stage$prefix/.complete"
    mv "$work/stage$prefix" "$prefix"
fi
[ "$build_phase" != dependencies ] || exit 0
[ "$(cat "$prefix/.complete")" = "$recipe" ] || { echo 'Weston build identity mismatch.' >&2; exit 1; }
printf "weston_prefix='%s'\n" "$prefix" > "$candidate"
mv "$candidate" /etc/magicdesk/weston.sh
WESTON
}

plasma_setup() {
    case "$distro" in steamos) kwin_version=6.2.5 ;; *) kwin_version=6.3.6 ;; esac
    distribution_support
    build_support
    cat <<'KWIN_HEAD'
jobs=$1
recipe=$2
[ -f /usr/local/share/applications/magicdesk-plasma-wayland.desktop ] || exit 0
[ ! -r /etc/profile.d/magicdesk-graphics.sh ] || . /etc/profile.d/magicdesk-graphics.sh
[ -n "${MAGICDESK_MESA_PREFIX:-}" ] || exit 0
case "$ID:$VERSION_ID" in
    debian:13)
        version=6.3.6
        archive_sha=27f2205f06d58f1d1f480d2a94ae24022c2f95b9c1fdc5a549f8e143713fce12 ;;
    steamos:0.3.0)
        version=6.2.5
        archive_sha=5cc450a6e41105c8c49929b72550b331237f96aafb294690f4707bdc5f776848 ;;
    *) echo 'The pinned KWin recipe requires Debian 13 or SteamOS 0.3.0.' >&2; exit 1 ;;
esac
prefix=/opt/magicdesk/kwin/$version-$recipe
work=/var/cache/magicdesk/kwin/$version-$recipe
mkdir -p /var/lib/magicdesk /etc/magicdesk "$work"
exec 9>/var/lib/magicdesk/installer.lock
flock -n 9 || { echo 'Another graphics setup is running in this environment.' >&2; exit 1; }
candidate=/etc/magicdesk/plasma-kwin.sh.new
trap 'status=$?; rm -f "$candidate"; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$work/dmaheap.patch" <<'KWIN_PATCH'
KWIN_HEAD
    kwin_patch "$kwin_version"
    cat <<'KWIN_BODY'
KWIN_PATCH
if [ ! -f "$prefix/.complete" ]; then
    if [ "$build_phase" != build ]; then
    case "$family" in
    apt)
    packages build-essential cmake ninja-build extra-cmake-modules pkgconf patch curl xz-utils \
        gettext hwdata breeze-dev kscreenlocker-dev kwayland-dev \
        libcanberra-dev libcap-dev libdisplay-info-dev libdrm-dev libegl-dev libeis-dev \
        libepoxy-dev libfontconfig-dev libfreetype-dev libgbm-dev libice-dev libinput-dev \
        libkdecorations3-dev libkf6auth-dev libkf6colorscheme-dev libkf6config-dev \
        libkf6configwidgets-dev libkf6coreaddons-dev libkf6crash-dev libkf6dbusaddons-dev \
        libkf6declarative-dev libkf6doctools-dev libkf6globalaccel-dev libkf6guiaddons-dev \
        libkf6i18n-dev libkf6idletime-dev libkf6itemviews-dev libkf6kcmutils-dev \
        libkf6newstuff-dev libkf6notifications-dev libkf6package-dev libkf6runner-dev \
        libkf6service-dev libkf6svg-dev libkf6widgetsaddons-dev libkf6windowsystem-dev \
        libkf6xmlgui-dev libkglobalacceld-dev libkirigami-dev liblcms2-dev libpipewire-0.3-dev \
        libplasma-dev libplasmaactivities-dev libqaccessibilityclient-qt6-dev libsm-dev \
        libsystemd-dev libudev-dev libwayland-dev libx11-xcb-dev libxcb-composite0-dev \
        libxcb-cursor-dev libxcb-damage0-dev libxcb-dri3-dev libxcb-glx0-dev \
        libxcb-icccm4-dev libxcb-image0-dev libxcb-keysyms1-dev libxcb-present-dev \
        libxcb-randr0-dev libxcb-render0-dev libxcb-shape0-dev libxcb-shm0-dev \
        libxcb-sync-dev libxcb-util-dev libxcb-xfixes0-dev libxcb-xinerama0-dev \
        libxcb-xinput-dev libxcb-xkb-dev libxcb-xtest0-dev libxcb1-dev libxcursor-dev \
        libxcvt-dev libxkbcommon-dev libxkbcommon-x11-dev plasma-wayland-protocols \
        qt6-5compat-dev qt6-base-dev qt6-base-private-dev qt6-declarative-dev \
        qt6-declarative-private-dev qt6-sensors-dev qt6-svg-dev qt6-tools-dev \
        qt6-wayland-dev qt6-wayland-dev-tools wayland-protocols xwayland ;;
    recovery)
        # Arch-style packages already include headers; retain the image's Plasma ABI.
        packages base-devel cmake ninja extra-cmake-modules pkgconf patch curl xz \
            gettext wayland-protocols plasma-wayland-protocols ;;
    esac
    fi
    [ "$build_phase" != dependencies ] || exit 0
    mkdir -p /var/cache/magicdesk/kwin/downloads
    archive=/var/cache/magicdesk/kwin/downloads/kwin-$version.tar.xz
    if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
        # EVENT_WAIT: download progress; a stalled connection fails and curl retries it.
        curl --fail --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 --output "$archive.part" \
            "https://download.kde.org/stable/plasma/$version/kwin-$version.tar.xz"
        printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum -c -
        mv "$archive.part" "$archive"
    fi
    source=$work/source
    if [ ! -f "$source/.patched" ]; then
        rm -rf "$source" "$work/build" "$work/unpack"
        mkdir "$work/unpack"
        tar --no-same-owner -xJf "$archive" -C "$work/unpack"
        patch --batch --forward --fuzz=0 -p1 -d "$work/unpack/kwin-$version" < "$work/dmaheap.patch"
        touch "$work/unpack/kwin-$version/.patched"
        mv "$work/unpack/kwin-$version" "$source"
        rmdir "$work/unpack"
    fi
    cmake -S "$source" -B "$work/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_AUTOGEN_PARALLEL="$jobs" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DKDE_INSTALL_USE_QT_SYS_PATHS=OFF \
        -DKDE_INSTALL_LIBDIR=lib -DKDE_INSTALL_QTPLUGINDIR=lib/qt6/plugins \
        -DKDE_INSTALL_QMLDIR=lib/qt6/qml -DCMAKE_INSTALL_RPATH="$prefix/lib" \
        -DBUILD_TESTING=OFF -DKWIN_BUILD_KCMS=OFF -DKWIN_BUILD_X11_BACKEND=OFF </dev/null
    cmake --build "$work/build" --parallel "$jobs" </dev/null
    rm -rf "$work/stage"
    DESTDIR="$work/stage" cmake --install "$work/build" </dev/null
    [ -x "$work/stage$prefix/bin/kwin_wayland" ] || exit 1
    mkdir -p /opt/magicdesk/kwin
    [ ! -e "$prefix" ] || { echo "Incomplete prefix exists: $prefix" >&2; exit 1; }
    printf '%s\n' "$recipe" > "$work/stage$prefix/.complete"
    mv "$work/stage$prefix" "$prefix"
fi
[ "$build_phase" != dependencies ] || exit 0
[ "$(cat "$prefix/.complete")" = "$recipe" ] || { echo 'KWin build identity mismatch.' >&2; exit 1; }
printf "kwin_prefix='%s'\n" "$prefix" > "$candidate"
mv "$candidate" /etc/magicdesk/plasma-kwin.sh
KWIN_BODY
}

flatpak_gl_helper() {
    cat <<'FLATPAK_GL_PY'
#!/usr/bin/env python3
"""Publish the selected Mesa build through Flatpak's local GL.host extension."""
import configparser
import ctypes
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

CONFIG = Path('/etc/magicdesk/mesa-prefix')
PROBE = Path('/usr/local/libexec/magicdesk-mesa-probe')
EXTENSION = 'org.freedesktop.Platform.GL.host'
FORMAT = '1'


def public_directory(path):
    try:
        path.mkdir()
    except FileExistsError:
        if not path.is_dir() or path.is_symlink():
            raise ValueError('Not a local Flatpak directory: ' + str(path))
    else:
        path.chmod(0o755)


def prepare_environment(base):
    # Host absolute driver paths are not valid inside a runtime. Use Flatpak's
    # normal loader discovery, without overriding explicit per-app settings.
    path = base / 'overrides/global'
    data = configparser.ConfigParser(interpolation=None, strict=False)
    data.optionxform = str
    original = path.read_text() if path.exists() else ''
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    data.read_string(original)
    unset = data.get('Context', 'unset-environment', fallback='').split(';')
    unset = [key for key in unset if key]
    changed = False
    for key in ('VK_DRIVER_FILES', 'VK_ICD_FILENAMES',
                '__EGL_VENDOR_LIBRARY_FILENAMES', 'LIBGL_DRIVERS_PATH'):
        if key not in unset and not data.has_option('Environment', key):
            unset.append(key)
            changed = True
    if not changed:
        return
    if not data.has_section('Context'):
        data.add_section('Context')
    data.set('Context', 'unset-environment', ';'.join(unset) + ';')
    output = io.StringIO()
    data.write(output, space_around_delimiters=False)
    public_directory(path.parent)
    fd, name = tempfile.mkstemp(prefix='.magicdesk-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(output.getvalue())
            os.fchmod(stream.fileno(), mode)
        if (path.read_text() if path.exists() else '') != original:
            raise ValueError('Flatpak overrides changed during GPU preparation; retry')
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def runtime_groups(base):
    groups = {}
    for metadata in sorted((base / 'runtime').glob('*/aarch64/*/active/metadata')):
        data = configparser.ConfigParser(interpolation=None, strict=False)
        data.read(metadata)
        section = 'Extension org.freedesktop.Platform.GL'
        if not data.has_section(section):
            continue
        layout = data.get(section, 'directory', fallback='')
        if not layout.startswith('lib/') or '..' in layout.split('/'):
            raise ValueError('Invalid GL extension directory: ' + layout)
        versions = data.get(section, 'versions', fallback=data.get(section, 'version',
                           fallback=metadata.parents[1].name)).split(';')
        # 1.4 is the unversioned NVIDIA ABI, not a Mesa compatibility promise.
        branch = next((v for v in versions if re.fullmatch(r'\d{2}\.\d{2}', v)), None)
        if branch and data.getboolean(section, 'subdirectories', fallback=False):
            groups.setdefault(branch, []).append((metadata.resolve(), layout))
    return groups


def relocate_json(source, target, root):
    data = json.loads(source.read_text())
    name = Path(data['ICD']['library_path']).name
    if not (target.parents[2] / 'lib' / name).is_file():
        raise ValueError('Missing Mesa ICD library: ' + name)
    data['ICD']['library_path'] = root + '/lib/' + name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data) + '\n')


def stage_bundle(prefix, directory, layout):
    shutil.copytree(prefix / 'lib', directory / 'lib', symlinks=True)
    # Development files are not part of a runtime extension.
    shutil.rmtree(directory / 'lib/pkgconfig', ignore_errors=True)
    root = '/usr/' + layout + '/host'
    relocate_json(prefix / 'share/vulkan/icd.d/freedreno_icd.aarch64.json',
                  directory / 'vulkan/icd.d/magicdesk.json', root)
    relocate_json(prefix / 'share/glvnd/egl_vendor.d/50_mesa.json',
                  directory / 'glvnd/egl_vendor.d/50_magicdesk.json', root)


def verify_runtime(metadata, bundle):
    files = metadata.parent / 'files'
    loaders = list(files.glob('lib/ld-linux-aarch64.so.1'))
    loaders += list(files.glob('lib/*/ld-linux-aarch64.so.1'))
    if not loaders:
        raise ValueError('No ARM64 glibc loader in ' + str(metadata))
    loader = '/usr/' + str(loaders[0].relative_to(files))
    libraries = [str(p.relative_to(bundle)) for p in sorted((bundle / 'lib').glob('*.so*'))
                 if p.is_file() and not p.is_symlink()]
    if not libraries:
        raise ValueError('Empty Mesa library set')
    command = ['bwrap', '--unshare-pid', '--unshare-net', '--unshare-ipc',
               '--ro-bind', str(files), '/usr', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/bin', '/bin', '--dev', '/dev', '--proc', '/proc',
               '--ro-bind', str(bundle), '/mdgl', '--ro-bind', str(PROBE), '/probe',
               '--chdir', '/', '--', loader, '--library-path',
               '/mdgl/lib:/usr/lib/aarch64-linux-gnu:/usr/lib', '/probe']
    command += ['/mdgl/' + name for name in libraries]
    # EVENT_WAIT: the runtime loader/dlopen probe exits; timeout rejects admission.
    result = subprocess.run(command, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=30)
    if result.returncode:
        raise ValueError('Mesa cannot load in ' + str(metadata) + ':\n' + result.stdout)


def owned(link):
    return not link.is_symlink() and (link / '.magicdesk-gl').is_file()


def publish(candidate, destination):
    if not destination.exists():
        os.rename(candidate, destination)
        return False
    # Exchange whole directories: relative symlinks inside an extension remain
    # valid after Flatpak mounts it; live sandboxes retain the old directory.
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if rename is None:
        raise OSError(errno.ENOSYS, 'libc does not provide renameat2 for atomic GL replacement')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(candidate), -100, os.fsencode(destination), 2):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return True


def retire(link, bundles):
    if owned(link):
        unused = Path(tempfile.mkdtemp(prefix='retired-', dir=bundles))
        os.replace(link, unused)


def write_receipt(directory, receipt):
    fd, name = tempfile.mkstemp(prefix='.receipt-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(receipt) + '\n')
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, directory / '.magicdesk-gl')
    finally:
        Path(name).unlink(missing_ok=True)


def extension_directory(base):
    destination = base
    for name in ('extension', EXTENSION, 'aarch64'):
        destination = destination / name
        public_directory(destination)
    return destination


def prepare(base, prefix):
    base = base.resolve()
    if not (base / 'runtime').is_dir():
        return
    bundles = base / '.magicdesk-gl'
    bundles.mkdir(exist_ok=True)
    with (bundles / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        destination = base / 'extension' / EXTENSION / 'aarch64'
        groups = runtime_groups(base) if prefix else {}
        failed = []
        if prefix:
            identity = (prefix / '.complete').read_text().strip()
            if not identity:
                raise ValueError('Incomplete Mesa build')
        for branch, runtimes in groups.items():
            link = destination / branch
            if os.path.lexists(link) and not owned(link):
                failed.append('Not replacing an independently installed GL.host: ' + str(link))
                continue
            layouts = {layout for _, layout in runtimes}
            if len(layouts) != 1:
                failed.append('Conflicting GL paths for runtime branch ' + branch)
                retire(link, bundles)
                continue
            layout = next(iter(layouts))
            receipt = [FORMAT, str(prefix), identity, layout,
                       [str(path) for path, _ in runtimes]]
            temporary = None
            try:
                previous = json.loads((link / '.magicdesk-gl').read_text()) if owned(link) else None
                if previous == receipt:
                    continue
                if isinstance(previous, list) and previous[:4] == receipt[:4]:
                    for metadata, _ in runtimes:
                        verify_runtime(metadata, link)
                    write_receipt(link, receipt)
                    continue
                temporary = Path(tempfile.mkdtemp(prefix='.prepare-', dir=bundles))
                stage_bundle(prefix, temporary, layout)
                for metadata, _ in runtimes:
                    verify_runtime(metadata, temporary)
                write_receipt(temporary, receipt)
                temporary.chmod(0o755)
                extension_directory(base)
                if publish(temporary, link):
                    previous_bundle, temporary = temporary, None
                    os.rename(previous_bundle, previous_bundle.with_name(
                        'retired-' + previous_bundle.name.removeprefix('.prepare-')))
                temporary = None
                print('Flatpak Mesa ready: ' + branch)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                # An old build is not silently reused after ABI admission failed.
                retire(link, bundles)
                failed.append(str(error))
            finally:
                if temporary:
                    shutil.rmtree(temporary)
        for link in destination.glob('*'):
            if link.name not in groups and owned(link):
                retire(link, bundles)
        if any(owned(destination / branch) for branch in groups):
            prepare_environment(base)
        # Old immutable bundles can still be mounted by running applications.
        # Keep them; never mutate a library beneath an existing sandbox.
        if failed:
            raise ValueError('\n'.join(failed))


def main():
    prefix = Path(CONFIG.read_text().strip()) if CONFIG.is_file() else None
    if prefix and not prefix.is_absolute():
        raise ValueError('Mesa prefix must be absolute')
    if len(sys.argv) > 1:
        bases = [Path(arg) for arg in sys.argv[1:]]
    else:
        bases = [Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'flatpak']
        if os.geteuid() == 0:
            bases.append(Path('/var/lib/flatpak'))
    for base in bases:
        prepare(base, prefix)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, configparser.Error, subprocess.SubprocessError) as error:
        print('Flatpak Mesa not activated: ' + str(error), file=sys.stderr)
        sys.exit(1)
FLATPAK_GL_PY
}

snap_gpu_helper() {
    cat <<'SNAP_GPU_PY'
#!/usr/bin/env python3
"""Publish prepared Mesa through mesa-2404's kernel-gpu-2404 content plug."""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

CONFIG = Path('/etc/magicdesk/mesa-prefix')
PROBE = Path('/usr/local/libexec/magicdesk-mesa-probe')
CACHE = Path('/var/cache/magicdesk/snap-gpu')
SNAP_DATA = Path('/var/snap/mesa-2404')
NAME = 'magicdesk-gpu-2404'
FORMAT = '2'
MANGLER = '''# Sourced by the official gpu-2404 provider, not an app wrapper.
md_gpu=$COMPONENT_PATH
export LD_LIBRARY_PATH="$md_gpu/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBGL_DRIVERS_PATH="$md_gpu/lib/dri" GBM_BACKENDS_PATH="$md_gpu/lib/gbm"
export __EGL_VENDOR_LIBRARY_FILENAMES="$md_gpu/share/glvnd/egl_vendor.d/50_mesa.json"
export VK_DRIVER_FILES="$md_gpu/share/vulkan/icd.d/freedreno_icd.aarch64.json"
export VK_ICD_FILENAMES="$VK_DRIVER_FILES"
export MESA_LOADER_DRIVER_OVERRIDE=zink GALLIUM_DRIVER=zink LIBGL_KOPPER_DRI2=true
unset LIBGL_ALWAYS_SOFTWARE md_gpu
'''


def run(argv, **kwargs):
    # EVENT_WAIT: the bounded preparation command exits; expiry rejects it.
    return subprocess.run(argv, check=True, timeout=300, **kwargs)


def check_connection():
    connection = http.client.HTTPConnection('localhost', timeout=30)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(30)
    try:
        connection.sock.connect('/run/snapd.socket')
        connection.request('GET', '/v2/connections?select=all')
        response = connection.getresponse()
        data = json.load(response)
        if response.status != 200:
            raise ValueError('Cannot inspect Snap GPU connections: ' + str(data))
    finally:
        connection.close()
    for entry in data['result']['established']:
        if entry['plug'] == {'snap': 'mesa-2404', 'plug': 'kernel-gpu-2404'}:
            if entry['slot'] != {'snap': NAME, 'slot': 'kernel-gpu-2404'}:
                raise ValueError('mesa-2404 already uses another GPU provider; disconnect it explicitly')


def wait_for_component(provider, identity):
    directory = SNAP_DATA / provider.name / 'kernel-gpu-2404'
    marker = directory / 'kernel-gpu-2404-sentinel'
    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'Cannot observe GPU component publication')
    try:
        events = 0x8 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800
        if libc.inotify_add_watch(fd, os.fsencode(directory.parent), events) < 0:
            raise OSError(ctypes.get_errno(), 'Cannot watch GPU provider data directory')
        deadline = time.monotonic() + 60
        while True:
            # The monitor can create or replace its publication directory. Keep
            # its parent watched and arm the current directory before reading.
            if libc.inotify_add_watch(fd, os.fsencode(directory), events) < 0:
                error = ctypes.get_errno()
                if error != errno.ENOENT:
                    raise OSError(error, 'Cannot watch GPU component directory')
            try:
                if marker.read_text().strip() == identity:
                    return
            except FileNotFoundError:
                pass
            remaining = deadline - time.monotonic()
            # EVENT_WAIT: component-monitor publishes the sentinel last. Timeout
            # is failure, not proof that the new driver is ready for applications.
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError('Timed out waiting for mesa-2404.component-monitor')
            os.read(fd, 65536)
    finally:
        os.close(fd)


def stage_bundle(prefix, root, identity):
    shutil.copytree(prefix / 'lib', root / 'lib', symlinks=True)
    shutil.rmtree(root / 'lib/pkgconfig', ignore_errors=True)
    for path in (root / 'lib').rglob('*'):
        if path.is_symlink() and not path.resolve().is_relative_to((root / 'lib').resolve()):
            raise ValueError('Mesa library link escapes its bundle: ' + str(path))
    for name in ('vulkan/icd.d/freedreno_icd.aarch64.json', 'glvnd/egl_vendor.d/50_mesa.json'):
        data = json.loads((prefix / 'share' / name).read_text())
        library = Path(data['ICD']['library_path']).name
        if not (root / 'lib' / library).is_file():
            raise ValueError('Missing Mesa library: ' + library)
        # The provider prepends its library directory; no host absolute paths.
        data['ICD']['library_path'] = library
        target = root / 'share' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data) + '\n')
    (root / 'kernel-gpu-2404-provider-mangler').write_text(MANGLER)
    (root / 'kernel-gpu-2404-sentinel').write_text(identity + '\n')
    (root / 'meta').mkdir()
    (root / 'meta/snap.yaml').write_text('''name: ''' + NAME + '''
version: 'md-''' + identity[:24] + ''''
summary: Locally prepared MagicDesk Mesa
description: Turnip and Zink for the mesa-2404 GPU content provider.
architectures: [arm64]
base: core24
confinement: strict
grade: devel
slots:
  kernel-gpu-2404:
    interface: content
    content: kernel-gpu-2404
    read: [$SNAP]
''')
    # The caller's private umask must not make a content snap root-only.
    root.chmod(0o755)
    for path in root.rglob('*'):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)


def provider_libraries(provider):
    # Both published mesa-2404 layouts retain the same content contract.
    for path in ('mesa-2404/usr/lib/aarch64-linux-gnu', 'usr/lib/aarch64-linux-gnu'):
        if (provider / path / 'libvulkan.so.1').is_file():
            return path
    raise ValueError('Unsupported mesa-2404 library layout')


def verify_runtime(root, base, provider):
    libraries = provider_libraries(provider)
    targets = [str(p.relative_to(root)) for p in sorted((root / 'lib').rglob('*.so*'))
               if p.is_file() and not p.is_symlink()]
    if not targets:
        raise ValueError('Empty Mesa library bundle')
    argv = ['bwrap', '--unshare-pid', '--unshare-net', '--unshare-ipc',
            '--ro-bind', str(base / 'usr'), '/usr', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/bin', '/bin', '--dev', '/dev', '--proc', '/proc',
            '--ro-bind', str(root), '/mdgl', '--ro-bind', str(provider), '/mdprovider',
            '--ro-bind', str(PROBE), '/probe', '--chdir', '/', '--',
            '/lib/ld-linux-aarch64.so.1', '--library-path',
            '/mdgl/lib:/mdprovider/' + libraries + ':/usr/lib/aarch64-linux-gnu',
            '/probe']
    run(argv + ['/mdgl/' + name for name in targets],
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})


def prepare(prefix, base, provider, jobs):
    marker = (prefix / '.complete').read_text().strip()
    if not marker:
        raise ValueError('Incomplete Mesa build')
    identity = hashlib.sha256((FORMAT + '\n' + str(prefix) + '\n' + marker + '\n' +
                               MANGLER + str(base) + '\n' + str(provider)).encode()).hexdigest()
    CACHE.mkdir(parents=True, exist_ok=True)
    image = CACHE / (NAME + '-' + identity + '.snap')
    if not image.is_file():
        with tempfile.TemporaryDirectory(prefix='.prepare-', dir=CACHE) as temporary:
            root = Path(temporary) / 'root'
            root.mkdir()
            stage_bundle(prefix, root, identity)
            verify_runtime(root, base, provider)
            candidate = Path(temporary) / 'gpu.snap'
            run(['mksquashfs', str(root), str(candidate), '-noappend', '-all-root',
                 '-comp', 'xz', '-processors', str(jobs), '-no-progress'])
            os.replace(candidate, image)
    return image, identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, help='Prepared Mesa prefix; defaults to recipe selection')
    parser.add_argument('--jobs', type=int, default=2, help='Compression workers')
    parser.add_argument('--build-only', action='store_true', help='Build and verify without changing Snap connections')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run as root inside the selected Linux environment')
    if args.jobs < 1:
        raise ValueError('--jobs must be positive')
    prefix = (args.prefix or Path(CONFIG.read_text().strip())).resolve(strict=True)
    base = Path('/snap/core24/current').resolve(strict=True)
    provider = Path('/snap/mesa-2404/current').resolve(strict=True)
    wrapper = (provider / 'bin/gpu-2404-provider-wrapper').read_text()
    if 'kernel-gpu-2404-provider-mangler' not in wrapper:
        raise ValueError('mesa-2404 does not support the kernel-gpu-2404 provider contract')
    for name in ('bwrap', 'mksquashfs', 'snap'):
        if not shutil.which(name):
            raise ValueError('Required command is not installed: ' + name)
    if not PROBE.is_file():
        raise ValueError('Reapply the graphics recipe to install the Mesa ABI probe')
    CACHE.mkdir(parents=True, exist_ok=True)
    with (CACHE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not args.build_only:
            check_connection()
        image, identity = prepare(prefix, base, provider, args.jobs)
        print('Snap GPU bundle: ' + str(image), flush=True)
        if args.build_only:
            return
        marker = Path('/snap') / NAME / 'current/kernel-gpu-2404-sentinel'
        if marker.parent.exists() and not marker.is_file():
            raise ValueError('Not replacing an independently installed ' + NAME)
        if not marker.is_file() or marker.read_text().strip() != identity:
            # Locally built content is unsigned; this does not disable confinement.
            run(['snap', 'install', '--dangerous', str(image)])
        run(['snap', 'connect', 'mesa-2404:kernel-gpu-2404', NAME + ':kernel-gpu-2404'])
        run(['snap', 'start', '--enable', 'mesa-2404.component-monitor'])
        wait_for_component(provider, identity)
        print('Snap GPU connected. Applications keep their mesa-2404:gpu-2404 connection.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Snap GPU preparation failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
SNAP_GPU_PY
}

# One payload is both fingerprinted and executed; the lab exports the same patch.
graphics_setup() {
    distribution_support
    build_support
    cat <<'GPU_HEAD'
set -eu
umask 022
gpu=$1
jobs=$2
recipe=$3
version=26.2.3
archive_sha=1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f
mkdir -p /var/lib/magicdesk /etc/profile.d
exec 9>/var/lib/magicdesk/installer.lock
flock -n 9 || { echo 'Another graphics setup is running in this environment.' >&2; exit 1; }
profile=/etc/profile.d/magicdesk-graphics.sh
candidate=$profile.new
trap 'status=$?; rm -f "$candidate"; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p /usr/local/libexec /usr/local/bin /etc/magicdesk
cat > /usr/local/bin/magicdesk-flatpak-gl <<'FLATPAK_GL_HELPER'
GPU_HEAD
    flatpak_gl_helper
    cat <<'GPU_HEAD'
FLATPAK_GL_HELPER
chmod 755 /usr/local/bin/magicdesk-flatpak-gl
cat > /usr/local/bin/magicdesk-snap-gpu <<'SNAP_GPU_HELPER'
GPU_HEAD
    snap_gpu_helper
    cat <<'GPU_HEAD'
SNAP_GPU_HELPER
chmod 755 /usr/local/bin/magicdesk-snap-gpu

prepare_meson() {
    meson_tool=$(command -v meson || :)
    if [ -n "$meson_tool" ] && python3 -c '
import re, sys
match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[.-].*)?", sys.argv[1])
sys.exit(0 if match and tuple(map(int, match.groups())) >= (1, 4, 0) else 1)
' "$("$meson_tool" --version)"; then return; fi
    meson_version=1.7.2
    meson_sha=4d40d63aa748a9c139cc41ab9bffe43edd113c5639d78bde81544ca955aea890
    meson_root=$work/tools/meson-$meson_version
    meson_tool=$meson_root/meson.py
    if [ ! -f "$meson_root/.complete" ]; then
        mkdir -p "$work/tools"
        meson_archive=$work/tools/meson-$meson_version.tar.gz
        if ! printf '%s  %s\n' "$meson_sha" "$meson_archive" | sha256sum -c - >/dev/null 2>&1; then
            # EVENT_WAIT: download progress; stalled transport fails before extraction.
            curl --fail --location --proto '=https' --proto-redir '=https' \
                --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 \
                --output "$meson_archive.part" \
                "https://github.com/mesonbuild/meson/releases/download/$meson_version/meson-$meson_version.tar.gz"
            printf '%s  %s\n' "$meson_sha" "$meson_archive.part" | sha256sum -c -
            mv "$meson_archive.part" "$meson_archive"
        fi
        rm -rf "$meson_root"
        tar --no-same-owner -xzf "$meson_archive" -C "$work/tools"
        [ "$("$meson_tool" --version)" = "$meson_version" ]
        touch "$meson_root/.complete"
    fi
}

automatic=no
if [ "$gpu" = auto ]; then
    automatic=yes
    gpu=software
    if [ -c /dev/kgsl-3d0 ] && [ -r /dev/kgsl-3d0 ] && [ -w /dev/kgsl-3d0 ]; then
        gpu=turnip
    else
        printf 'KGSL is unavailable; selecting software rendering.\n'
    fi
fi
if [ "$gpu" != turnip ] && [ "$build_phase" = dependencies ]; then exit 0; fi
if [ "$gpu" = turnip ]; then
    [ -c /dev/kgsl-3d0 ] && [ -r /dev/kgsl-3d0 ] && [ -w /dev/kgsl-3d0 ] || {
        echo 'Turnip requires access to /dev/kgsl-3d0; the graphics profile is unchanged.' >&2
        exit 1
    }
    prefix=/opt/magicdesk/mesa/$version-$recipe
    work=/var/cache/magicdesk/mesa/$version-$recipe
    mkdir -p "$work"
    cat > "$work/wayland-zink.patch" <<'MESA_PATCH'
GPU_HEAD
    mesa_patch
    cat <<'GPU_BODY'
MESA_PATCH
    if [ "$build_phase" != build ]; then
    case "$family" in
    apt) packages build-essential meson ninja-build pkg-config \
        python3-mako python3-yaml python3-ply bison flex patch curl xz-utils glslang-tools \
        libdrm-dev libexpat1-dev libzstd-dev zlib1g-dev libelf-dev \
        libwayland-dev libwayland-egl-backend-dev wayland-protocols libglvnd-dev libvulkan-dev vulkan-tools mesa-utils \
        libx11-dev libx11-xcb-dev libxext-dev libxfixes-dev libxxf86vm-dev \
        libxrandr-dev libxshmfence-dev libxcb-glx0-dev libxcb-randr0-dev \
        libxcb-shm0-dev libxcb-dri3-dev libxcb-present-dev libxcb-sync-dev \
        libxcb-xfixes0-dev ;;
    apk) packages build-base meson ninja pkgconf python3 py3-mako py3-yaml py3-ply bison flex \
        patch curl xz glslang-dev linux-headers libdrm-dev expat-dev zstd-dev zlib-dev elfutils-dev \
        wayland-dev wayland-protocols libglvnd-dev vulkan-headers vulkan-tools \
        libx11-dev libxext-dev libxfixes-dev libxxf86vm-dev libxrandr-dev libxshmfence-dev libxcb-dev ;;
    dnf) packages gcc gcc-c++ meson ninja-build pkgconf-pkg-config python3-mako python3-pyyaml \
        python3-ply bison flex patch curl xz glslang libdrm-devel expat-devel libzstd-devel zlib-ng-compat-devel \
        elfutils-libelf-devel wayland-devel wayland-protocols-devel libglvnd-devel vulkan-headers vulkan-tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    pacman|recovery) packages base-devel meson ninja pkgconf python-mako python-yaml python-ply bison flex \
        patch curl xz glslang libdrm expat zstd zlib libelf wayland wayland-protocols libglvnd vulkan-headers \
        vulkan-tools libx11 libxext libxfixes libxxf86vm libxrandr libxshmfence libxcb ;;
    zypper) packages gcc gcc-c++ make meson ninja pkgconf-pkg-config python3-Mako python3-PyYAML \
        python3-ply bison flex patch curl xz glslang-devel libdrm-devel libexpat-devel libzstd-devel zlib-devel \
        libelf-devel wayland-devel wayland-protocols-devel libglvnd-devel vulkan-headers vulkan-tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    xbps) packages base-devel meson ninja pkg-config python3-Mako python3-yaml python3-ply bison flex \
        patch curl xz glslang libdrm-devel expat-devel libzstd-devel zlib-devel elfutils-devel \
        wayland-devel wayland-protocols libglvnd-devel Vulkan-Headers Vulkan-Tools \
        libX11-devel libXext-devel libXfixes-devel libXxf86vm-devel libXrandr-devel libxshmfence-devel libxcb-devel ;;
    esac
    fi
    [ "$build_phase" != dependencies ] || exit 0
    if [ ! -f "$prefix/.complete" ]; then
        mkdir -p /var/cache/magicdesk/mesa/downloads
        archive=/var/cache/magicdesk/mesa/downloads/mesa-$version.tar.xz
        if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
            # EVENT_WAIT: download progress; a stalled connection fails and curl retries it.
            curl --fail --location --proto '=https' --proto-redir '=https' \
                --connect-timeout 30 --speed-limit 1 --speed-time 60 --retry 3 --output "$archive.part" \
                "https://archive.mesa3d.org/mesa-$version.tar.xz"
            printf '%s  %s\n' "$archive_sha" "$archive.part" | sha256sum -c -
            mv "$archive.part" "$archive"
        fi
        source=$work/source
        if [ ! -f "$source/.patched" ]; then
            rm -rf "$source" "$work/build" "$work/unpack"
            mkdir "$work/unpack"
            tar --no-same-owner -xJf "$archive" -C "$work/unpack"
            source_tmp=$work/unpack/mesa-$version
            patch --batch --forward --fuzz=0 -p1 -d "$source_tmp" < "$work/wayland-zink.patch"
            touch "$source_tmp/.patched"
            mv "$source_tmp" "$source"
            rmdir "$work/unpack"
        fi
        prepare_meson
        # Both KMDs are needed: Vulkan WSI also uses the DRM image allocator.
        set -- --prefix="$prefix" --libdir=lib --buildtype=release --wrap-mode=nodownload \
            -Dauto_features=disabled -Dplatforms=x11,wayland -Dllvm=disabled \
            -Dxmlconfig=disabled -Dbuild-tests=false -Dgallium-rusticl=false \
            -Dvulkan-drivers=freedreno -Dfreedreno-kmds=msm,kgsl \
            -Dgallium-drivers=zink,softpipe -Dopengl=true -Dgles1=enabled -Dgles2=enabled -Dglx=dri \
            -Degl=enabled -Dgbm=enabled -Dglvnd=enabled -Dgallium-va=disabled
        if [ -f "$work/build/build.ninja" ]; then
            "$meson_tool" setup --reconfigure "$work/build" "$source" "$@" </dev/null
        else
            "$meson_tool" setup "$work/build" "$source" "$@" </dev/null
        fi
        ninja -C "$work/build" -j "$jobs" </dev/null
        # Install off to the side; a resumed/failed installation cannot alter active libraries.
        rm -rf "$work/stage"
        "$meson_tool" install -C "$work/build" --no-rebuild --destdir "$work/stage" </dev/null
        mkdir -p /opt/magicdesk/mesa
        [ ! -e "$prefix" ] || { echo "Incomplete prefix exists: $prefix" >&2; exit 1; }
        printf '%s\n' "$recipe" > "$work/stage$prefix/.complete"
        mv "$work/stage$prefix" "$prefix"
    fi
    [ "$(cat "$prefix/.complete")" = "$recipe" ] || { echo 'Mesa build identity mismatch.' >&2; exit 1; }
    cat > "$work/flatpak-gl-probe.c" <<'PROBE'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        void *library = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
        if (!library) { fprintf(stderr, "%s: %s\n", argv[i], dlerror()); return 1; }
        dlclose(library);
    }
    return 0;
}
PROBE
    cc -O2 "$work/flatpak-gl-probe.c" -ldl -o "$work/flatpak-gl-probe"
    install -m 755 "$work/flatpak-gl-probe" /usr/local/libexec/magicdesk-mesa-probe
fi

# Remove only our previously exported library directory when re-sourcing a login profile.
reset_profile() {
cat <<'PROFILE'
if [ -n "${MAGICDESK_FEX_THUNKCONFIG:-}" ] && [ "${FEX_THUNKCONFIG:-}" = "$MAGICDESK_FEX_THUNKCONFIG" ]; then
    unset FEX_THUNKCONFIG
fi
unset MAGICDESK_FEX_THUNKCONFIG
if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
    _md_paths=${LD_LIBRARY_PATH:-}
    _md_kept=
    while [ -n "$_md_paths" ]; do
        _md_item=${_md_paths%%:*}
        case $_md_paths in *:*) _md_paths=${_md_paths#*:} ;; *) _md_paths= ;; esac
        if [ -n "$_md_item" ] && [ "$_md_item" != "$MAGICDESK_MESA_PREFIX/lib" ]; then
            _md_kept=${_md_kept:+$_md_kept:}$_md_item
        fi
    done
    if [ -n "$_md_kept" ]; then export LD_LIBRARY_PATH=$_md_kept; else unset LD_LIBRARY_PATH; fi
    _md_paths=${PRESSURE_VESSEL_FILESYSTEMS_RO:-}
    _md_kept=
    while [ -n "$_md_paths" ]; do
        _md_item=${_md_paths%%:*}
        case $_md_paths in *:*) _md_paths=${_md_paths#*:} ;; *) _md_paths= ;; esac
        if [ -n "$_md_item" ] && [ "$_md_item" != "$MAGICDESK_MESA_PREFIX" ] && [ "$_md_item" != /opt/magicdesk/fex-thunks.json ]; then
            _md_kept=${_md_kept:+$_md_kept:}$_md_item
        fi
    done
    if [ -n "$_md_kept" ]; then export PRESSURE_VESSEL_FILESYSTEMS_RO=$_md_kept; else unset PRESSURE_VESSEL_FILESYSTEMS_RO; fi
    unset _md_paths _md_kept _md_item
fi
unset MAGICDESK_MESA_PREFIX LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER MESA_LOADER_DRIVER_OVERRIDE
unset LIBGL_DRIVERS_PATH LIBGL_KOPPER_DRI2 __EGL_VENDOR_LIBRARY_FILENAMES VK_DRIVER_FILES VK_ICD_FILENAMES
unset MESA_VK_WSI_DEBUG
PROFILE
}
reset_profile > "$candidate"
if [ "$gpu" = turnip ]; then
    printf 'export MAGICDESK_MESA_PREFIX=%s\n' "$prefix" >> "$candidate"
    cat >> "$candidate" <<'PROFILE'
export LD_LIBRARY_PATH="$MAGICDESK_MESA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBGL_DRIVERS_PATH="$MAGICDESK_MESA_PREFIX/lib/dri"
export __EGL_VENDOR_LIBRARY_FILENAMES="$MAGICDESK_MESA_PREFIX/share/glvnd/egl_vendor.d/50_mesa.json"
export VK_DRIVER_FILES="$MAGICDESK_MESA_PREFIX/share/vulkan/icd.d/freedreno_icd.aarch64.json"
# Zink can also present through the frontend when Kopper/DRI3 is unavailable.
export MESA_LOADER_DRIVER_OVERRIDE=zink GALLIUM_DRIVER=zink LIBGL_KOPPER_DRI2=true
# Thunk defaults are loaded before FEX's per-game overrides; never replace those.
if [ -r /opt/magicdesk/fex-thunks.json ]; then
    if [ "${FEX_THUNKCONFIG+x}" != x ]; then
        export FEX_THUNKCONFIG=/opt/magicdesk/fex-thunks.json
        export MAGICDESK_FEX_THUNKCONFIG=$FEX_THUNKCONFIG
    fi
    export PRESSURE_VESSEL_FILESYSTEMS_RO="$MAGICDESK_MESA_PREFIX:/opt/magicdesk/fex-thunks.json${PRESSURE_VESSEL_FILESYSTEMS_RO:+:$PRESSURE_VESSEL_FILESYSTEMS_RO}"
fi
PROFILE
    # EVENT_WAIT: Vulkan enumeration exits; timeout rejects a hung driver, never activates it.
    probe_status=0
    /bin/sh -c '. "$1"; unset DISPLAY WAYLAND_DISPLAY; exec timeout 30 vulkaninfo --summary' sh "$candidate" \
        > "$work/vulkan-probe.log" 2>&1 || probe_status=$?
    cat "$work/vulkan-probe.log"
    if [ "$probe_status" -ne 0 ] || ! grep -Eq 'driverID[[:space:]]*=[[:space:]]*DRIVER_ID_MESA_TURNIP' "$work/vulkan-probe.log"; then
        [ "$automatic" = yes ] || {
            echo 'No working Turnip GPU found; the graphics profile is unchanged.' >&2; exit 1;
        }
        printf 'Turnip could not initialize this GPU (status %s); selecting software rendering.\n' "$probe_status"
        gpu=software
        reset_profile > "$candidate"
    fi
fi
if [ "$gpu" = software ]; then
    if [ "$ID" = steamos ]; then
        # Valve's Mesa supplies Zink, not a swrast Gallium driver. Its older
        # Lavapipe package needs LLVM 17 alongside the image's newer LLVM.
        packages vulkan-swrast llvm17-libs vulkan-tools mesa-utils
        cat >> "$candidate" <<'PROFILE'
export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=zink MESA_LOADER_DRIVER_OVERRIDE=zink
export LIBGL_KOPPER_DRI2=true
export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.aarch64.json
PROFILE
        work=/var/cache/magicdesk/software
        mkdir -p "$work"
        # EVENT_WAIT: Vulkan/EGL probes exit; expiry rejects the candidate profile.
        probe_status=0
        /bin/sh -c '. "$1"; unset DISPLAY WAYLAND_DISPLAY; exec timeout 30 /bin/sh -ec \
            "vulkaninfo --summary; eglinfo -B -p surfaceless"' sh "$candidate" \
            > "$work/probe.log" 2>&1 || probe_status=$?
        cat "$work/probe.log"
        if [ "$probe_status" -ne 0 ] \
                || ! grep -q 'DRIVER_ID_MESA_LLVMPIPE' "$work/probe.log" \
                || ! grep -Eq 'OpenGL core profile renderer:.*zink.*llvmpipe' "$work/probe.log"; then
            echo 'Lavapipe/Zink could not initialize; the graphics profile is unchanged.' >&2
            exit 1
        fi
    else
        printf 'export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe\n' >> "$candidate"
    fi
fi
chmod 644 "$candidate"
mv -f "$candidate" "$profile"
if [ "$gpu" = turnip ]; then
    printf '%s\n' "$prefix" > /etc/magicdesk/mesa-prefix.new
    mv /etc/magicdesk/mesa-prefix.new /etc/magicdesk/mesa-prefix
    mkdir -p /usr/share/flatpak/triggers
    cat > /usr/share/flatpak/triggers/magicdesk-gl.trigger <<'TRIGGER'
#!/bin/sh
exec /usr/local/bin/magicdesk-flatpak-gl "$1"
TRIGGER
    chmod 755 /usr/share/flatpak/triggers/magicdesk-gl.trigger
else
    rm -f /etc/magicdesk/mesa-prefix
fi
if command -v python3 >/dev/null 2>&1; then
    magicdesk-flatpak-gl || echo 'Flatpak GPU preparation failed; see the diagnostic above.' >&2
fi
printf 'Graphics profile activated for new launches: %s\n' "$gpu"
GPU_BODY
}

desktop_session() {
    cat <<'DESKTOP'
#!/bin/sh
set -eu
desktop=${1:?Expected xfce, weston, gnome, plasma-x11 or plasma-wayland}
shift
[ ! -r /etc/profile.d/magicdesk-graphics.sh ] || . /etc/profile.d/magicdesk-graphics.sh
[ ! -r /etc/profile.d/magicdesk-applications.sh ] || . /etc/profile.d/magicdesk-applications.sh
if command -v magicdesk-flatpak-gl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    magicdesk-flatpak-gl || echo 'Flatpak GPU preparation failed; see the diagnostic above.' >&2
fi
# Root needs no authentication agent. Keep packaged and user autostart files
# intact; this profile applies only to explicitly launched root desktops.
if [ "$(id -u)" = 0 ]; then
    export XDG_CONFIG_DIRS="/etc/magicdesk/root-session:${XDG_CONFIG_DIRS:-/etc/xdg}"
fi
case "$desktop" in
    xfce)
        unset WAYLAND_DISPLAY WAYLAND_SOCKET
        export XDG_SESSION_TYPE=x11 XDG_CURRENT_DESKTOP=XFCE XDG_SESSION_DESKTOP=xfce
        set -- xfce4-session "$@" ;;
    weston)
        export XDG_SESSION_TYPE=wayland
        # Package upgrades can retire the compatibility build without rebuilding.
        case "$(/usr/bin/weston --version)" in
            'weston 13.0.'[0-3])
                [ -r /etc/magicdesk/weston.sh ] || {
                    echo 'Complete Weston compatibility setup before launching this desktop.' >&2; exit 1;
                }
                . /etc/magicdesk/weston.sh
                [ -x "$weston_prefix/bin/weston" ] || exit 1
                export PATH="$weston_prefix/bin:$PATH"
                export LD_LIBRARY_PATH="$weston_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
        esac
        renderer=pixman
        [ -z "${MAGICDESK_MESA_PREFIX:-}" ] || renderer=gl
        mkdir -p -m 1777 /tmp/.X11-unix
        set -- weston --backend=wayland --renderer="$renderer" --shell=desktop-shell.so --xwayland "$@" ;;
    gnome)
        export XDG_SESSION_TYPE=wayland XDG_CURRENT_DESKTOP=GNOME
        set -- gnome-shell --devkit "$@" ;;
    plasma-x11|plasma-wayland)
        export XDG_CURRENT_DESKTOP=KDE XDG_SESSION_DESKTOP=KDE KDE_FULL_SESSION=true KDE_SESSION_VERSION=6
        unset WAYLAND_SOCKET
        mkdir -p -m 1777 /tmp/.X11-unix
        mkdir -p "$HOME/.config"
        kwriteconfig6 --file startkderc --group General --key systemdBoot false
        if [ "$desktop" = plasma-x11 ]; then
            unset WAYLAND_DISPLAY
            export XDG_SESSION_TYPE=x11 QT_QPA_PLATFORM=xcb
            if [ "${LIBGL_ALWAYS_SOFTWARE:-}" = 1 ]; then
                export QT_QUICK_BACKEND=software
            fi
            set -- startplasma-x11 "$@"
        else
            unset DISPLAY
            export XDG_SESSION_TYPE=wayland QT_QPA_PLATFORM=wayland
            if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
                [ -r /etc/magicdesk/plasma-kwin.sh ] || {
                    echo 'Complete Plasma Turnip setup before launching the Wayland desktop.' >&2; exit 1;
                }
                . /etc/magicdesk/plasma-kwin.sh
                [ -x "$kwin_prefix/bin/kwin_wayland" ] || exit 1
                export PATH="$kwin_prefix/bin:$PATH"
                export LD_LIBRARY_PATH="$kwin_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
                export QT_PLUGIN_PATH="$kwin_prefix/lib/qt6/plugins${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
                export QML_IMPORT_PATH="$kwin_prefix/lib/qt6/qml${QML_IMPORT_PATH:+:$QML_IMPORT_PATH}"
                export XDG_DATA_DIRS="$kwin_prefix/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
            else
                # The stock nested compositor has no DRM output in this session.
                export KWIN_COMPOSE=Q QT_QUICK_BACKEND=software
            fi
            set -- startplasma-wayland "$@"
        fi ;;
    *) echo "Unknown desktop: $desktop" >&2; exit 2 ;;
esac
# Reuse the launcher's bus. Direct guest-console launches get the same contract.
if [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    exec magicdesk-audio-session "$@"
fi
exec dbus-run-session -- magicdesk-audio-session "$@"
DESKTOP
}

audio_session() {
    cat <<'AUDIO'
#!/bin/bash
set -euo pipefail
if [[ ${1:-} == --ready ]]; then
    printf '%s\n' "$2" >&3
    exit
fi
[[ $# != 0 ]] || { echo 'Expected desktop command.' >&2; exit 2; }
[[ -n ${MAGICDESK_AUDIO_PULSE:-} ]] || exec "$@"
[[ ${MAGICDESK_AUDIO_SESSION:-} != active ]] || exec "$@"
# Native scheduling remains available; this session does not provide RTKit.
export DISABLE_RTKIT=1
host=$MAGICDESK_AUDIO_PULSE
[[ $host == /* && $host != *$'\n'* && $host != *$'\r'* ]] || {
    echo 'Invalid Android audio endpoint.' >&2; exit 2;
}
work=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/magicdesk-audio.XXXXXXXX")
children=()
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    # EVENT_WAIT: release clients before their server; wait owns only our child processes.
    for (( i=${#children[@]}-1; i>=0; i-- )); do
        kill "${children[i]}" 2>/dev/null || :
        wait "${children[i]}" 2>/dev/null || :
    done
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/config/pipewire.conf.d" "$work/config/pipewire-pulse.conf.d" "$work/wp/wireplumber.conf.d"
cp /usr/share/pipewire/pipewire.conf /usr/share/pipewire/pipewire-pulse.conf "$work/config/"
cp /usr/share/wireplumber/wireplumber.conf "$work/wp/"
if [[ -d /usr/share/wireplumber/main.lua.d ]]; then
    # WirePlumber 0.4 (Ubuntu 24.04) uses Lua configuration, not feature profiles.
    for part in main.lua.d policy.lua.d bluetooth.lua.d common; do
        # Private editable configuration needs links/content, not package owners.
        cp -R -P "/usr/share/wireplumber/$part" "$work/wp/"
    done
    cat > "$work/wp/main.lua.d/80-magicdesk.lua" <<'LUA'
alsa_monitor.enabled = false
v4l2_monitor.enabled = false
libcamera_monitor.enabled = false
LUA
    cat > "$work/wp/bluetooth.lua.d/80-magicdesk.lua" <<'LUA'
bluez_monitor.enabled = false
bluez_midi_monitor.enabled = false
LUA
fi
host=unix:${host//\\/\\\\}
host=${host//\"/\\\"}
cat > "$work/config/pipewire.conf.d/90-magicdesk.conf" <<CONFIG
# The guest graph has no hardware clock or guaranteed real-time scheduling.
# Keep a bounded scheduling budget even when a client requests a tiny quantum.
context.properties = { default.clock.rate = 48000 default.clock.min-quantum = 1024 mem.allow-mlock = false }
context.exec = [ { path = /usr/local/bin/magicdesk-audio-session args = "--ready core" } ]
CONFIG
# Keep the remote tunnel in a client context, not a core-to-itself connection.
cat > "$work/config/pipewire-pulse.conf.d/90-magicdesk.conf" <<CONFIG
pulse.properties = { pulse.min.req = 1024/48000 pulse.min.quantum = 1024/48000 }
context.modules = [
  { name = libpipewire-module-pulse-tunnel args = {
      tunnel.mode = sink
      pulse.server.address = "$host"
      pulse.latency = 60
      audio.rate = 48000
      audio.channels = 2
      audio.position = [ FL FR ]
      stream.props = {
        node.name = magicdesk.android
        node.description = "Android audio"
        # This is the guest's output device, not an internal routing node.
        node.virtual = false
      }
  } }
]
context.exec = [ { path = /usr/local/bin/magicdesk-audio-session args = "--ready pulse" } ]
CONFIG
cat > "$work/wp/wireplumber.conf.d/90-magicdesk.conf" <<'CONFIG'
wireplumber.profiles = {
  main = {
    monitor.alsa = disabled monitor.alsa-midi = disabled
    monitor.bluez = disabled monitor.bluez-midi = disabled
    monitor.v4l2 = disabled monitor.libcamera = disabled
  }
}
CONFIG
export PIPEWIRE_RUNTIME_DIR=$work PULSE_RUNTIME_PATH=$work/pulse
export PIPEWIRE_REMOTE=pipewire-0 PULSE_SERVER=unix:$work/pulse/native
export MAGICDESK_AUDIO_SESSION=active
mkfifo "$work/ready"
exec 3<>"$work/ready"
PIPEWIRE_CONFIG_DIR=$work/config pipewire &
children+=("$!")
# EVENT_WAIT: PipeWire context.exec startup receipt; expiry tears down this session.
read -r -t 15 receipt <&3 && [[ $receipt == core ]] || {
    echo 'Guest PipeWire startup failed.' >&2; exit 1;
}
WIREPLUMBER_CONFIG_DIR=$work/wp wireplumber 3>&- &
children+=("$!")
PIPEWIRE_CONFIG_DIR=$work/config pipewire-pulse &
children+=("$!")
# EVENT_WAIT: Pulse protocol server initialization, not a fixed startup delay.
read -r -t 15 receipt <&3 && [[ $receipt == pulse ]] || {
    echo 'Guest Pulse compatibility startup failed.' >&2; exit 1;
}
# EVENT_WAIT: the policy manager publishes both output ports; expiry rejects startup.
# A listening server alone does not mean that its sink has been configured.
exec 4< <(pw-link --input --monitor 3>&-)
monitor=$!
children+=("$monitor")
left=0 right=0 deadline=$((SECONDS + 15))
while (( !left || !right )); do
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) && IFS= read -r -t "$remaining" port <&4 || {
        echo 'Guest Android audio sink was not configured.' >&2; exit 1;
    }
    case $port in
        *magicdesk.android:*_FL) left=1 ;;
        *magicdesk.android:*_FR) right=1 ;;
    esac
done
exec 4<&-
kill "$monitor" 2>/dev/null || :
wait "$monitor" 2>/dev/null || :
unset 'children[-1]'
"$@" <&0 3>&- &
children+=("$!")
# EVENT_WAIT: desktop command lifetime; signal traps stop all owned audio services.
status=0
wait "${children[-1]}" || status=$?
unset 'children[-1]'
exit "$status"
AUDIO
}

steam_game() {
    cat <<'STEAM_GAME'
#!/usr/bin/env python3
"""Steam Launch Options: magicdesk-steam-game %command%."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


CONTAINER = r'''
set -eu
# FEX's empty-root lookup is relative to cwd; the container root is explicit.
if [ "${FEX_ROOTFS-unset}" = "" ]; then export FEX_ROOTFS=/; fi
if [ -n "${MAGICDESK_MESA_PREFIX:-}" ]; then
    export LD_LIBRARY_PATH="$MAGICDESK_MESA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LIBGL_DRIVERS_PATH="$MAGICDESK_MESA_PREFIX/lib/dri${LIBGL_DRIVERS_PATH:+:$LIBGL_DRIVERS_PATH}"
fi
exec "$@"
'''


def launch(command):
    if not command:
        raise ValueError('Use magicdesk-steam-game %command% in Steam Launch Options')
    if 'PRESSURE_VESSEL_EMULATOR' not in os.environ:
        # Steam declares its selected tools. argv also covers launchers that omit
        # that variable; never guess the user's Steam library location.
        directories = [Path(p) for p in os.environ.get('STEAM_COMPAT_TOOL_PATHS', '').split(':') if p]
        directories += [Path(p).parent for p in command if os.path.isabs(p)]
        for directory in dict.fromkeys(directories):
            source = directory / 'emulator.json'
            if not source.is_file():
                continue
            manifest = json.loads(source.read_text())
            emulator = manifest.get('emulator_v0', {})
            if 'FEX_ROOTFS' not in emulator.get('container_environment', {}):
                continue
            for key in ('argv', 'container_argv', 'main_argv', 'server_argv'):
                value = emulator.get(key)
                if value is None:
                    continue
                if isinstance(value, str):
                    value = [value]
                if not isinstance(value, list) or not value or not all(isinstance(p, str) for p in value):
                    raise ValueError('Invalid emulator command: ' + key)
                if not os.path.isabs(value[0]):
                    value[0] = str((directory / value[0]).absolute())
                emulator[key] = value
            for key in ('container_argv', 'main_argv'):
                # pressure-vessel maps this native host executable into /run/host.
                emulator[key] = ['/usr/bin/sh', '-c', CONTAINER,
                                 'magicdesk-steam-container', *emulator[key]]
            # SteamOS /bin/sh is Bash; its dependency must be captured with FEX's.
            emulator['required_libraries'] = list(dict.fromkeys([
                *emulator.get('required_libraries', []), 'libreadline.so.8']))
            data = json.dumps(manifest, sort_keys=True, indent=2).encode() + b'\n'
            cache = Path(os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache') / 'magicdesk/steam-fex'
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = cache / (hashlib.sha256(data).hexdigest() + '.json')
            if not target.is_file():
                fd, temporary = tempfile.mkstemp(dir=cache)
                try:
                    with os.fdopen(fd, 'wb') as output:
                        output.write(data)
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            os.environ['PRESSURE_VESSEL_EMULATOR'] = str(target)
            break
    os.execvp(command[0], command)


try:
    launch(sys.argv[1:])
except (OSError, ValueError, KeyError, TypeError) as error:
    sys.exit('magicdesk-steam-game: ' + str(error))
STEAM_GAME
}

system_setup() {
    distribution_support
    printf "install_desktop_session() {\ncat > /usr/local/bin/magicdesk-desktop-session <<'MD_DESKTOP_SESSION'\n"
    desktop_session
    cat <<'MD_DESKTOP_INSTALL'
MD_DESKTOP_SESSION
chmod 755 /usr/local/bin/magicdesk-desktop-session
# Normally created by tmpfiles at boot; direct non-root desktop launches need
# the same root-owned shared socket directories without booting the OS.
install -d -o root -g root -m 1777 /tmp/.X11-unix /tmp/.ICE-unix
mkdir -p /etc/magicdesk/root-session/autostart
cat > /etc/magicdesk/root-session/autostart/xfce-polkit.desktop <<'MD_ROOT_AGENT'
[Desktop Entry]
Type=Application
Name=XFCE PolKit
Hidden=true
MD_ROOT_AGENT
}
MD_DESKTOP_INSTALL
    printf "install_audio_session() {\ncat > /usr/local/bin/magicdesk-audio-session <<'MD_AUDIO_SESSION'\n"
    audio_session
    printf 'MD_AUDIO_SESSION\nchmod 755 /usr/local/bin/magicdesk-audio-session\n}\n'
    printf "install_steam_game() {\ncat > /usr/local/bin/magicdesk-steam-game <<'MD_STEAM_GAME'\n"
    steam_game
    printf 'MD_STEAM_GAME\nchmod 755 /usr/local/bin/magicdesk-steam-game\n}\n'
    cat <<'SETUP'
gui=$1
protocol=$2
locale_name=$3
zone=$4
new_user=$5
fonts=$6
cache=$7
extras=$8
# Minimal images may need util-linux first; package managers own their bootstrap locks.
setup_locked=no
if command -v flock >/dev/null 2>&1; then
    mkdir -p /var/lib/magicdesk
    exec 9>/var/lib/magicdesk/installer.lock
    flock -n 9 || { echo 'Another environment setup is running.' >&2; exit 1; }
    setup_locked=yes
fi
trap 'status=$?; package_cleanup; exit "$status"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
case "$family" in
    apt)
        if [ "$locale_name" != keep ] && [ "$locale_name" != C.UTF-8 ]; then
            # Slim images exclude translations from newly installed GUI packages.
            printf 'path-include /usr/share/locale/*\n' > /etc/dpkg/dpkg.cfg.d/zz-magicdesk-locales
        fi
        # Package services belong to Linux, not Android's service manager.
        if [ ! -e /usr/sbin/policy-rc.d ]; then
            printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
            chmod 755 /usr/sbin/policy-rc.d
        fi
        dpkg --configure -a </dev/null
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata locales passwd ;;
    apk)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata musl-locales musl-locales-lang lang shadow ;;
    dnf) packages ca-certificates bash coreutils util-linux tzdata glibc-langpack-en shadow-utils ;;
    zypper)
        refresh_packages
        packages ca-certificates bash coreutils util-linux timezone glibc-locale glibc-i18ndata shadow ;;
    xbps)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata glibc-locales shadow ;;
    pacman)
        refresh_packages
        packages ca-certificates bash coreutils util-linux tzdata gzip ;;
    recovery)
        refresh_packages
        dbus-uuidgen --ensure ;;
esac
mkdir -p /var/lib/magicdesk /etc/profile.d /usr/local/bin /usr/local/share/applications
if [ "$family" = recovery ]; then
    mkdir -p /opt/magicdesk
    cat > /opt/magicdesk/fex-thunks.json <<'FEX_DEFAULTS'
{"ThunksDB":{"GL":"1","Vulkan":"1"}}
FEX_DEFAULTS
    install_steam_game
fi
if [ "$setup_locked" = no ]; then
    exec 9>/var/lib/magicdesk/installer.lock
    flock -n 9 || { echo 'Another environment setup is running.' >&2; exit 1; }
fi

if [ "$zone" != keep ]; then
    [ -f "/usr/share/zoneinfo/$zone" ] || { echo "Unknown timezone: $zone" >&2; exit 1; }
    ln -sfn "/usr/share/zoneinfo/$zone" /etc/localtime
    printf '%s\n' "$zone" > /etc/timezone
fi
if [ "$locale_name" != keep ]; then
    if [ "$locale_name" != C.UTF-8 ]; then
        language=${locale_name%%_*}
        case "$family" in
            apt|pacman|recovery|zypper|xbps) localedef -i "${locale_name%.UTF-8}" -f UTF-8 "$locale_name" ;;
            dnf) packages "glibc-langpack-$language" ;;
            apk)
                MUSL_LOCPATH=/usr/share/i18n/locales/musl locale -a | grep -Fqx "${locale_name%.UTF-8}" || {
                    echo "Locale not supplied by musl-locales: $locale_name" >&2; exit 1;
                } ;;
        esac
    fi
    # The selected guest locale must not be masked by Android Shell's LC_ALL.
    printf 'unset LC_ALL\nexport LANG=%s\n' "$locale_name" > /etc/profile.d/magicdesk-locale.sh
    printf 'LANG=%s\n' "$locale_name" > /etc/locale.conf
fi
if [ -n "$new_user" ]; then
    if getent passwd "$new_user" >/dev/null; then
        [ "$(id -u "$new_user")" -ge 1000 ] || {
            echo "Refusing to reuse system account: $new_user" >&2; exit 1;
        }
        printf 'Retaining existing account and home: %s\n' "$new_user"
    else
        useradd -m -U -s /bin/bash "$new_user"
    fi
fi

# Keep the selected desktops on resume, but refresh their shared launch services.
gui_services=no
if { [ "$gui" != none ] && [ "$gui" != keep ]; } || [ -x /usr/local/bin/magicdesk-audio-session ]; then
    gui_services=yes
    case "$family" in
        apt) packages pipewire pipewire-bin pipewire-pulse wireplumber pipewire-alsa pulseaudio-utils \
            libsdl2-2.0-0 libudev1 libdecor-0-plugin-1-cairo ;;
        apk) packages pipewire pipewire-pulse pipewire-tools wireplumber pipewire-alsa pulseaudio-utils \
            sdl2 eudev-libs libdecor ;;
        dnf) packages pipewire pipewire-pulseaudio pipewire-utils wireplumber pipewire-alsa pulseaudio-utils \
            sdl2-compat systemd-libs libdecor ;;
        pacman|recovery)
            udev_package=systemd-libs
            sdl_package=sdl2
            if [ "$ID" = artix ]; then udev_package=libudev; sdl_package=sdl2-compat; fi
            packages pipewire pipewire-pulse wireplumber pipewire-alsa libpulse \
                "$sdl_package" "$udev_package" libdecor ;;
        zypper) packages pipewire pipewire-pulseaudio pipewire-tools wireplumber pipewire-alsa pulseaudio-utils \
            libSDL2-2_0-0 libudev1 libdecor ;;
        xbps) packages pipewire wireplumber alsa-pipewire pulseaudio-utils SDL2 eudev-libudev libdecor ;;
    esac
    install_audio_session
    install_desktop_session
    case "$ID" in
        steamos) ;;
        openkylin) packages pavucontrol-qt ;;
        *) packages pavucontrol ;;
    esac
    if [ "$gui" = xfce ] || [ -f /usr/local/share/applications/magicdesk-xfce.desktop ]; then
        packages xfce4-pulseaudio-plugin
    fi
    if [ "$gui" = plasma ] || [ -f /usr/local/share/applications/magicdesk-plasma-wayland.desktop ]; then
        packages plasma-pa
    fi
fi
if [ "$gui" != none ] && [ "$gui" != keep ]; then
    case "$family" in
        apt) packages dbus-x11 xkb-data adwaita-icon-theme mousepad thunar xfce4-terminal \
            libgl1-mesa-dri libegl-mesa0 libglx-mesa0 libegl1 libgl1 libgles2 ;;
        apk) packages dbus dbus-x11 xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal \
            mesa-dri-gallium mesa-egl mesa-gl ;;
        dnf) packages dbus-daemon dbus-x11 xkeyboard-config adwaita-icon-theme mousepad Thunar xfce4-terminal \
            mesa-dri-drivers mesa-libEGL mesa-libGL ;;
        pacman) packages dbus xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal mesa ;;
        zypper) packages dbus-1-daemon dbus-1-tools xkeyboard-config adwaita-icon-theme mousepad thunar xfce4-terminal \
            Mesa-dri Mesa-libEGL1 Mesa-libGL1 ;;
        xbps) packages dbus xkeyboard-config adwaita-icon-theme mousepad Thunar xfce4-terminal \
            mesa-dri mesa ;;
    esac
    dbus-uuidgen --ensure
    case "$gui:$family" in
        xfce:apt|xfce:apk|xfce:pacman) packages xfce4 ;;
        xfce:dnf|xfce:zypper|xfce:xbps) packages xfce4-session xfce4-panel xfce4-settings xfce4-appfinder xfdesktop xfwm4 ;;
        weston:apk) packages weston weston-shell-desktop weston-backend-wayland weston-clients weston-xwayland xwayland ;;
        weston:apt) packages weston xwayland ;;
        weston:dnf) packages weston xorg-x11-server-Xwayland ;;
        weston:pacman) packages weston xorg-xwayland ;;
        weston:zypper) packages weston xwayland ;;
        weston:xbps) packages weston xorg-server-xwayland ;;
        plasma:apt) packages plasma-desktop plasma-workspace kwin-wayland kwin-x11 \
            dolphin konsole kdialog breeze xwayland qml6-module-qtquick-controls \
            qml6-module-qtquick-layouts qml6-module-qtquick-window ;;
        gnome:dnf) packages gnome-shell mutter-devkit gnome-terminal nautilus gnome-text-editor ;;
    esac
fi
if [ "$gui_services" = yes ]; then
    # Recovery images can ship Flatpak without an initialized system repo.
    # Prepare it as root before desktop notifiers try to monitor it as a user.
    if command -v flatpak >/dev/null 2>&1 && [ ! -f /var/lib/flatpak/repo/config ]; then
        echo 'Initializing the system Flatpak repository...'
        flatpak repair --system
    fi

    # Scheduling policy is launch-scoped, not a replacement for distro config.
    for config in client.conf client-rt.conf; do
        rm -f "/etc/pipewire/$config.d/90-magicdesk-scheduling.conf"
    done

    # VLC's relocatable Linux build guesses its plugin directory from native
    # /proc/self/maps. Object-backed stores need its explicit search path.
    mkdir -p /etc/profile.d
    cat > /etc/profile.d/magicdesk-applications.sh <<'APPLICATIONS'
# No realtime portal/RTKit service; PipeWire may still use native scheduling.
export DISABLE_RTKIT=1
if [ "${VLC_PLUGIN_PATH+x}" != x ]; then
    for _md_lib in /usr/lib /usr/lib64 /usr/lib/*-linux-gnu; do
        if [ -d "$_md_lib/vlc/plugins" ]; then
            export VLC_PLUGIN_PATH=$_md_lib/vlc/plugins
            break
        fi
    done
    unset _md_lib
fi
APPLICATIONS

fi
if [ "$gui" != none ] && [ "$gui" != keep ]; then
    # Protocol-specific entries are ours; distribution/user launchers are never rewritten.
    for backend in x11 wayland; do
        apps='mousepad thunar terminal'
        [ "$family" != recovery ] || apps=
        for app in $apps; do
            entry=/usr/local/share/applications/magicdesk-$app-$backend.desktop
            if [ "$protocol" != both ] && [ "$protocol" != "$backend" ]; then
                rm -f "$entry"
                continue
            fi
            case "$app" in
                mousepad) title=Mousepad; cmd='mousepad --disable-server %F'; icon=org.xfce.mousepad ;;
                thunar) title=Thunar; cmd='thunar %F'; icon=org.xfce.thunar ;;
                terminal) title='Xfce Terminal'; cmd='xfce4-terminal --disable-server'; icon=org.xfce.terminal ;;
            esac
            printf '[Desktop Entry]\nType=Application\nName=%s (%s)\nExec=env GDK_BACKEND=%s %s\nIcon=%s\nTerminal=false\nCategories=Utility;\nX-MagicDesk-Graphics=%s\n' \
                "$title" "$backend" "$backend" "$cmd" "$icon" "$backend" > "$entry"
        done
    done
    if [ ! -e /etc/profile.d/magicdesk-graphics.sh ]; then
        printf 'export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe\n' > /etc/profile.d/magicdesk-graphics.sh
    fi
    if [ "$family" != recovery ]; then
        command -v mousepad
        command -v thunar
        command -v xfce4-terminal
    fi
fi

if [ "$gui_services" = yes ]; then
    # Refresh only installer-owned entries that exist or were explicitly selected.
    for desktop in xfce weston gnome plasma-x11 plasma-wayland; do
        entry=/usr/local/share/applications/magicdesk-$desktop.desktop
        [ "$gui" = "${desktop%%-*}" ] || [ -f "$entry" ] || continue
        case "$desktop" in
            xfce) title='Xfce Desktop'; backend=x11; icon=org.xfce.xfdesktop; program=xfce4-session ;;
            weston) title='Weston Desktop'; backend=wayland; icon=computer; program=weston ;;
            gnome) title='GNOME Shell (development kit)'; backend=wayland; icon=computer; program=gnome-shell ;;
            plasma-*) backend=${desktop#plasma-}; title="Plasma Desktop ($backend)"; icon=preferences-desktop; program=startplasma-$backend ;;
        esac
        command -v "$program"
        printf '[Desktop Entry]\nType=Application\nName=%s - %s\nExec=magicdesk-desktop-session %s\nIcon=%s\nTerminal=false\nCategories=System;\nX-MagicDesk-Graphics=%s\nX-MagicDesk-GraphicsMode=desktop\n' \
            "${NAME:-$ID}" "$title" "$desktop" "$icon" "$backend" > "$entry"
    done
    rm -f /usr/local/bin/magicdesk-plasma /usr/local/bin/magicdesk-weston
fi

if [ "$fonts" != keep ]; then
    case "$family" in
        apt) packages fonts-dejavu-core; [ "$fonts" != cjk ] || packages fonts-noto-cjk ;;
        apk) packages font-dejavu; [ "$fonts" != cjk ] || packages font-noto-cjk ;;
        dnf) packages dejavu-sans-fonts; [ "$fonts" != cjk ] || packages google-noto-sans-cjk-fonts ;;
        pacman) packages ttf-dejavu; [ "$fonts" != cjk ] || packages noto-fonts-cjk ;;
        zypper) packages dejavu-fonts; [ "$fonts" != cjk ] || packages google-noto-sans-cjk-fonts ;;
        xbps) packages dejavu-fonts-ttf; [ "$fonts" != cjk ] || packages noto-fonts-cjk ;;
    esac
fi
# Names were validated before any image mutation; no evaluation of package text.
if [ -n "$extras" ]; then
    set -f
    packages $extras
    set +f
fi
if [ "$cache" = clean ]; then
    case "$family" in
        apt) apt-get clean ;;
        apk) rm -f /var/cache/apk/*.apk ;;
        dnf) dnf clean packages ;;
        pacman) pacman -Sc --noconfirm </dev/null ;;
        zypper) zypper --non-interactive clean ;;
        xbps) xbps-remove -Oy ;;
    esac
fi
SETUP
}

recovery_reader() {
    cat <<'READER'
import base64
import bz2
import hashlib
import io
import json
import mmap
from pathlib import Path
import stat
import struct
import sys
import tarfile
import zlib


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('Truncated recovery image')
    return data


def partition_table(stream):
    header = bytearray(exact(stream, 1024)[512:])
    if header[:8] != b'EFI PART':
        raise ValueError('Expected a GPT recovery image')
    size, checksum = struct.unpack_from('<II', header, 12)
    if not 92 <= size <= 512:
        raise ValueError('Invalid GPT header length')
    struct.pack_into('<I', header, 16, 0)
    if zlib.crc32(header[:size]) != checksum:
        raise ValueError('GPT header checksum mismatch')
    first, last = struct.unpack_from('<QQ', header, 40)
    lba, count, stride, crc = struct.unpack_from('<QIII', header, 72)
    if lba != 2 or not 1 <= count <= 4096 or stride != 128:
        raise ValueError('Unsupported GPT entry layout')
    table = exact(stream, count * stride)
    if zlib.crc32(table) != crc:
        raise ValueError('GPT table checksum mismatch')
    parts = {}
    ranges = []
    for i in range(count):
        entry = table[i * stride:(i + 1) * stride]
        if entry[:16] == bytes(16):
            continue
        start, end = struct.unpack_from('<QQ', entry, 32)
        name = entry[56:128].decode('utf-16-le').rstrip('\0')
        if not first <= start <= end <= last or name in parts:
            raise ValueError('Invalid or duplicate GPT partition')
        parts[name] = (start * 512, (end - start + 1) * 512)
        ranges.append((start, end))
    ranges.sort()
    if any(a[1] >= b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping GPT partitions')
    return parts, 1024 + len(table)


def extract_root(archive, target):
    with bz2.open(archive, 'rb') as source:
        parts, offset = partition_table(source)
        start, size = parts['rootfs-A']
        if start < offset or size > 16 * 1024**3:
            raise ValueError('Unsupported recovery root partition')
        print(f'Reading rootfs-A: {size // 1024**2} MiB', flush=True)
        while offset < start:
            offset += len(exact(source, min(start - offset, 4 * 1024**2)))
        with target.open('xb') as output:
            remaining = size
            while remaining:
                block = exact(source, min(remaining, 4 * 1024**2))
                output.write(block)
                remaining -= len(block)
                if (size - remaining) % (256 * 1024**2) == 0 or not remaining:
                    print(f'Read {(size - remaining) // 1024**2}/{size // 1024**2} MiB', flush=True)
        # Consume the tail: a complete bzip2 stream, not just a readable partition.
        while source.read(4 * 1024**2):
            pass


def acl_text(value):
    if len(value) < 4 or struct.unpack_from('<I', value)[0] != 2 or (len(value) - 4) % 8:
        raise ValueError('Invalid POSIX ACL')
    names = {1: 'user', 2: 'user', 4: 'group', 8: 'group', 16: 'mask', 32: 'other'}
    entries = []
    for tag, perm, identifier in struct.iter_unpack('<HHI', value[4:]):
        if tag not in names or perm > 7:
            raise ValueError('Invalid POSIX ACL entry')
        who = str(identifier) if tag in (2, 8) else ''
        mode = ''.join(c if perm & bit else '-' for c, bit in [('r', 4), ('w', 2), ('x', 1)])
        entries.append(f'{names[tag]}:{who}:{mode}')
    return ','.join(entries)


def xattrs(node):
    from dissect.btrfs.c_btrfs import c_btrfs
    for _, data in node.subvolume.tree.cursor().iter(
            node.inum, c_btrfs.BTRFS_XATTR_ITEM_KEY, 0, ignore_offset=True):
        stream = io.BytesIO(data)
        while stream.tell() < len(data):
            item = c_btrfs.btrfs_dir_item(stream)
            yield item.name.decode('utf-8'), item.data


def metadata(node, name):
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(node.mode)
    info.uid, info.gid = node.uid, node.gid
    info.mtime = node.mtime_ns // 10**9
    for field in ('mtime', 'atime'):
        value = getattr(node, field + '_ns')
        seconds, nanos = divmod(abs(value), 10**9)
        info.pax_headers[field] = f'{"-" if value < 0 else ""}{seconds}.{nanos:09d}'
    for key, value in xattrs(node):
        if key == 'btrfs.compression':
            continue  # Filesystem storage policy, not a userspace file attribute.
        if key in ('system.posix_acl_access', 'system.posix_acl_default'):
            info.pax_headers['SCHILY.acl.' + key.rsplit('_', 1)[1]] = acl_text(value)
        elif key == 'security.capability':
            info.pax_headers['LIBARCHIVE.xattr.' + key] = base64.b64encode(value).decode()
        else:
            raise ValueError(f'Unsupported image attribute {key} on {name}')
    return info


def children(node):
    return {name: child for name, child in node.iterdir() if name not in ('.', '..')}


def export_tree(archive, node, path='', fallback=None, links=None, factory=False):
    links = {} if links is None else links
    name = path or '.'
    info = metadata(node, name)
    kind = stat.S_IFMT(node.mode)
    if kind == stat.S_IFDIR:
        info.type = tarfile.DIRTYPE
    elif kind == stat.S_IFLNK:
        info.type, info.linkname = tarfile.SYMTYPE, node.link
    elif kind == stat.S_IFIFO:
        info.type = tarfile.FIFOTYPE
    elif kind == stat.S_IFREG:
        key = (factory, node.subvolume.objectid, node.inum)
        if key in links:
            info.type, info.linkname = tarfile.LNKTYPE, links[key]
        else:
            info.size = node.size
            links[key] = name
    else:
        raise ValueError(f'Unsupported file type {oct(kind)} at {name}')
    if info.isreg():
        with node.open() as source:
            archive.addfile(info, source)
    else:
        archive.addfile(info)
    if len(archive.members) % 5000 == 0:
        print(f'Exported {len(archive.members)} entries: /{name}', flush=True)
    if kind == stat.S_IFDIR:
        entries = children(node)
        defaults = children(fallback) if fallback else {}
        for child in sorted(entries.keys() | defaults.keys()):
            if not child or '/' in child or '\0' in child or child.startswith('.wh.'):
                raise ValueError('Invalid filesystem name')
            primary = entries.get(child)
            secondary = defaults.get(child)
            if primary is None:
                # Factory contents are copies, not aliases of /usr/share/factory.
                export_tree(archive, secondary, f'{path}/{child}'.lstrip('/'), links=links, factory=True)
            else:
                if not (primary.is_dir() and secondary and secondary.is_dir()):
                    secondary = None
                export_tree(archive, primary, f'{path}/{child}'.lstrip('/'), secondary, links, factory)


class HashWriter:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def write(self, data):
        self.digest.update(data)
        return self.stream.write(data)


def json_blob(directory, value, media):
    data = json.dumps(value, separators=(',', ':')).encode()
    digest = hashlib.sha256(data).hexdigest()
    (directory / digest).write_bytes(data)
    return {'mediaType': media, 'digest': 'sha256:' + digest, 'size': len(data)}


def convert(image, destination):
    from compression import zstd
    from dissect.btrfs import Btrfs
    blobs = destination / 'blobs/sha256'
    blobs.mkdir(parents=True)
    layer = destination / 'layer.tmp'
    with image.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        fs = Btrfs(mapped)
        release = fs.get('/etc/os-release').open().read().decode()
        if '\nID=steamos\n' not in release or '\nVERSION_ID=0.3.0\n' not in release:
            raise ValueError('Unexpected SteamOS release')
        with zstd.open(layer, 'wb', level=3) as compressed:
            writer = HashWriter(compressed)
            with tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                # Recovery /var contains reimaging tools. Populate the installed
                # userspace from rootfs and its factory defaults instead.
                root = fs.get('/')
                info = metadata(root, '.')
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                links = {}
                for name, node in sorted(children(root).items()):
                    print(f'Exporting /{name}', flush=True)
                    default = fs.get('/usr/share/factory/var') if name == 'var' else None
                    export_tree(tar, node, name, default, links)
        diff_id = writer.digest.hexdigest()
    with layer.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    length = layer.stat().st_size
    layer.rename(blobs / digest)
    config = json_blob(blobs, {
        'architecture': 'arm64', 'os': 'linux',
        'config': {'User': 'steamos', 'WorkingDir': '/home/steamos', 'Cmd': ['/bin/bash'],
                   'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/bin', 'HOME=/home/steamos'],
                   'Labels': {'org.opencontainers.image.title': 'SteamOS ARM64',
                              'org.opencontainers.image.version': '0.3.0',
                              'io.github.mekhontsev.magicdesk.recovery.sha256':
                              '3a4a077f1b1f40688ab3279affcb56776bd97c54db1573e7c65fc52a97106676'}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + diff_id]}},
        'application/vnd.oci.image.config.v1+json')
    manifest = json_blob(blobs, {'schemaVersion': 2, 'config': config, 'layers': [{
        'mediaType': 'application/vnd.oci.image.layer.v1.tar+zstd',
        'digest': 'sha256:' + digest, 'size': length}]},
        'application/vnd.oci.image.manifest.v1+json')
    (destination / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    (destination / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
    print(f'Local SteamOS image ready: {length // 1024**2} MiB', flush=True)


if __name__ == '__main__':
    archive, work = Path(sys.argv[1]), Path(sys.argv[2])
    image = work / 'rootfs.img'
    extract_root(archive, image)
    convert(image, work / 'oci')
    image.unlink()
READER
}

download_verified() {
    file="$downloads/${1##*/}"
    if [ -f "$file" ] && [ ! -L "$file" ]; then
        actual=$(sha256sum "$file"); actual=${actual%% *}
        if [ "$actual" = "$2" ]; then printf 'Using verified %s\n' "$file"; return; fi
    fi
    magicdesk download "$1" "$file" --sha256 "$2"
}

import_helper() { MAGICDESK_GUEST_HOME="$import_work/library" shroot "$@"; }

prepare_downloads() {
    environments=$(shroot list)
    if printf '%s\n' "$environments" | cut -f1 | grep -Fxq "$name"; then
        fail "Environment $name already exists; use --resume to continue setup."
    fi
    downloads=${downloads:-${HOME:?}/downloads}
    mkdir -p "$downloads"
    downloads=$(cd "$downloads" && pwd -P)
}

prepare_import_helper() {
    work_parent=${TMPDIR:-$HOME/.cache}
    mkdir -p "$work_parent"
    work_parent=$(cd "$work_parent" && pwd -P)
    case "$work_parent/" in "$downloads/"*) fail 'Temporary work must be outside the read-only download cache.' ;; esac
    import_work=$(mktemp -d "$work_parent/magicdesk-import-XXXXXX")
    mkdir "$import_work/exchange"
    # Validate the selected DNS policy before fetching the multi-GB recovery archive.
    stage='preparing the temporary Python environment'
    import_helper install 'python@sha256:fe368aeff9df1995b57f0aa9bbced949a2a98fb3e6dfd92568e5f6acea6220f7' --name unpack --dns "$dns"
}

prepare_rootfs() {
    prepare_downloads
    stage="downloading the official $distro rootfs"
    download_verified "$source" "$source_sha"
    image="$downloads/${source##*/}"
    case "$source" in
        *.xz)
            prepare_import_helper
            stage='decompressing the rootfs archive'
            # Only change compression. Native import owns tar validation and metadata.
            import_helper exec unpack --bind "$import_work/exchange" /mnt --bind-ro "$downloads" /media \
                -- /usr/local/bin/python3 -c '
import gzip, lzma, shutil, sys
with lzma.open(sys.argv[1], "rb") as source, gzip.open(sys.argv[2], "wb", compresslevel=1) as target:
    shutil.copyfileobj(source, target, 1024 * 1024)
' "/media/${source##*/}" /mnt/rootfs.tar.gz
            image="$import_work/exchange/rootfs.tar.gz" ;;
    esac
}

prepare_recovery() {
    prepare_downloads
    prepare_import_helper
    stage='downloading the official SteamOS recovery image'
    download_verified "$source" '3a4a077f1b1f40688ab3279affcb56776bd97c54db1573e7c65fc52a97106676'
    stage='downloading pinned filesystem readers'
    download_verified 'https://files.pythonhosted.org/packages/a8/24/717afae59efd76fb85d882af52eeea827207776dd8bfdcd24916a0de5288/dissect_btrfs-1.10-py3-none-any.whl' '22569fba43c1740aa998544998beee09b599ff95f45d4fe3e05a47fac689d938'
    download_verified 'https://files.pythonhosted.org/packages/37/1c/dc626b1b0e477546c8e80d8cb028442ef4602af276c405f7a5ccc85b0b5a/dissect_cstruct-4.7-py3-none-any.whl' '0427621ce67baa3106df2dc63a320d0a7f5c2da88ba3faf2ef5886a1a6b458fd'
    download_verified 'https://files.pythonhosted.org/packages/cd/09/926cbb3fed29f762e676fb6a8d62b68c6bf536f817892cd35e89145e30e7/dissect_util-3.24-cp310-abi3-musllinux_1_2_aarch64.whl' 'df4130e896201c44e6b3d8ec1c022b586915abaedd1552f9c1b878bd343ae696'
    stage='installing the verified filesystem readers'
    import_helper exec unpack --bind-ro "$downloads" /mnt -- /usr/local/bin/python3 -m pip install \
        --no-index --no-deps --only-binary=:all: --no-cache-dir --root-user-action=ignore \
        /mnt/dissect_btrfs-1.10-py3-none-any.whl /mnt/dissect_cstruct-4.7-py3-none-any.whl \
        /mnt/dissect_util-3.24-cp310-abi3-musllinux_1_2_aarch64.whl
    stage='converting SteamOS to a local Linux image'
    recovery_reader | import_helper exec unpack --bind "$import_work/exchange" /mnt \
        --bind-ro "$downloads" /media -- /usr/local/bin/python3 - "/media/${source##*/}" /mnt
    image="$import_work/exchange/oci"
}

fail() { printf '%s\n' "$*" >&2; exit 1; }
require_magicdesk_version() {
    command -v magicdesk >/dev/null 2>&1 || fail 'magicdesk is unavailable. Open a MagicDesk Shell console first.'
    installed_magicdesk_version_code=$(magicdesk get_state --field data.app.versionCode) || \
        fail "Cannot determine MagicDesk version. Use MagicDesk $MIN_MAGICDESK_VERSION_NAME or newer and open a new Shell console."
    case "$installed_magicdesk_version_code" in
        ''|*[!0-9]*) fail 'Invalid MagicDesk versionCode; expected a non-negative Android version code.' ;;
    esac
    if [ "${#installed_magicdesk_version_code}" -gt 10 ] || [ "$installed_magicdesk_version_code" -gt 2147483647 ]; then
        fail 'Invalid MagicDesk versionCode; expected a non-negative Android version code.'
    fi
    [ "$installed_magicdesk_version_code" -ge "$MIN_MAGICDESK_VERSION_CODE" ] || \
        fail "This installer requires MagicDesk $MIN_MAGICDESK_VERSION_NAME or newer (versionCode $MIN_MAGICDESK_VERSION_CODE; installed $installed_magicdesk_version_code). Update MagicDesk, open a new Shell console and try again."
}
ask() {
    printf '%s [%s]: ' "$1" "$2"
    IFS= read -r answer || fail 'Input closed.'
    answer=${answer:-$2}
}
ask_dns() {
    printf '\n%s\n' \
        '  auto      Current network (recommended)' \
        '  preserve  Keep the Linux image/current Linux DNS settings' \
        '  IP[,IP...]  Custom DNS server addresses (1-3)'
    [ "$1" != cancel ] || printf '  cancel    Cancel installation\n'
    dns_default=$1
    [ "$dns_default" != system ] || dns_default=auto
    ask 'Network' "$dns_default"
    dns=$answer
}
check_dns() {
    while :; do
        [ "$dns" != auto ] || dns=system
        if dns_error=$(shroot dns --check "$dns" 2>&1); then return; fi
        printf '\nCannot prepare guest DNS.\n%s\n' "$dns_error" >&2
        printf '%s\n' \
            'Check the current connection, then choose auto to try again, or choose another DNS option.' \
            'No public DNS server will be selected automatically.' >&2
        [ "$yes" = no ] || fail 'Retry with --dns auto, --dns IP[,IP...] or --dns preserve.'
        ask_dns cancel
        case "$dns" in
            cancel) printf 'Cancelled.\n'; exit 0 ;;
        esac
    done
}
dns_description() {
    case "$dns" in
        auto|system) printf 'Current network (DNS saved once; editable in Linux)' ;;
        preserve) printf 'Keep Linux DNS settings' ;;
        *) printf 'Custom DNS: %s' "$dns" ;;
    esac
}
recipe_defaults() {
    source_kind=oci
    source_sha=
    case "$distro" in
        debian)
            source=https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/cf1f4a45447842b45e9952e0f018ae734a7341c7/trixie/slim/oci/blobs/rootfs.tar.gz
            source_sha=bbeda6b4abb749f743f4547ef5a28070a14de8caef211daa5afb78d5b5fa21ba
            source_kind=rootfs; version=13 ;;
        ubuntu)
            source=https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-arm64.tar.gz
            source_sha=a91d5a93010193712d346d761372b7c9db6dfcf093893161c64ca107f05914f2
            source_kind=rootfs; version=24.04 ;;
        alpine)
            source=https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/alpine-minirootfs-3.23.6-aarch64.tar.gz
            source_sha=b17a57958e29735ff0e6e64254d958e65903687a70ca30cc430b33a965ad49d7
            source_kind=rootfs; version=3.23 ;;
        fedora) source=registry.fedoraproject.org/fedora:44; version=44 ;;
        arch)
            # Official mirror with working TLS; archive authenticated with upstream's build key.
            source=https://de3.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz
            source_sha=42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319
            source_kind=rootfs; version=rolling ;;
        opensuse)
            source=https://download.opensuse.org/ports/aarch64/tumbleweed/appliances/opensuse-tumbleweed-image.aarch64-1.0.0-lxc-Snapshot20261011.tar.xz
            source_sha=a7b97cc9dfc056d7383b74a549b34572e57bfcfff8067a41e48db79a07e2b179
            source_kind=rootfs; version=Tumbleweed ;;
        openkylin) source=openkylin/openkylin:latest; version=3.0 ;;
        deepin) source=linuxdeepin/deepin:crimson-arm64; version=25 ;;
        manjaro)
            source=https://github.com/manjaro-arm/rootfs/releases/download/20261012/Manjaro-ARM-aarch64-latest.tar.gz
            source_sha=1ae540a80e21e1ca55e0576df9618fd2865cf4596b8204d20780f225aca5164a
            source_kind=rootfs; version=rolling ;;
        void)
            source=https://repo-default.voidlinux.org/live/20250202/void-aarch64-ROOTFS-20250202.tar.xz
            source_sha=01a30f17ae06d4d5b322cd579ca971bc479e02cc284ec1e5a4255bea6bac3ce6
            source_kind=rootfs; version=rolling ;;
        armtix)
            source=https://armtix.artixlinux.org/images/armtix-runit-20260921.tar.xz
            source_sha=8e1de041c64cb8bd8c1766d8f9048e75544de1c162769c02a626ce484aad4465
            source_kind=rootfs; version=rolling ;;
        steamos) source=https://steamdeck-images.steamos.cloud/recovery/steamframe-oobe-repair-20260922.5153644-0.3.0.img.bz2; version=0.3.0; source_kind=recovery ;;
        *) fail 'Unsupported distribution; use --list for available recipes.' ;;
    esac
}
distribution_id() {
    case "$1" in
        archarm) printf 'arch\n' ;;
        opensuse-tumbleweed) printf 'opensuse\n' ;;
        manjaro-arm) printf 'manjaro\n' ;;
        artix) printf 'armtix\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}
gui_notice() {
    [ "$gui" != gnome ] || printf 'GNOME devkit also needs a Linux system bus; this recipe does not boot one.\n'
}
admin_exec() (
    admin_target=$1
    shift
    # exec retains image HOME; setup must use the selected account's home instead.
    exec shroot login "$admin_target" --user root "$@"
)
package_exec() (
    package_target=$1
    shift
    # These hints apply only to setup, never to later logins or systemd boots.
    [ "${FORCE_IPV4:-}" != 1 ] || set -- --env FORCE_IPV4=1 "$@"
    admin_exec "$package_target" --env DEBIAN_FRONTEND=noninteractive --env SYSTEMD_IN_CHROOT=1 "$@"
)
register_libc_recipe() {
    libc_registry=$(shroot libc path) || fail 'Update MagicDesk: shared libc registry is unavailable.'
    case "$libc_registry" in /*/artifacts) ;; *) fail 'Invalid libc registry path.' ;; esac
    libc_home=${libc_registry%/artifacts}
    mkdir -p "$libc_home" "$libc_registry" "$libc_home/work" || fail 'Cannot create the libc build directory.'
    # Save only this downloaded script, never fetch a second MagicDesk artifact.
    saved_recipe=$(mktemp "$libc_home/.installer.XXXXXX") || fail 'Cannot stage the libc recipe.'
    cp "$0" "$saved_recipe" && chmod 600 "$saved_recipe" && mv -f "$saved_recipe" "$libc_home/install_linux.sh" \
        || { rm -f "$saved_recipe"; fail 'Cannot register the libc recipe.'; }
}
prepare_libc() (
    libc_name=$1
    libc_mode=$2
    libc_jobs=$3
    libc_target=${4:-installed}
    recipe=$(libc_setup | sha256sum); recipe=${recipe%% *}
    if [ "$libc_mode" = base ]; then
        libc_setup | admin_exec "$libc_name" -- /bin/sh -s -- base "$libc_jobs" "$recipe"
        exit $?
    fi
    register_libc_recipe
    work=$(mktemp -d "$libc_home/work/build.XXXXXX") || exit 1
    printf 'Libc build work: %s\n' "$work"
    printf 'Checking installed libc and the shared build cache...\n'
    libc_setup | admin_exec "$libc_name" -- /bin/sh -s -- identify "$libc_jobs" "$recipe" > "$work/manifest" || exit $?
    key=$(sha256sum "$work/manifest"); key=${key%% *}
    if [ -f "$libc_registry/$key/manifest" ] && cmp -s "$work/manifest" "$libc_registry/$key/manifest"; then
        printf 'Reusing Shroot libc: %s\n' "$key"
    else
        printf 'Preparing libc directly in %s (jobs: %s); no environment copy. Build packages are installed in this Linux.\n' "$libc_name" "$libc_jobs"
        # Targets must exist before the explicit bindings are admitted.
        admin_exec "$libc_name" -- /bin/sh -ec 'mkdir -p /run/shroot-libc-build /run/shroot-libc-cache' || exit $?
        if libc_setup | package_exec "$libc_name" --env "SHROOT_LIBC_BUILD_TARGET=$libc_target" \
                --bind "$work" /run/shroot-libc-build --bind-ro "$libc_registry" /run/shroot-libc-cache \
                -- /bin/sh -s -- shroot "$libc_jobs" "$recipe"; then :; else
            status=$?
            printf 'Libc preparation failed; distribution libc was not replaced by Shroot. Build packages are retained. Work: %s\n' "$work" >&2
            exit "$status"
        fi
        key=$(cat "$work/result") || fail 'Libc preparation returned no result.'
    fi
    case "$key" in ''|*[!a-f0-9]*) fail 'Invalid libc build result.' ;; esac
    [ "${#key}" = 64 ] || fail 'Invalid libc build result.'
    if [ -d "$work/candidate" ]; then
        printf 'Publishing the verified libc build to the shared cache...\n'
        shroot libc publish "$work/candidate" || {
            [ -f "$libc_registry/$key/manifest" ] && cmp -s "$work/candidate/manifest" "$libc_registry/$key/manifest" \
                || fail 'Could not publish the verified libc build.'
        }
    fi
    [ -f "$libc_registry/$key/manifest" ] || fail 'Cached build was removed; retry libc preparation.'
    printf 'Enabling libc selection for new launches of %s...\n' "$libc_name"
    admin_exec "$libc_name" -- /bin/sh -ec \
        'mkdir -p "/opt/shroot/libc/$1"
        # Shutdown helpers use this libc too. Retain its mounts until the final
        # namespace teardown, like the root filesystem, not umount.target.
        dropin=/etc/systemd/system/opt-shroot-libc-.mount.d
        mkdir -p "$dropin"
        printf "%s\n" "[Unit]" "DefaultDependencies=no" > "$dropin/50-shroot-runtime.conf"
        chmod 644 "$dropin/50-shroot-runtime.conf"
        rm -f /etc/shroot/libc-base' sh "$key" || exit $?
    printf 'Removing temporary libc build files...\n'
    rm -rf "$work" || exit $?
    printf 'Shroot libc prepared: %s. New launches select it when compatible.\n' "$key"
)
prepare_libc_command() (
    [ "$#" = 1 ] || { [ "$#" = 3 ] && [ "$2" = --jobs ]; } || fail 'Expected NAME_OR_IMAGE [--jobs N].'
    target=$1
    jobs=${3:-2}
    case "$jobs" in [1-8]) ;; *) fail 'Compiler jobs must be 1-8.' ;; esac
    require_magicdesk_version
    shroot --probe | grep -q '^libc-registry=1$' || fail 'Update MagicDesk: shared libc registry is unavailable.'
    register_libc_recipe
    temporary=
    target_kind=installed
    if ! shroot path "$target" >/dev/null 2>&1; then
        temporary=libc-build-$$-$(date +%s)
        shroot install "$target" --name "$temporary"
        target=$temporary
        target_kind=image
    fi
    if prepare_libc "$target" shroot "$jobs" "$target_kind"; then
        [ -z "$temporary" ] || shroot remove "$temporary"
    else
        [ -z "$temporary" ] || printf 'Build environment retained: %s\n' "$temporary" >&2
        exit 1
    fi
)
if [ "${1:-}" = --prepare-libc ]; then shift; prepare_libc_command "$@"; exit $?; fi
if [ "$#" = 1 ] && [ "$1" = --print-mesa-patch ]; then mesa_patch; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-flatpak-gl-helper ]; then flatpak_gl_helper; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-snap-gpu-helper ]; then snap_gpu_helper; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-system-setup ]; then system_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-graphics-setup ]; then graphics_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-weston-setup ]; then weston_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-libc-setup ]; then libc_setup; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-desktop-session ]; then desktop_session; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-audio-session ]; then audio_session; exit 0; fi
if [ "$#" = 1 ] && [ "$1" = --print-steam-game ]; then steam_game; exit 0; fi
if [ "$#" -ge 1 ] && [ "$1" = --print-kwin-patch ]; then
    [ "$#" -le 2 ] || fail 'Expected one KWin version.'
    kwin_patch "${2:-6.3.6}" || fail 'KWin version must be 6.3.6 or 6.2.5.'
    exit 0
fi
if [ "$#" = 1 ] && [ "$1" = --print-recovery-reader ]; then recovery_reader; exit 0; fi
distro=
name=
image=
gui=
protocol=both
gpu=
libc=
jobs=2
locale_name=
zone=
new_user=
fonts=
cache=keep
extras=
yes=no
resume=no
dns=
downloads=
import_work=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --distro|--name|--image|--downloads|--gui|--protocol|--gpu|--libc|--jobs|--locale|--timezone|--create-user|--fonts|--cache|--package|--dns)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"
            case "$1" in
                --distro) distro=$2 ;; --name) name=$2 ;; --image) image=$2 ;; --gui) gui=$2 ;;
                --protocol) protocol=$2 ;; --gpu) gpu=$2 ;; --jobs) jobs=$2 ;; --locale) locale_name=$2 ;;
                --timezone) zone=$2 ;; --create-user) new_user=$2 ;; --fonts) fonts=$2 ;;
                --cache) cache=$2 ;;
                --package) extras="${extras:+$extras }$2" ;; --dns) dns=$2 ;;
                --downloads) downloads=$2 ;;
                --libc) libc=$2 ;;
            esac
            shift 2 ;;
        --yes) yes=yes; shift ;;
        --resume) resume=yes; shift ;;
        --list) configurations; exit 0 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown argument: $1 (see --help)" ;;
    esac
done
if [ "$resume" = yes ]; then
    [ -n "$name" ] || fail '--resume requires --name NAME.'
    [ -z "$dns" ] && [ -z "$image" ] || fail '--resume retains image and DNS; use shroot dns to change DNS.'
fi

command -v shroot >/dev/null 2>&1 || fail 'Open a MagicDesk Shell console with shell access first.'
case "$(id -u)" in 2000|0) ;; *) fail 'Shroot requires the selected Android shell (UID 2000) or root executor.' ;; esac
require_magicdesk_version
if [ "$yes" = no ]; then
    [ -t 0 ] || fail 'Interactive input is unavailable. Save the script before running it, or use --yes.'
    if [ "$resume" = no ]; then
        configurations
        if [ -z "$distro" ]; then ask 'Distribution' debian; distro=$answer; fi
    fi
    if [ -z "$name" ]; then ask 'Independent environment name' "${distro:-debian}"; name=$answer; fi
    if [ "$distro" = steamos ]; then
        fonts=${fonts:-keep}
        printf 'SteamOS retains its supplied applications and system drivers.\n'
    fi
    if [ -z "$gui" ]; then
        default_gui=apps; [ "$resume" = no ] || default_gui=keep
        [ "$distro" != steamos ] || default_gui=plasma
        ask 'GUI: none/apps/xfce/weston/plasma (Debian/SteamOS)/gnome (Fedora devkit)/keep' "$default_gui"; gui=$answer
    fi
    if [ -z "$gpu" ]; then
        default_gpu=keep
        if [ "$distro" = steamos ] && [ "$resume" = no ]; then default_gpu=auto; fi
        ask 'Graphics: keep/software/auto/turnip (Adreno KGSL; builds Mesa)' "$default_gpu"; gpu=$answer
    fi
    if [ -z "$libc" ]; then
        ask 'Linux libc: shroot (build/reuse accelerated libc)/base/keep' shroot; libc=$answer
    fi
    if { [ "$libc" = shroot ] || [ "$gpu" = turnip ] || [ "$gpu" = auto ] || [ "$gui" = plasma ]; } && [ "$jobs" = 2 ]; then
        ask 'Compiler jobs for libc/Mesa/KWin (1-8)' 2; jobs=$answer
    fi
    if [ -z "$locale_name" ]; then ask 'Locale, e.g. ru_RU.UTF-8; keep leaves it unchanged' keep; locale_name=$answer; fi
    if [ -z "$zone" ]; then ask 'Timezone: system, IANA zone, or keep' keep; zone=$answer; fi
    if [ -z "$fonts" ]; then
        default_fonts=basic; [ "$resume" = no ] || default_fonts=keep
        [ "$distro" != steamos ] || default_fonts=keep
        ask 'Fonts: basic/cjk/keep' "$default_fonts"; fonts=$answer
    fi
    ask 'Additional settings (guest user, protocol, packages, DNS, cache)? y/N' N
    case "$answer" in
        y|Y|yes|YES)
            if [ -z "$new_user" ]; then ask 'Create guest user (empty = no new account)' ''; new_user=$answer; fi
            if [ "$distro" != steamos ]; then
                ask 'Installer application entries: both/x11/wayland' "$protocol"; protocol=$answer
                ask 'Additional repository packages (space-separated)' "$extras"; extras=$answer
            fi
            if [ "$resume" = no ] && [ -z "$dns" ]; then
                ask_dns auto
            fi
            if [ "$distro" != steamos ]; then ask 'Downloaded package cache: keep/clean' "$cache"; cache=$answer; fi
            ;;
    esac
fi
name=${name:-${distro:-debian}}
if [ "$resume" = yes ]; then
    gui=${gui:-keep}; fonts=${fonts:-keep}
elif [ "$distro" = steamos ]; then
    gui=${gui:-plasma}; gpu=${gpu:-auto}; fonts=${fonts:-keep}
else gui=${gui:-apps}; fonts=${fonts:-basic}; fi
gpu=${gpu:-keep}
libc=${libc:-shroot}
locale_name=${locale_name:-keep}
zone=${zone:-keep}
dns=${dns:-system}
case "$name" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9_.-]*) fail 'Invalid environment name.' ;; esac
[ "${#name}" -le 64 ] || fail 'Name must be at most 64 characters.'
case "$gui" in none|apps|xfce|weston|plasma|gnome|keep) ;; *) fail 'Invalid GUI profile.' ;; esac
case "$protocol" in both|x11|wayland) ;; *) fail 'Protocol must be both, x11 or wayland.' ;; esac
case "$gpu" in keep|software|turnip|auto) ;; *) fail 'GPU must be keep, software, auto or turnip.' ;; esac
case "$jobs" in [1-8]) ;; *) fail 'Jobs must be between 1 and 8.' ;; esac
case "$libc" in keep|shroot|base) ;; *) fail 'Libc must be keep, shroot or base.' ;; esac
case "$locale_name" in
    keep|C.UTF-8) ;;
    *) printf '%s\n' "$locale_name" | grep -Eq '^[a-z]{2,3}_[A-Z]{2}\.UTF-8$' || fail 'Expected a UTF-8 locale such as en_US.UTF-8.' ;;
esac
if [ "$zone" = system ]; then
    command -v getprop >/dev/null 2>&1 || fail 'Android timezone is unavailable; supply an IANA timezone.'
    zone=$(getprop persist.sys.timezone)
    [ -n "$zone" ] || fail 'Android timezone is empty; supply an IANA timezone.'
fi
case "$zone" in ''|/*|*..*|*[!A-Za-z0-9_+/-]*) fail 'Invalid IANA timezone.' ;; esac
if [ -n "$new_user" ]; then
    printf '%s\n' "$new_user" | grep -Eq '^[a-z_][a-z0-9_-]{0,30}$' || fail 'Invalid guest account name.'
    [ "$new_user" != root ] || fail 'The root account already exists; --create-user creates an ordinary account.'
fi
case "$fonts" in basic|cjk|keep) ;; *) fail 'Fonts must be basic, cjk or keep.' ;; esac
case "$cache" in keep|clean) ;; *) fail 'Cache must be keep or clean.' ;; esac
if [ -n "$extras" ]; then
    printf '%s\n' "$extras" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9+_.-]*( [A-Za-z0-9][A-Za-z0-9+_.-]*)*$' || fail 'Expected repository package names, not options or shell commands.'
fi

# Read-only validation precedes every existing-environment mutation.
if [ "$resume" = yes ]; then
    detected=$(admin_exec "$name" -- /bin/sh -c '. /etc/os-release; printf "%s\n" "$ID"')
    detected=$(distribution_id "$detected")
    [ -z "$distro" ] || [ "$distro" = "$detected" ] || fail 'Selected distribution does not match the existing environment.'
    distro=$detected
else
    distro=${distro:-debian}
fi
recipe_defaults
if [ "$distro" = steamos ]; then
    [ -z "$image" ] || fail 'SteamOS uses its pinned official recovery archive, not --image.'
    { [ "$gui" = keep ] || [ "$gui" = plasma ]; } && [ "$fonts" = keep ] && [ -z "$extras" ] \
        && [ "$cache" = keep ] || fail 'SteamOS supports plasma/keep with supplied applications and fonts.'
fi
if [ -n "$image" ]; then source_kind=oci; else image=$source; fi
[ "$gui" != gnome ] || [ "$distro" = fedora ] || fail 'The GNOME devkit recipe currently requires Fedora 44. Use apps, Xfce or Weston on other distributions.'
[ "$gui" != plasma ] || [ "$distro" = debian ] || [ "$distro" = steamos ] || fail 'The Plasma recipe requires Debian 13 or SteamOS 0.3.0.'
[ "$gui" != none ] || [ "$gpu" = keep ] || fail 'Choose a GUI profile before installing graphics; use --gui keep for an existing GUI.'
[ "$resume" = yes ] || check_dns

printf '\n%s %s ARM64 | %s | GUI=%s | graphics=%s\n' "$distro" "$version" "$name" "$gui" "$gpu"
printf 'Locale=%s | timezone=%s | fonts=%s | application entries=%s\n' "$locale_name" "$zone" "$fonts" "$protocol"
printf 'Guest account=%s | extra packages=%s | package cache=%s\n' "${new_user:-unchanged}" "${extras:-none}" "$cache"
printf 'Linux libc: %s\n' "$libc"
if [ "$libc" = shroot ] || [ "$gpu" = turnip ] || [ "$gpu" = auto ] || [ "$gui" = plasma ]; then
    printf 'Compiler jobs for libc/Mesa/KWin: %s\n' "$jobs"
fi
if [ "$resume" = yes ]; then printf 'Continue the existing environment without replacing user data.\n'
else printf 'Source: %s\nNetwork: %s\n' "$image" "$(dns_description)"; fi
[ "$distro" != armtix ] || printf 'Armtix retains its upstream repository signature policy (the supplied rootfs disables package signatures).\n'
[ "$gui" != gnome ] || printf 'GNOME development kit is experimental; it is not a booted systemd/GDM desktop.\n'
gui_notice
if [ "$yes" = no ]; then
    ask 'Continue? y/N' N
    case "$answer" in y|Y|yes|YES) ;; *) printf 'Cancelled.\n'; exit 0 ;; esac
fi

stage='checking Shroot'
ready=no
finish() {
    status=$?
    if [ -n "$import_work" ]; then
        if [ "$status" -eq 0 ] || [ "$ready" = yes ]; then
            if import_helper remove unpack && import_helper prune; then
                rm -rf "$import_work"
            else
                printf 'Temporary converter retained: %s\n' "$import_work" >&2
            fi
        else
            printf 'Image conversion work retained for inspection: %s\n' "$import_work" >&2
        fi
    fi
    if [ "$status" -ne 0 ]; then
        printf '\nInstallation stopped while %s (exit %s).\n' "$stage" "$status" >&2
        if [ "$ready" = yes ]; then
            printf 'Environment retained. Repeat your options with --name %s --resume (do not reinstall).\n' "$name" >&2
            printf 'GUI=%s GPU=%s jobs=%s locale=%s timezone=%s fonts=%s libc=%s\n' \
                "$gui" "$gpu" "$jobs" "$locale_name" "$zone" "$fonts" "$libc" >&2
        else
            printf 'Inspect shroot list before retrying an interrupted installation.\n' >&2
        fi
    fi
}
trap finish 0
trap 'exit 130' INT
trap 'exit 143' TERM
runtime_features=$(shroot --probe)
printf '%s\n' "$runtime_features"
if [ "$libc" != keep ]; then
    printf '%s\n' "$runtime_features" | grep -q '^libc-registry=1$' || fail 'Update MagicDesk: shared libc registry is unavailable.'
fi
if [ "$resume" = no ]; then
    case "$source_kind" in
        recovery) prepare_recovery ;;
        rootfs) prepare_rootfs ;;
    esac
    stage='installing the Linux image'
    case "$source_kind" in
        recovery) shroot install "$image" --oci --name "$name" --dns "$dns" ;;
        rootfs) shroot install "$image" --rootfs --name "$name" --dns "$dns" ;;
        oci) shroot install "$image" --name "$name" --dns "$dns" ;;
    esac
    if [ "$dns" != preserve ]; then
        stage='applying selected DNS to the new environment'
        shroot dns "$name" "$dns" --replace
    fi
fi
stage='validating the selected environment'
admin_exec "$name" -- /bin/sh -c '
    set -eu
    . /etc/os-release
    case "$ID" in archarm) ID=arch ;; opensuse-tumbleweed) ID=opensuse ;; manjaro-arm) ID=manjaro ;; artix) ID=armtix ;; esac
    [ "$ID" = "$1" ] || exit 1
    case "$ID" in
        debian|ubuntu|openkylin|deepin) [ "$VERSION_ID" = "$2" ] && [ "$(dpkg --print-architecture)" = arm64 ] ;;
        alpine) case "$VERSION_ID" in "$2".*) ;; *) exit 1 ;; esac; [ "$(apk --print-arch)" = aarch64 ] ;;
        fedora) [ "$VERSION_ID" = "$2" ] && [ "$(rpm --eval "%{_arch}")" = aarch64 ] ;;
        opensuse) [ "$(rpm --eval "%{_arch}")" = aarch64 ] ;;
        arch|manjaro|armtix) [ "$(uname -m)" = aarch64 ] ;;
        void) [ "$(xbps-uhelper arch)" = aarch64 ] ;;
        steamos) [ "$VERSION_ID" = "$2" ] && [ "$(uname -m)" = aarch64 ] ;;
    esac || { echo "Unexpected distribution version or architecture; setup was not applied." >&2; exit 1; }
' sh "$distro" "$version"
ready=yes
setup_exec() {
    set -- -- /bin/sh -s -- "$@"
    [ -z "${setup_phase:-}" ] || set -- --env MAGICDESK_BUILD_PHASE="$setup_phase" "$@"
    package_exec "$name" "$@"
}
setup_libc() {
    if [ "$libc" != keep ]; then
        stage="preparing the $libc libc runtime"
        prepare_libc "$name" "$libc" "$jobs"
    fi
}
setup_build() {
    build_label=$1
    build_payload=$2
    shift 2
    unset setup_phase
    build_recipe=$("$build_payload" | sha256sum)
    build_recipe=${build_recipe%% *}
    if [ "$libc" = shroot ]; then
        stage="installing build dependencies for $build_label"
        setup_phase=dependencies
        "$build_payload" | setup_exec "$@" "$build_recipe"
        # Package dependencies can replace libc. Match the final bytes before
        # starting compiler processes, without changing their link-time ABI.
        setup_libc
        setup_phase=build
    fi
    stage="preparing the $build_label"
    "$build_payload" | setup_exec "$@" "$build_recipe"
    unset setup_phase
}
stage='installing packages and guest settings'
while :; do
    if system_setup | setup_exec \
            "$gui" "$protocol" "$locale_name" "$zone" "$new_user" "$fonts" "$cache" "$extras"; then
        break
    else
        setup_status=$?
    fi
    [ "$yes" = no ] || exit "$setup_status"
    printf '\nPackage setup failed (exit %s). The environment and your choices are retained.\n' "$setup_status" >&2
    printf 'Review the error above. Changing DNS only helps resolver problems.\n' >&2
    while :; do
        ask 'Package setup: retry, dns (change resolver and retry), or cancel' cancel
        case "$answer" in
            retry) break ;;
            dns)
                ask_dns "$dns"
                check_dns
                [ "$dns" = preserve ] || shroot dns "$name" "$dns" --replace
                break ;;
            cancel) exit "$setup_status" ;;
            *) printf 'Choose retry, dns, or cancel.\n' >&2 ;;
        esac
    done
done

if [ "$distro" = steamos ]; then
    stage='preparing the supplied Steam client'
    printf 'Preparing the supplied Steam client for the steamos account...\n'
    shroot exec "$name" -- /bin/sh -c '
        set -eu
        [ "$(id -un)" = steamos ]
        mkdir -p "$HOME/.steam" "$HOME/.local/share"
        exec 9>"$HOME/.steam/installer.lock"
        flock -n 9 || { echo "Another Steam setup is running." >&2; exit 1; }
        if [ ! -d "$HOME/.local/share/Steam" ]; then
            work=$(mktemp -d "$HOME/.local/share/.steam-XXXXXX")
            trap '\''rm -rf "$work"'\'' 0
            tar --no-same-owner --zstd --checkpoint=10000 -xf /usr/lib/steam/steam.tar.zst -C "$work"
            [ -x "$work/steamrtarm64/steam" ]
            mv "$work" "$HOME/.local/share/Steam"
        fi
        if [ ! -e "$HOME/.steam/steam" ] && [ ! -L "$HOME/.steam/steam" ]; then
            ln -s ../.local/share/Steam "$HOME/.steam/steam"
        fi
        # Desktop launches need the SDK paths too, without RUNSTEAM session policy.
        for link in root sdk32 sdk64 sdkarm64 bin32 bin64 binarm64; do
            case "$link" in
                root) target=. ;;
                sdk32) target=linux32 ;; sdk64) target=linux64 ;; sdkarm64) target=linuxarm64 ;;
                bin32) target=ubuntu12_32 ;; bin64) target=ubuntu12_64 ;; binarm64) target=steamrtarm64 ;;
            esac
            if [ ! -e "$HOME/.steam/$link" ] && [ ! -L "$HOME/.steam/$link" ]; then
                ln -s "steam/$target" "$HOME/.steam/$link"
            fi
        done
    '
fi

# Source builds prepare libc after their dependencies; without a source-build
# stage, apply the selected runtime here. Base must precede any build launch.
if [ "$libc" != shroot ] || {
    [ "$gpu" = keep ] && [ "$gui" != plasma ] && [ "$gui" != weston ] && [ "$gui" != keep ]
}; then
    setup_libc
fi

if [ "$gpu" != keep ]; then
    setup_build "$gpu graphics profile" graphics_setup "$gpu" "$jobs"
fi

if [ "$gui" = plasma ] || [ "$gpu" != keep ]; then
    setup_build 'nested Plasma compositor' plasma_setup "$jobs"
fi

if [ "$gui" = weston ] || [ "$gui" = keep ]; then
    setup_build 'Weston compatibility' weston_setup "$jobs"
fi

stage=complete
printf '\nLinux is ready: %s (%s %s)\n' "$name" "$distro" "$version"
gui_notice
printf '\nNext steps:\n'
if [ "$gui" != none ]; then
    printf 'In MagicDesk Control Panel, select a display and open Apps (Start).\n'
    printf 'Press Refresh beside the search field to load installed Linux entries.\n'
    printf 'Audio connects to Android automatically. Desktop volume controls use their private PipeWire graph.\n'
    printf 'Android gamepads are available in the focused Shroot window, on X11 and Wayland.\n'
fi
case "$gui" in
    none) printf 'No GUI was installed by this run. Use a terminal below.\n' ;;
    keep) printf 'Existing GUI entries were preserved; choose an installed application or desktop.\n' ;;
    *)
        app_backends='x11 wayland'
        [ "$distro" != steamos ] || app_backends=
        for backend in $app_backends; do
            if [ "$protocol" = both ] || [ "$protocol" = "$backend" ]; then
                printf 'Individual apps: Mousepad (%s), Thunar (%s), Xfce Terminal (%s).\n' "$backend" "$backend" "$backend"
            fi
        done
        case "$gui" in
            apps) printf 'The apps profile adds individual applications, not a whole Linux desktop.\n' ;;
            xfce) printf 'Whole desktop: search for Xfce Desktop (X11), environment %s.\n' "$name" ;;
            weston) printf 'Whole desktop: search for Weston Desktop (Wayland), environment %s.\n' "$name" ;;
            plasma) printf 'Whole desktop: search for Plasma Desktop (x11) or Plasma Desktop (wayland), environment %s.\n' "$name" ;;
            gnome) printf 'Experimental desktop: search for GNOME Shell (development kit), environment %s; requires a Linux system bus.\n' "$name" ;;
        esac ;;
esac
printf 'Terminal: Terminal sessions > New session > Shroot environments > %s > New session.\n' "$name"
printf 'Keep privileged access available; no MagicDesk Desktop session or installer rerun is needed.\n'
printf 'Console: shroot login %s\n' "$name"
[ "$distro" != steamos ] || printf '%s\n' 'SteamOS uses the steamos guest account. Open Steam from Apps; its own updater may download client components.' 'For x86 Linux games using FEX, set Steam Launch Options: magicdesk-steam-game %command%' 'This installs Linux userspace, not SteamOS boot, recovery or VR services. GPU/game compatibility is a separate check.'
if [ -n "$new_user" ]; then printf 'User console: shroot login %s --user %s\n' "$name" "$new_user"; fi
printf 'Folder attachment: shroot login %s --bind /sdcard/Download /mnt\n' "$name"
printf 'Optional Android command access: shroot login %s --magicdesk\n' "$name"
printf 'Backup (close its applications first): shroot backup %s /sdcard/Download/%s.tar.zst\n' "$name" "$name"
if [ "$gpu" = turnip ]; then
    printf 'Software fallback: sh install_linux.sh --name %s --resume --gpu software\n' "$name"
fi
