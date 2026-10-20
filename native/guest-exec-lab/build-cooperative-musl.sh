#!/usr/bin/env sh
# Build an isolated libc fixture; never replace an installed distribution libc.
set -eu
test "$#" = 1 || { test "$#" = 2 && test "$2" = --stock; }
stock=${2:-}
scripts=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
libc=$scripts/../shroot/libc
mkdir -p "$1"
out=$(CDPATH= cd -- "$1" && pwd)
archive=$out/musl-1.2.5.tar.gz
if [ ! -f "$archive" ]; then
    curl -fL --connect-timeout 20 --max-time 180 \
        -o "$archive.part" https://musl.libc.org/releases/musl-1.2.5.tar.gz
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 "$archive" | sha256sum -c -
integration=$(sha256sum "$libc/integrate_musl.py" "$libc/source_integration.py" "$libc/musl.patch")
if [ -n "$stock" ]; then integration=stock-musl-1.2.5; fi
if [ ! -f "$out/integration-stamp" ] || [ "$(cat "$out/integration-stamp")" != "$integration" ]; then
    # Added integration files must not survive a fresh source generation.
    rm -rf "$out/musl-1.2.5" "$out/objects" "$out/sysroot"
    tar --no-same-owner -xzf "$archive" -C "$out"
    if [ -z "$stock" ]; then python "$libc/integrate_musl.py" "$out/musl-1.2.5"; fi
    printf '%s\n' "$integration" > "$out/integration-stamp"
fi
if [ -z "$stock" ]; then
# Remove only headers installed by the previous laboratory integration.
rm -f "$out/musl-1.2.5/src/internal/entry_route.h" "$out/musl-1.2.5/src/internal/syscall_catalog.h"
for header in cooperative_entry.h; do
    origin=$scripts/../shroot/src/$header
    destination=$out/musl-1.2.5/src/internal/$header
    cmp -s "$origin" "$destination" || cp "$origin" "$destination"
done
cmp -s "$libc/musl_entry.c" "$out/musl-1.2.5/src/thread/aarch64/shroot.c" || \
    cp "$libc/musl_entry.c" "$out/musl-1.2.5/src/thread/aarch64/shroot.c"
fi
cc=${CC:-clang}
resource=$("$cc" -print-resource-dir)
builtins=${COMPILER_BUILTINS:-$resource/lib/linux/libclang_rt.builtins-aarch64-android.a}
test -f "$builtins"
mkdir -p "$out/objects"
cd "$out/objects"
if [ ! -f config.mak ]; then
    CC="$cc --target=aarch64-linux-musl -fuse-ld=lld" \
        LIBCC="$builtins" CFLAGS='-O2 -g -mno-outline-atomics' \
        "$out/musl-1.2.5/configure" --target=aarch64-linux-musl --prefix="$out/sysroot" --syslibdir="$out/sysroot/lib"
fi
make -s -j"${JOBS:-4}" AR="${AR:-llvm-ar}" RANLIB="${RANLIB:-llvm-ranlib}"
make -s install AR="${AR:-llvm-ar}" RANLIB="${RANLIB:-llvm-ranlib}"
sh "$scripts/build-cooperative-probes.sh" "$out"
