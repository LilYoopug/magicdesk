#!/usr/bin/env sh
# Refresh only workload binaries against an existing isolated musl sysroot.
set -eu
test "$#" = 1
scripts=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
out=$(CDPATH= cd -- "$1" && pwd)
cc=${CC:-clang}
resource=$("$cc" -print-resource-dir)
builtins=${COMPILER_BUILTINS:-$resource/lib/linux/libclang_rt.builtins-aarch64-android.a}
test -f "$builtins"
test -f "$out/sysroot/lib/libc.so"
for kind in static dynamic; do
    flags=-static
    crt=crt1.o
    if [ "$kind" = dynamic ]; then
        flags='-pie -Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1'
        crt=Scrt1.o
    fi
    "$cc" --target=aarch64-linux-musl --sysroot="$out/sysroot" \
        -isystem "$out/sysroot/include" -idirafter "${PREFIX:-/usr}/include" \
        -idirafter "${PREFIX:-/usr}/include/aarch64-linux-android" \
        -fuse-ld=lld -O2 -g -Wall -Wextra -Werror -nostdlib $flags \
        "$out/sysroot/lib/$crt" "$out/sysroot/lib/crti.o" \
        "$scripts/test_cooperative_libc.c" -L"$out/sysroot/lib" -lc "$builtins" \
        "$out/sysroot/lib/crtn.o" -o "$out/probe-$kind"
done
