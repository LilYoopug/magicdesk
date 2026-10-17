#!/bin/sh
# Runs inside the isolated builder, never in the installed guest distribution.
set -eu
cd /work
lib=/work/sysroot/usr/lib64
gcc -O2 -g -fexceptions -pthread -DMD_LIBC_NAME='"glibc"' \
    -I/work -I/work/sysroot/usr/include -c /work/probe.c -o /work/probe.o
for kind in static dynamic; do
    if [ "$kind" = static ]; then
        begin=$(gcc --print-file-name=crtbeginT.o)
        set -- -static -Wl,--start-group \
            "$lib/libc.a" -lgcc -lgcc_eh -Wl,--end-group
    else
        begin=$(gcc --print-file-name=crtbegin.o)
        set -- -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
            /work/sysroot/lib64/libc.so.6 "$lib/libc_nonshared.a" -lgcc_s -lgcc
    fi
    gcc -no-pie -nostdlib "$lib/crt1.o" "$lib/crti.o" "$begin" /work/probe.o \
        "$@" "$(gcc --print-file-name=crtend.o)" "$lib/crtn.o" -o "/work/probe-$kind"
done
mkdir -p /work/sysroot/lib
cp /usr/lib/aarch64-linux-gnu/libgcc_s.so.1 /work/sysroot/lib/
