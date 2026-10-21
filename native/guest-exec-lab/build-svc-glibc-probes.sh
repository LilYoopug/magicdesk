#!/bin/sh
# Link identical workloads to supplied stock libraries, not host libc.
set -eu
cd /tmp
gcc -O2 -g -fexceptions -pthread -DMD_LIBC_NAME='"glibc"' \
    -I/tmp/include -I/tmp/include/aarch64-linux-gnu -c probe.c -o probe.o
gcc -no-pie -nostdlib "stock/crt1.o" "stock/crti.o" \
    "$(gcc --print-file-name=crtbeginT.o)" probe.o -static -Wl,--start-group \
    "stock/libc.a" -lgcc -lgcc_eh -Wl,--end-group \
    "$(gcc --print-file-name=crtend.o)" "stock/crtn.o" -o probe-stock
gcc -pie -nostdlib stock/Scrt1.o stock/crti.o \
    "$(gcc --print-file-name=crtbeginS.o)" probe.o \
    -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1 -Wl,-rpath=/lib \
    stock/libc.so.6 stock/libc_nonshared.a stock/ld-linux-aarch64.so.1 stock/libgcc_s.so.1 -lgcc \
    "$(gcc --print-file-name=crtendS.o)" stock/crtn.o -o probe-stock-dynamic
