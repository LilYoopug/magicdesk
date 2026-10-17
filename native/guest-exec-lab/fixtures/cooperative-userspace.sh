#!/bin/sh
set -eu
b=/bin/busybox
work=$1
"$b" mkdir -p "$work/source" "$work/restored"
cd "$work/source"
umask 027
i=0
while [ "$i" -lt 128 ]; do
    printf '%s\n' "record-$i" > "file-$i"
    i=$((i + 1))
done
"$b" ln file-0 alias
"$b" ln -s file-1 symbolic
"$b" chmod 640 file-0
"$b" touch -t 202001020304.05 file-1
test "$("$b" stat -c %a file-0)" = 640
test "$("$b" stat -c %i file-0)" = "$("$b" stat -c %i alias)"
test "$("$b" cat symbolic)" = record-1
"$b" find . -type f | "$b" sort | "$b" xargs "$b" sha256sum > ../expected
"$b" tar -cf ../archive.tar .
cd ../restored
"$b" tar -xf ../archive.tar
"$b" find . -type f | "$b" sort | "$b" xargs "$b" sha256sum > ../actual
"$b" cmp ../expected ../actual
test "$("$b" stat -c %i file-0)" = "$("$b" stat -c %i alias)"
test "$("$b" readlink symbolic)" = file-1
test "$("$b" stat -c %a file-0)" = 640
"$b" mv file-0 renamed
"$b" rm alias
test "$("$b" cat renamed)" = record-0
"$b" test ! -e file-0
cd /
"$b" rm -rf "$work"
printf '%s\n' 'PASS userspace: shell, archive, hardlinks, symlinks, metadata, traversal and pipelines'
