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
tar -xf "$archive" -C source --strip-components=1
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
fi
make -j"$jobs"
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
