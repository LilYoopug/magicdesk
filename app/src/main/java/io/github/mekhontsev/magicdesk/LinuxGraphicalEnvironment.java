package io.github.mekhontsev.magicdesk;

/** Guest-side session policy; the distribution supplies D-Bus and its authentication policy. */
final class LinuxGraphicalEnvironment {
    // /proc encodes whitespace and backslashes as octal escapes. Keep the encoded
    // records until each helper invocation; never evaluate mount-table content.
    private static final String CLEANUP = """
            md_session_mounts() {
                while IFS=' ' read -r md_source md_path md_type md_options; do
                    md_target=$md_path
                    case "$md_path" in *'\\'*)
                        md_target=$(printf '%b.' "$md_path") || return
                        md_target=${md_target%.} ;;
                    esac
                    case "$md_target" in
                        "$XDG_RUNTIME_DIR"|"$XDG_RUNTIME_DIR"/*)
                            printf '%s %s\\n' "$md_path" "$md_type" ;;
                    esac
                done < /proc/self/mounts
            }
            md_session_cleanup() {
                md_mounts=$(md_session_mounts) || return
                # Reverse path order puts nested mounts before their parents.
                printf '%s\\n' "$md_mounts" | LC_ALL=C sort -r |
                while IFS=' ' read -r md_path md_type; do
                    [ -n "$md_path" ] || continue
                    md_target=$(printf '%b.' "$md_path") || exit
                    md_target=${md_target%.}
                    case "$md_type" in
                        fuse|fuse.*|fuseblk)
                            if command -v fusermount3 >/dev/null 2>&1; then
                                fusermount3 -u -z -- "$md_target" 2>/dev/null || :
                            elif command -v fusermount >/dev/null 2>&1; then
                                fusermount -u -z -- "$md_target" 2>/dev/null || :
                            else
                                umount -l -- "$md_target" 2>/dev/null || :
                            fi ;;
                        *) umount -l -- "$md_target" 2>/dev/null || : ;;
                    esac
                done
                # A daemon may have unmounted concurrently. Check the outcome,
                # not a helper's error for a mount that has already disappeared.
                md_mounts=$(md_session_mounts) || return
                if [ -n "$md_mounts" ]; then
                    printf 'MagicDesk: runtime mounts remain; retaining %s\\n' "$XDG_RUNTIME_DIR" >&2
                    return 1
                fi
                if [ -e "$XDG_RUNTIME_DIR" ] || [ -L "$XDG_RUNTIME_DIR" ]; then
                    find "$XDG_RUNTIME_DIR" -xdev -depth -delete
                fi
            }
            md_session_exit() {
                md_status=$?
                trap - EXIT
                if ! md_session_cleanup; then
                    printf 'MagicDesk: runtime cleanup failed: %s\\n' "$XDG_RUNTIME_DIR" >&2
                    [ "$md_status" -ne 0 ] || md_status=1
                fi
                exit "$md_status"
            }
            trap md_session_exit EXIT
            """;

    static String wrap(GraphicalProtocol protocol, String command) {
        return wrap(protocol, "", command);
    }

    static String wrap(GraphicalProtocol protocol, String prepare, String command) {
        String setup = "set -eu; umask 077; XDG_RUNTIME_DIR=$(mktemp -d /tmp/magicdesk-runtime.XXXXXX); "
                + "export XDG_RUNTIME_DIR XDG_SESSION_TYPE=" + protocol.wireName + "; "
                + CLEANUP;
        return setup + prepare + "dbus-run-session -- " + command;
    }

    private LinuxGraphicalEnvironment() { }
}
