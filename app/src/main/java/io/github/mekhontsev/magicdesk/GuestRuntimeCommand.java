package io.github.mekhontsev.magicdesk;

/** Lazy CLI adapter. Preparation is a child command, never the owner of application FDs. */
public final class GuestRuntimeCommand {
    public static final String LIBRARIES_ENV = "MAGICDESK_GUEST_LIBRARIES";
    public static final String BODY = "unset LD_PRELOAD LD_LIBRARY_PATH\n"
            + "md_guest=$(CLASSPATH=\"${MAGICDESK_COMMAND_APK:?Open a new MagicDesk console}\" "
            + "/system/bin/app_process / io.github.mekhontsev.magicdesk.GuestRuntimeMain "
            + "\"${" + LIBRARIES_ENV + ":?Shroot is unavailable}\" "
            + "\"${MAGICDESK_RUNTIME:?Missing shell runtime}/guest-runtime\") || exit $?\n"
            + "md_libc_home=${MAGICDESK_GUEST_HOME:-$MAGICDESK_RUNTIME/guest-environments}/libc\n"
            + "md_libc=$md_libc_home/artifacts\n"
            + "md_libc_init() { mkdir -p \"$md_libc\" || printf '%s\\n' 'Optional libc registry unavailable; using Shroot Base.' >&2; }\n"
            + "md_library() { CLASSPATH=\"$MAGICDESK_COMMAND_APK\" /system/bin/app_process / "
            + "io.github.mekhontsev.magicdesk.GuestEnvironmentMain \"$md_guest\" "
            + "\"${MAGICDESK_GUEST_HOME:-$MAGICDESK_RUNTIME/guest-environments}\" \"$@\"; }\n"
            + "md_image() { md_action=$1; md_store=$2; shift 2\n"
            + "case \"$md_action\" in run|exec|login)\n"
            + "md_libc_init\n"
            + "set -- --libc-registry \"$md_libc\" \"$@\"\n"
            + LinuxAudioEnvironment.shrootArguments() + GamepadWire.shrootArguments() + ";; esac\n"
            + "exec \"$md_guest/libmagicdesk_guest_image.so\" \"$md_action\" \"$md_store\" \"$@\"; }\n"
            + "case \"${1-}\" in\n"
            + "  libc) shift; case \"${1-}\" in\n"
            + "    path) [ \"$#\" = 1 ] || exit 2; printf '%s\\n' \"$md_libc\" ;;\n"
            + "    list|prune) [ \"$#\" = 1 ] || exit 2; exec \"$md_guest/libmagicdesk_guest_image.so\" \"libc-$1\" \"$md_libc\" ;;\n"
            + "    publish) [ \"$#\" = 2 ] || exit 2; exec \"$md_guest/libmagicdesk_guest_image.so\" libc-publish \"$md_libc\" \"$2\" ;;\n"
            + "    prepare) shift; [ -f \"$md_libc_home/install_linux.sh\" ] || { printf '%s\\n' 'First run: sh ~/install_linux.sh --prepare-libc NAME_OR_IMAGE'; exit 1; }; exec \"${MAGICDESK_ANDROID_SHELL:?Missing bundled shell}\" \"$md_libc_home/install_linux.sh\" --prepare-libc \"$@\" ;;\n"
            + "    *) printf '%s\\n' 'Usage: shroot libc prepare NAME_OR_IMAGE [--jobs N] | list | prune | path' >&2; exit 2 ;;\n"
            + "    esac; exit $? ;;\n"
            + "  run|exec|login) md_action=$1; shift\n"
            + "     md_store=$(md_library resolve \"${1-}\") || exit $?\n"
            + "     shift\n"
            + "     \"$md_guest/libmagicdesk_guest_supervisor.so\" \"$md_guest/libmagicdesk_guest_bootstrap.so\" --probe >/dev/null || exit $?\n"
            + "     md_image \"$md_action\" \"$md_store\" \"$@\" ;;\n"
            + "  install|list|inspect|path|backup|restore|remove|prune|dns|launches|stop|applications|icons) md_library \"$@\"; exit $? ;;\n"
            + "  ''|-h|--help|help) md_library help; exit $? ;;\n"
            + "  image) shift\n"
            + "     if [ \"${1-}\" = run ] || [ \"${1-}\" = exec ] || [ \"${1-}\" = login ]; then\n"
            + "       \"$md_guest/libmagicdesk_guest_supervisor.so\" \"$md_guest/libmagicdesk_guest_bootstrap.so\" --probe >/dev/null || exit $?\n"
            + "     fi\n"
            + "     if [ \"$#\" -ge 2 ]; then md_image \"$@\"; fi\n"
            + "     exec \"$md_guest/libmagicdesk_guest_image.so\" \"$@\" ;;\n"
            + "  --import) exec \"$md_guest/libmagicdesk_guest_service.so\" \"$@\" ;;\n"
            + "  --probe) exec \"$md_guest/libmagicdesk_guest_supervisor.so\" \"$md_guest/libmagicdesk_guest_bootstrap.so\" \"$@\" ;;\n"
            + "  *) \"$md_guest/libmagicdesk_guest_supervisor.so\" \"$md_guest/libmagicdesk_guest_bootstrap.so\" --probe >/dev/null || exit $?\n"
            + LinuxAudioEnvironment.shrootArguments()
            + GamepadWire.shrootArguments()
            + "     md_libc_init\n"
            + "     exec \"$md_guest/libmagicdesk_guest_run.so\" --libc-registry \"$md_libc\" \"$@\" ;;\n"
            + "esac\n";
    private GuestRuntimeCommand() { }
}
