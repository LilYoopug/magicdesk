package io.github.mekhontsev.magicdesk;

import java.util.List;

/** Explicit guest addresses and per-launch authentication; no host filesystem aliases. */
final class GuestGraphicalConnection {
    static final String WAYLAND_PATH = "/tmp/magicdesk-wayland/wayland-0";

    static GuestLaunchPlan plan(GuestEnvironment environment, String directory, String command,
            GraphicalProtocol protocol) {
        return new GuestLaunchPlan(environment, directory, List.of(
                "/tmp/magicdesk-helpers/libmagicdesk_guest_files.so", "--", "/bin/sh", "-lc",
                session(protocol, "/bin/sh -lc " + ShellCommandLine.quote(command))));
    }

    static String invocation(GuestLaunchPlan plan, GraphicalProtocol protocol) {
        return invocation(plan, protocol, false);
    }

    static String invocation(GuestLaunchPlan plan, GraphicalProtocol protocol, boolean files) {
        String endpoint = "\"${MAGICDESK_GRAPHICS_ENDPOINT:?Missing graphical endpoint}\"";
        String source = protocol == GraphicalProtocol.WAYLAND ? ShellCommandLine.quote(WAYLAND_PATH)
                : "\"/tmp/.X11-unix/X${DISPLAY#:}\"";
        String prepare = files ? quoted(new GuestLaunchPlan(plan.environment(), plan.directory(),
                List.of("/bin/sh", "-c", "mkdir -p /tmp/magicdesk-helpers")).arguments()) + "; " : "";
        String fileOptions = files ? " --bind-ro \"${MAGICDESK_GUEST_LIBRARIES:?Missing helpers}\" /tmp/magicdesk-helpers"
                + " --env \"MAGICDESK_GUEST_FILES_SOCKET=$MAGICDESK_GUEST_FILES_SOCKET\""
                + " --env \"MAGICDESK_GUEST_FILES_TOKEN=$MAGICDESK_GUEST_FILES_TOKEN\"" : "";
        return "set -eu; " + prepare + "exec " + quoted(plan.launcherArguments()) + fileOptions
                + (protocol == GraphicalProtocol.X11 ? " --socket-resource-path " : " --socket-path ") + source + " " + endpoint
                + (protocol == GraphicalProtocol.X11 ? " --socket-resource-abstract " + source + " " + endpoint : "")
                + " -- " + quoted(plan.command());
    }

    static String session(GraphicalProtocol protocol, String command) {
        // Activated D-Bus services must inherit the same authority as the client.
        String prepare = protocol != GraphicalProtocol.X11 ? "" : ": \"${MAGICDESK_X11_AUTHORITY:?Missing X11 authority}\"; "
                + "export XAUTHORITY=\"$XDG_RUNTIME_DIR/Xauthority\"; "
                + "printf '%s' \"$MAGICDESK_X11_AUTHORITY\" | base64 -d > \"$XAUTHORITY\"; "
                + "unset MAGICDESK_X11_AUTHORITY; ";
        return LinuxGraphicalEnvironment.wrap(protocol, prepare, command);
    }

    private static String quoted(List<String> arguments) {
        return String.join(" ", arguments.stream().map(ShellCommandLine::quote).toList());
    }
    private GuestGraphicalConnection() { }
}
