package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.List;

/** The guest helper owns session setup/cleanup; Exec carries only its arguments. */
final class LinuxGraphicalEnvironment {
    static List<String> arguments(String helper, GraphicalProtocol protocol, boolean routed,
            boolean files, List<String> command) {
        var arguments = new ArrayList<>(List.of(helper, "--session", protocol == GraphicalProtocol.X11 && routed
                ? "x11-routed" : protocol.wireName));
        if (files) arguments.add("--files");
        arguments.add("--");
        arguments.addAll(command);
        return List.copyOf(arguments);
    }

    private LinuxGraphicalEnvironment() { }
}
