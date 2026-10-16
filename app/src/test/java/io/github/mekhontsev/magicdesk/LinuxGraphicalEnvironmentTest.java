package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeFalse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class LinuxGraphicalEnvironmentTest {
    @Rule public final TemporaryFolder temporary = new TemporaryFolder();

    @Test public void waylandSessionRetainsExitAndCleanup() throws Exception {
        run(GraphicalProtocol.WAYLAND, 0, 23);
    }

    @Test public void failedBusDoesNotExecuteApplicationAndStillCleansDirectory() throws Exception {
        run(GraphicalProtocol.WAYLAND, 37, 37);
    }

    @Test public void ordinaryLinuxSessionsKeepTheirStandardTransport() throws Exception {
        run(GraphicalProtocol.X11, 0, 23);
    }

    @Test public void guestX11AuthorityPrecedesBusAndActivatedChildren() throws Exception {
        run(GraphicalProtocol.X11, 0, 23, true, "Y29va2ll");
    }

    @Test public void guestX11BusFailureCleansAuthority() throws Exception {
        run(GraphicalProtocol.X11, 37, 37, true, "Y29va2ll");
    }

    @Test public void guestWaylandNeedsNoX11Authority() throws Exception {
        run(GraphicalProtocol.WAYLAND, 0, 23, true, null);
    }

    @Test public void missingGuestAuthorityDoesNotStartBus() throws Exception {
        run(GraphicalProtocol.X11, 0, -1, true, null);
    }

    @Test public void malformedGuestAuthorityDoesNotStartBus() throws Exception {
        run(GraphicalProtocol.X11, 0, -1, true, "!not-base64!");
    }

    private void run(GraphicalProtocol protocol, int busExit, int expected) throws Exception {
        run(protocol, busExit, expected, false, null);
    }

    private void run(GraphicalProtocol protocol, int busExit, int expected,
            boolean guest, String authority) throws Exception {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        String shell = System.getenv("PREFIX") == null ? "/bin/sh" : System.getenv("PREFIX") + "/bin/sh";
        Path root = temporary.getRoot().toPath();
        Path bin = Files.createDirectory(root.resolve("bin"));
        Path runtime = Files.createDirectory(root.resolve("runtime ' space"));
        Path capture = root.resolve("bus-arguments");
        String checkAuthority = guest && protocol == GraphicalProtocol.X11
                ? "test \"$XAUTHORITY\" = \"$XDG_RUNTIME_DIR/Xauthority\"\n"
                    + "test \"$(cat \"$XAUTHORITY\")\" = cookie\n"
                    + "test -z \"${MAGICDESK_X11_AUTHORITY+x}\"\n" : "";
        script(bin, "mktemp", shell, "printf '%s\\n' \"$MD_DIRECTORY\"\n");
        script(bin, "dbus-run-session", shell,
                "printf '%s\\0' \"$@\" > \"$MD_CAPTURE\"\n"
                + "test \"$XDG_SESSION_TYPE\" = " + protocol.wireName + "\n"
                + "test \"$XDG_RUNTIME_DIR\" = \"$MD_DIRECTORY\"\n"
                + checkAuthority
                + (busExit == 0 ? "" : "exit " + busExit + "\n")
                + "test \"$1\" = --\nshift\nexec \"$@\"\n");
        String command = "set -eu; " + checkAuthority + "printf '%s' \"literal ' $value\"; exit 23";
        String invocation = ShellCommandLine.quote(shell) + " -c " + ShellCommandLine.quote(command);
        String wrapped = guest ? GuestGraphicalConnection.session(protocol, invocation)
                : LinuxGraphicalEnvironment.wrap(protocol, invocation);
        ProcessBuilder builder = new ProcessBuilder(shell, "-c", wrapped);
        builder.environment().put("PATH", bin + ":" + System.getenv("PATH"));
        builder.environment().put("MD_DIRECTORY", runtime.toString());
        builder.environment().put("MD_CAPTURE", capture.toString());
        builder.environment().put("value", "unchanged");
        builder.environment().remove("MAGICDESK_X11_AUTHORITY");
        if (authority != null) builder.environment().put("MAGICDESK_X11_AUTHORITY", authority);
        var result = BoundedProcessRunner.run(builder.start(), 5000, 16384);
        if (expected == -1) {
            assertNotEquals(result.output, 0, result.exitCode);
            assertFalse(Files.exists(capture));
            assertFalse(Files.exists(runtime));
            return;
        }
        assertEquals(result.output, expected, result.exitCode);
        assertEquals(busExit == 0 ? "literal ' unchanged" : "", result.output);
        assertFalse(Files.exists(runtime));
        assertEquals(List.of("--", shell, "-c", command), List.of(Files.readString(capture).split("\0")));
    }

    private static void script(Path bin, String name, String shell, String body) throws Exception {
        Path file = Files.writeString(bin.resolve(name), "#!" + shell + "\nset -eu\n" + body);
        assertTrue(file.toFile().setExecutable(true));
    }
}
