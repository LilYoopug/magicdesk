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

    @Test public void cleanupDetachesNestedMountsWithoutTouchingAnotherSession() throws Exception {
        mountedCleanup(23, 0, false, false);
    }

    @Test public void cleanupSupportsLegacyFuseAndConcurrentUnmount() throws Exception {
        mountedCleanup(0, 1, false, true);
    }

    @Test public void rejectedUnmountRetainsDirectoryAndFailsSuccessfulCommand() throws Exception {
        mountedCleanup(0, 1, true, false);
    }

    @Test public void rejectedUnmountRetainsOriginalCommandFailure() throws Exception {
        mountedCleanup(23, 1, true, false);
    }

    @Test public void unavailableMountInventoryNeverDeletesRuntime() throws Exception {
        mountedCleanup(0, 0, true, false, true);
    }

    private void mountedCleanup(int applicationExit, int helperExit, boolean retain,
            boolean legacy) throws Exception {
        mountedCleanup(applicationExit, helperExit, retain, legacy, false);
    }

    private void mountedCleanup(int applicationExit, int helperExit, boolean retain,
            boolean legacy, boolean missingInventory) throws Exception {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        String shell = System.getenv("PREFIX") == null ? "/bin/sh" : System.getenv("PREFIX") + "/bin/sh";
        Path root = temporary.getRoot().toPath();
        Path bin = Files.createDirectory(root.resolve("bin"));
        Path runtime = Files.createDirectory(root.resolve("runtime ' space\\slash\nline"));
        Path outer = Files.createDirectory(runtime.resolve("outer"));
        Path nested = Files.createDirectory(outer.resolve("nested ' \\tab\tline\n"));
        Path foreign = Files.createDirectory(Path.of(runtime + "-other"));
        Path saved = Files.writeString(foreign.resolve("keep"), "foreign document");
        Path local = Files.writeString(runtime.resolve("keep"), "local file");
        Path mounts = root.resolve("mounts");
        Path calls = root.resolve("calls");
        String outside = mountRecord(foreign, "fuse.portal");
        if (!missingInventory) Files.writeString(mounts,
                outside + mountRecord(outer, "tmpfs") + mountRecord(nested, "fuse.portal"));
        Files.writeString(root.resolve("after-child"), outside + mountRecord(outer, "tmpfs"));
        Files.writeString(root.resolve("after-parent"), outside);
        script(bin, "mktemp", shell, "test \"$(( $(umask) ))\" = 63\nprintf '%s\\n' \"$MD_DIRECTORY\"\n");
        script(bin, "dbus-run-session", shell, "shift\nexec \"$@\"\n");
        script(bin, legacy ? "fusermount" : "fusermount3", shell,
                "test \"$1 $2 $3\" = '-u -z --'\n"
                + "printf '%s\\0' \"$4\" >> \"$MD_CALLS\"\n"
                + (retain ? "" : "cp \"$MD_ROOT/after-child\" \"$MD_MOUNTS\"\n")
                + "exit " + helperExit + "\n");
        script(bin, "umount", shell, "test \"$1 $2\" = '-l --'\n"
                + "printf '%s\\0' \"$3\" >> \"$MD_CALLS\"\n"
                + (retain ? "" : "cp \"$MD_ROOT/after-parent\" \"$MD_MOUNTS\"\n")
                + "exit " + helperExit + "\n");
        String wrapped = sessionScript()
                .replace("/proc/self/mounts", ShellCommandLine.quote(mounts.toString()));
        // Keep the legacy-helper case independent of the build host's packages.
        if (legacy) wrapped = wrapped.replace("fusermount3", "md_missing_fusermount3");
        ProcessBuilder builder = new ProcessBuilder(shell, "-c", wrapped,
                "magicdesk-session", "wayland", shell, "-c", "exit " + applicationExit).redirectErrorStream(true);
        builder.environment().put("PATH", bin + ":" + System.getenv("PATH"));
        builder.environment().put("MD_DIRECTORY", runtime.toString());
        builder.environment().put("MD_ROOT", root.toString());
        builder.environment().put("MD_MOUNTS", mounts.toString());
        builder.environment().put("MD_CALLS", calls.toString());
        var result = BoundedProcessRunner.run(builder.start(), 5000, 16384);
        assertEquals(result.output, applicationExit != 0 ? applicationExit : retain ? 1 : 0, result.exitCode);
        assertEquals("foreign document", Files.readString(saved));
        assertEquals(retain, Files.exists(runtime));
        if (retain) {
            assertEquals("local file", Files.readString(local));
            assertTrue(result.output, result.output.contains("runtime cleanup failed"));
        }
        if (missingInventory) assertFalse(Files.exists(calls));
        else assertEquals(List.of(nested.toString(), outer.toString()),
                List.of(Files.readString(calls).split("\0")));
    }

    private static String mountRecord(Path path, String type) {
        String encoded = path.toString().replace("\\", "\\134").replace(" ", "\\040")
                .replace("\t", "\\011").replace("\n", "\\012");
        return "none " + encoded + " " + type + " rw 0 0\n";
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
        script(bin, "mktemp", shell, "test \"$(( $(umask) ))\" = 63\nprintf '%s\\n' \"$MD_DIRECTORY\"\n");
        script(bin, "dbus-run-session", shell,
                "test \"$(( $(umask) ))\" = 23\n"
                + "printf '%s\\0' \"$@\" > \"$MD_CAPTURE\"\n"
                + "test \"$XDG_SESSION_TYPE\" = " + protocol.wireName + "\n"
                + "test \"$XDG_RUNTIME_DIR\" = \"$MD_DIRECTORY\"\n"
                + checkAuthority
                + (busExit == 0 ? "" : "exit " + busExit + "\n")
                + "test \"$1\" = --\nshift\nexec \"$@\"\n");
        String command = "set -eu; test \"$(( $(umask) ))\" = 23; "
                + checkAuthority + "printf '%s' \"literal ' $value\"; exit 23";
        ProcessBuilder builder = new ProcessBuilder(shell, "-c", "umask 027; " + sessionScript(),
                "magicdesk-session", guest && protocol == GraphicalProtocol.X11 ? "x11-routed" : protocol.wireName,
                shell, "-c", command);
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

    private static String sessionScript() throws Exception {
        return Files.readString(Path.of("../native/magicdesk_guest_session.sh")).replace("\r\n", "\n");
    }
}
