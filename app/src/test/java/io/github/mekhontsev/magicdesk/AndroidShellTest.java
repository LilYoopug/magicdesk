package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class AndroidShellTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();

    @Test public void interpreterPathsUseAndroidSeparatorsOnEveryBuildHost() {
        assertEquals("/apk/lib/arm64/libmagicdesk_mksh.so", AndroidShell.path("/apk/lib/arm64"));
        assertEquals("/apk/lib/arm64/libmagicdesk_mksh.so", AndroidShell.path("/apk/lib/arm64/"));
        assertEquals("/libmagicdesk_mksh.so", AndroidShell.path("/"));
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.path((String) null));
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.path("relative/lib"));
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.path("C:\\apk\\lib"));
    }

    @Test public void generatedScriptsSelectThePackagedInterpreterExplicitly() {
        String shell = AndroidShell.path("/apk/lib/arm64");
        for (String body : new String[]{CommandShellEnvironment.BODY,
                CommandShellEnvironment.CONNECT_BODY, GuestRuntimeCommand.BODY}) {
            String script = AndroidShell.script(shell, body);
            assertTrue(script.startsWith("#!/apk/lib/arm64/libmagicdesk_mksh.so\n"));
            assertTrue(script.contains("export MAGICDESK_ANDROID_SHELL=" + ShellCommandLine.quote(shell)));
            assertTrue(script.endsWith(body));
            assertFalse(script.contains("/system/bin/sh"));
        }
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.script("/bad path/mksh", ""));
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.script("/bad\npath/mksh", ""));
        assertThrows(IllegalArgumentException.class, () -> AndroidShell.script("mksh", ""));
    }

    @Test public void aliasesAreAtomicReferencesToOneInterpreterNotCopies() throws Exception {
        // Windows host symlink privileges are unrelated to the Android runtime contract.
        Assume.assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        Path directory = temporary.newFolder("bin").toPath();
        Path original = temporary.newFile("old-interpreter").toPath();
        Path next = temporary.newFile("new-interpreter").toPath();
        Files.writeString(original, "unchanged old executable");
        Files.writeString(next, "unchanged new executable");
        AndroidShell.installAliases(directory, original.toString());
        AndroidShell.installAliases(directory, original.toString());
        AndroidShell.installAliases(directory, next.toString());
        for (String name : new String[]{"sh", "mksh"}) {
            assertTrue(Files.isSymbolicLink(directory.resolve(name)));
            assertEquals(next, Files.readSymbolicLink(directory.resolve(name)));
        }
        assertEquals("unchanged old executable", Files.readString(original));
        assertEquals("unchanged new executable", Files.readString(next));
        try (var files = Files.list(directory)) { assertEquals(2, files.count()); }
    }

    @Test public void termuxSetupDoesNotReplaceItsShellOrInstallShAliases() {
        String script = CommandShellEnvironment.termuxSetup("localhost:1", "/apk/base.apk", "/apk/lib");
        assertTrue(script.contains("libmagicdesk_mksh.so"));
        assertFalse(script.contains("export SHELL="));
        assertFalse(script.contains("$md_bin/sh"));
        assertFalse(script.contains("/system/bin/sh"));
    }

    @Test public void androidLaunchAdaptersHaveNoImplicitSystemShell() throws Exception {
        Path source = Path.of("src/main/java/io/github/mekhontsev/magicdesk");
        for (String file : new String[]{"ShellCommandService", "ShellExecutionEnvironment",
                "ShellCommandExecutor", "CommandExecution", "RunCommandLaunch", "ShellScriptLauncher",
                "GuestEnvironmentOperations", "X11Execution", "WaylandExecution",
                "ShellDisplayRecordingSession", "platform/nubia/NubiaCapabilityProbe"}) {
            assertFalse(file, Files.readString(source.resolve(file + ".java")).contains("/system/bin/sh"));
        }
    }
}
