package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public final class LinuxAudioEnvironmentTest {
    @Test public void terminalVariablesRemainLiteral() throws Exception {
        var values = Map.of("PULSE_SERVER", "unix:/tmp/a ' b", "PIPEWIRE_REMOTE", "/tmp/native");
        assertEquals(values, TerminalLaunchEnvironment.decode(TerminalLaunchEnvironment.encode(values)));
        var builder = new ProcessBuilder(shell(), "-c", TerminalLaunchEnvironment.exports(values)
                + "printf '%s' \"$PULSE_SERVER\"");
        var result = BoundedProcessRunner.run(builder.start(), 5000, 4096);
        assertEquals(0, result.exitCode);
        assertEquals(values.get("PULSE_SERVER"), result.output);
    }

    @Test public void invalidPtyEnvironmentIsRejected() {
        for (String value : List.of("=value", "0KEY=value", "X;id=value", "A=x\0", "A"))
            assertThrows(IllegalArgumentException.class, () -> TerminalLaunchEnvironment.decode(new String[]{value}));
        assertThrows(IllegalArgumentException.class, () -> TerminalLaunchEnvironment.decode(new String[65]));
        assertThrows(IllegalArgumentException.class, () -> TerminalLaunchEnvironment.decode(new String[]{"A=" + "x".repeat(65536)}));
    }

    @Test public void shrootKeepsRoutesOptionalAndBeforeTheCommand() throws Exception {
        for (boolean enabled : List.of(false, true)) {
            var builder = new ProcessBuilder(shell(), "-c", "set -- -- /bin/echo 'a b'\n"
                    + LinuxAudioEnvironment.shrootArguments() + "printf '%s\\n' \"$@\"");
            builder.environment().remove("MAGICDESK_AUDIO_NATIVE_ENDPOINT");
            builder.environment().remove("MAGICDESK_AUDIO_PULSE_ENDPOINT");
            if (enabled) {
                builder.environment().put("MAGICDESK_AUDIO_NATIVE_ENDPOINT", "native-a");
                builder.environment().put("MAGICDESK_AUDIO_PULSE_ENDPOINT", "pulse-a");
            }
            var result = BoundedProcessRunner.run(builder.start(), 5000, 4096);
            assertEquals(0, result.exitCode);
            assertTrue(result.output.endsWith("--\n/bin/echo\na b\n"));
            assertEquals(enabled, result.output.contains("--socket-path\n/tmp/magicdesk-audio/pulse\npulse-a\n"));
            assertFalse(result.output.contains("su "));
        }
    }

    private static String shell() {
        org.junit.Assume.assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        return System.getenv("PREFIX") == null ? "/bin/sh" : System.getenv("PREFIX") + "/bin/sh";
    }
}
