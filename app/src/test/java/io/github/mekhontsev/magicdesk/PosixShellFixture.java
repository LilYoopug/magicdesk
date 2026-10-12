package io.github.mekhontsev.magicdesk;

import java.nio.charset.StandardCharsets;
import static org.junit.Assert.assertFalse;

/** Carries shell source as stdin, independently of Windows command-line quoting. */
final class PosixShellFixture {
    static String executable() {
        return System.getenv().getOrDefault("MAGICDESK_TEST_BASH", "bash").replace('\\', '/');
    }

    static BoundedProcessRunner.BinaryResult run(String script) throws Exception {
        Process process = new ProcessBuilder(executable(), "--noprofile", "--norc", "-s").start();
        try {
            try (var input = process.getOutputStream()) {
                input.write((script + "\n").getBytes(StandardCharsets.UTF_8));
            }
            // EVENT_WAIT: shell exit and output EOF; timeout fails the fixture and terminates it.
            var result = BoundedProcessRunner.runBinary(process, 10_000, 16_384, 16_384);
            assertFalse(result.stdoutTruncated);
            assertFalse(result.stderrTruncated);
            return result;
        } finally {
            process.destroyForcibly();
        }
    }

    private PosixShellFixture() { }
}
