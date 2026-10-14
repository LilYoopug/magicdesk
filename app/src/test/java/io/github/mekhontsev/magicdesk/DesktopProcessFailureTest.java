package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class DesktopProcessFailureTest {
    @Test
    public void exposesStableDiagnosticIdentity() {
        assertEquals(
                "DESKTOP-PROCESS-CRASH-001",
                DesktopProcessFailure.code(DesktopProcessFailure.CRASH));
        assertEquals(
                "DESKTOP-PROCESS-ANR-001",
                DesktopProcessFailure.code(DesktopProcessFailure.ANR));
        assertEquals("", DesktopProcessFailure.code(99));
    }

    @Test
    public void compactsAndLimitsFailureReason() {
        final String reason = "  Input\n\tdispatching  "
                + repeat('x', 300);

        final String compact = DesktopProcessFailure.compactReason(reason);

        assertEquals(160, compact.length());
        assertFalse(compact.contains("\n"));
        assertFalse(compact.contains("\t"));
        assertFalse(compact.contains("  "));
    }

    @Test
    public void formatsTaskCorrelationWithoutStackTrace() {
        assertEquals(
                "process=com.example.app | pid=123 | task=42 | display=2"
                        + " | windowingMode=5"
                        + " | top=com.example.app/.MainActivity"
                        + " | reason=Illegal state",
                DesktopProcessFailure.technicalDetail(
                        "com.example.app",
                        123,
                        42,
                        2,
                        5,
                        "com.example.app/.MainActivity",
                        "Illegal state"));
    }

    private static String repeat(final char character, final int count) {
        final StringBuilder result = new StringBuilder(count);
        for (int index = 0; index < count; index++) {
            result.append(character);
        }
        return result.toString();
    }

    @Test
    public void carriesBoundedMultilineEvidenceAndVersion() throws Exception {
        var failure = new DesktopProcessFailureEvent(1, "com.example:renderer", 12,
                42, 10, 4, 5, "com.example/.Main", "IndexOutOfBoundsException",
                "index=7", "at example.Main.go(Main.java:1)\nCaused by: test\n" + "x".repeat(20_000));
        assertEquals("com.example", failure.packageName());
        assertTrue(failure.stackTrace.length() < 12_100);
        assertTrue(failure.stackTrace.endsWith("[truncated]"));
        String detail = failure.technicalDetail("1.2 (12)");
        assertTrue(detail.contains("packageVersion=1.2 (12)"));
        assertTrue(detail.contains("user=10"));
        assertTrue(detail.contains("\n Caused by: test"));
        assertTrue(failure.summary().getBoolean("stackCaptured"));
        assertFalse(failure.summary().has("stackTrace"));
    }

    @Test
    public void missingStackRemainsMissingAndTruncationPreservesUnicode() {
        var failure = new DesktopProcessFailureEvent(1, null, 1, 2, -1, 0, 5,
                null, null, null, null);
        assertEquals("", failure.stackTrace);
        assertFalse(failure.technicalDetail("unavailable").contains("stack:"));
        assertEquals("a\n[truncated]", DesktopProcessFailureEvent.bounded("a\uD83D\uDE00b", 2));
    }
}
