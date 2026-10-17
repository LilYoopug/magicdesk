package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public final class DesktopWindowingPropertiesTest {
    @Test
    public void propertyAllowlistContainsOnlyReviewedDesktopKeys() {
        final DesktopWindowingProperties.Property[] properties =
                DesktopWindowingProperties.Property.values();

        assertEquals(2, properties.length);
        assertEquals(
                "persist.wm.debug.desktop_mode_enforce_device_restrictions",
                DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS.key);
        assertEquals(
                "persist.wm.debug.desktop_use_rounded_corners",
                DesktopWindowingProperties.Property.ROUNDED_CORNERS.key);
    }

    @Test
    public void valuesAreLimitedToBooleanOrEmptyRestore() {
        assertTrue(DesktopWindowingProperties.isBooleanOrEmpty(""));
        assertTrue(DesktopWindowingProperties.isBooleanOrEmpty("true"));
        assertTrue(DesktopWindowingProperties.isBooleanOrEmpty("false"));

        assertFalse(DesktopWindowingProperties.isBooleanOrEmpty(null));
        assertFalse(DesktopWindowingProperties.isBooleanOrEmpty("1"));
        assertFalse(DesktopWindowingProperties.isBooleanOrEmpty("false; reboot"));
    }

    @Test public void allPropertiesVerifyBothBooleansAndEmptyRestore() throws Exception {
        for (final var property : DesktopWindowingProperties.Property.values()) {
            for (final String expected : List.of("true", "false", "")) {
                final List<String> operations = new ArrayList<>();
                final String[] current = {expected.isEmpty() ? "false" : ""};
                assertTrue(DesktopWindowingProperties.write(property, expected, key -> {
                    assertSame(property, key);
                    operations.add("read");
                    return current[0];
                }, (key, value) -> {
                    assertSame(property, key);
                    assertEquals(expected, value);
                    operations.add("write");
                    current[0] = value;
                    return "Result: Parcel(00000000 '....')";
                }));
                assertEquals(List.of("read", "write", "read"), operations);
            }
        }
    }

    @Test public void matchingValueDoesNotRequireWriterOrRepeatMutation() throws Exception {
        for (final String expected : List.of("", "true", "false")) {
            assertFalse(DesktopWindowingProperties.write(
                    DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, expected,
                    property -> expected, (property, value) -> {
                        throw new AssertionError("unchanged property must not be written");
                    }));
        }
    }

    @Test public void rejectsInvalidRequestsBeforeAnyIo() {
        final DesktopWindowingProperties.PropertyReader reader = property -> {
            throw new AssertionError("invalid request must not read");
        };
        final DesktopWindowingProperties.Writer writer = (property, value) -> {
            throw new AssertionError("invalid request must not write");
        };
        assertThrows(IllegalArgumentException.class, () -> DesktopWindowingProperties.write(
                null, "false", reader, writer));
        for (final String value : new String[] {null, "0", "false; reboot", "false\n"}) {
            assertThrows(IllegalArgumentException.class, () -> DesktopWindowingProperties.write(
                    DesktopWindowingProperties.Property.ROUNDED_CORNERS, value, reader, writer));
        }
    }

    @Test public void initialReadFailureDoesNotWrite() {
        final IOException denied = new IOException("property read denied");
        assertSame(denied, assertThrows(IOException.class, () -> DesktopWindowingProperties.write(
                DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, "false",
                property -> { throw denied; }, (property, value) -> {
                    throw new AssertionError("no confirmed initial state");
                })));
    }

    @Test public void successfulCommandWithBinderDenialIsNotSuccessfulWrite() {
        final String reply = "Result: Parcel(ffffffff ...)\n"
                + "setSystemProperties requires WRITE_SECURE_SETTINGS permission";
        final IOException error = assertThrows(IOException.class,
                () -> DesktopWindowingProperties.write(
                        DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, "false",
                        property -> "", (property, value) -> reply));
        assertTrue(error.getMessage().contains("expected=false observed=<empty>"));
        assertTrue(error.getMessage().contains("WRITE_SECURE_SETTINGS"));
        assertFalse(error.getMessage().contains("\n"));
    }

    @Test public void successReplyAloneDoesNotProveRestoration() {
        final IOException error = assertThrows(IOException.class,
                () -> DesktopWindowingProperties.write(
                        DesktopWindowingProperties.Property.ROUNDED_CORNERS, "",
                        property -> "false", (property, value) -> "Result: Parcel(00000000)"));
        assertTrue(error.getMessage().contains("expected=<empty> observed=false"));
    }

    @Test public void writerFailureIsNotRetriedUnderAnotherIdentity() {
        for (final String reason : List.of("service unavailable", "permission denied", "timed out")) {
            final IOException failure = new IOException(reason);
            final AtomicInteger writes = new AtomicInteger();
            assertSame(failure, assertThrows(IOException.class, () -> DesktopWindowingProperties.write(
                    DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, "false",
                    property -> "", (property, value) -> {
                        writes.incrementAndGet();
                        throw failure;
                    })));
            assertEquals(1, writes.get());
        }
    }

    @Test public void failedReadbackRetainsTransportReplyAndCause() {
        final AtomicInteger reads = new AtomicInteger();
        final IOException failure = new IOException("getprop unavailable");
        final IOException error = assertThrows(IOException.class, () -> DesktopWindowingProperties.write(
                DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, "false", property -> {
                    if (reads.getAndIncrement() == 0) return "";
                    throw failure;
                }, (property, value) -> "Binder reply"));
        assertSame(failure, error.getCause());
        assertTrue(error.getMessage().contains("getprop unavailable"));
        assertTrue(error.getMessage().contains("Binder reply"));
    }

    @Test public void failureDiagnosticsHaveBoundedSize() {
        final IOException error = assertThrows(IOException.class, () -> DesktopWindowingProperties.write(
                DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, "false",
                property -> "", (property, value) -> "x".repeat(64 * 1024)));
        assertTrue(error.getMessage().contains("[truncated]"));
        assertTrue(error.getMessage().length() < 33 * 1024);
    }
}
