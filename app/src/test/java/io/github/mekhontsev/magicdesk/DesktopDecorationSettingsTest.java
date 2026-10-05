package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class DesktopDecorationSettingsTest {
    private final DesktopDecorationSettings setting = new DesktopDecorationSettings();

    @Test public void bothDirectionsVerifyBeforeOneRestart() throws Exception {
        for (boolean before : new boolean[]{false, true}) {
            final var access = new FakeAccess();
            access.value = before;
            setting.apply(access, before);
            assertEquals(!before, access.value);
            assertEquals(List.of("read", "prepare", "write", "read", "restart"), access.events);
        }
    }

    @Test public void missingAccessOrActiveDesktopCannotMutateAnything() {
        final var access = new FakeAccess();
        access.allowed = false;
        assertThrows(IOException.class, () -> setting.apply(access, false));
        assertTrue(access.events.isEmpty());
    }

    @Test public void staleConfirmationDoesNotInvertANewValue() {
        final var access = new FakeAccess();
        access.value = true;
        assertThrows(IOException.class, () -> setting.apply(access, false));
        assertEquals(List.of("read"), access.events);
    }

    @Test public void restartUnavailableOrRateLimitedLeavesPropertyAlone() {
        final var access = new FakeAccess();
        access.prepareError = new IOException("restart unavailable");
        assertThrows(IOException.class, () -> setting.apply(access, false));
        assertFalse(access.value);
        assertEquals(List.of("read", "prepare"), access.events);
    }

    @Test public void rejectedOrUnverifiedWritesNeverRestartSystemUi() {
        for (boolean fail : new boolean[]{false, true}) {
            final var access = new FakeAccess();
            access.ignoreWrite = true;
            access.writeError = fail ? new IOException("denied") : null;
            assertThrows(IOException.class, () -> setting.apply(access, false));
            assertFalse(access.events.contains("restart"));
        }
    }

    @Test public void sessionStartingDuringPreparationStopsTheWrite() {
        final var access = new FakeAccess();
        access.afterPrepare = () -> access.allowed = false;
        assertThrows(IOException.class, () -> setting.apply(access, false));
        assertEquals(List.of("read", "prepare"), access.events);
    }

    @Test public void sessionStartingAfterWriteStopsTheRestartAndReportsPartialChange() {
        final var access = new FakeAccess();
        access.afterWrite = () -> access.allowed = false;
        final var error = assertThrows(IOException.class, () -> setting.apply(access, false));
        assertTrue(error.getMessage().contains("Device restrictions=true"));
        assertTrue(access.value);
        assertFalse(access.events.contains("restart"));
    }

    @Test public void unconfirmedRestartIsNotRetriedOrRolledBack() {
        final var access = new FakeAccess();
        access.restartError = new IOException("timed out");
        final var error = assertThrows(IOException.class, () -> setting.apply(access, false));
        assertTrue(error.getMessage().contains("No automatic retry"));
        assertTrue(access.value);
        assertEquals(List.of("read", "prepare", "write", "read", "restart"), access.events);
    }

    @Test public void busyGuardCoversOtherActivitiesAndReleasesAfterFailure() throws Exception {
        final var access = new FakeAccess();
        final var other = new FakeAccess();
        access.afterWrite = () -> assertThrows(IOException.class, () -> setting.apply(other, false));
        access.restartError = new IOException("unavailable");
        assertThrows(IOException.class, () -> setting.apply(access, false));
        assertTrue(other.events.isEmpty());
        setting.apply(other, false);
        assertTrue(other.value);
    }

    private static final class FakeAccess implements DesktopDecorationSettings.Access {
        final List<String> events = new ArrayList<>();
        boolean allowed = true, value, ignoreWrite;
        IOException prepareError, writeError, restartError;
        Runnable afterPrepare = () -> {}, afterWrite = () -> {};
        public boolean canChange() { return allowed; }
        public boolean read() { events.add("read"); return value; }
        public void prepareRestart() throws IOException {
            events.add("prepare");
            if (prepareError != null) throw prepareError;
            afterPrepare.run();
        }
        public void write(boolean enabled) throws IOException {
            events.add("write");
            if (writeError != null) throw writeError;
            if (!ignoreWrite) value = enabled;
            afterWrite.run();
        }
        public void restart() throws IOException {
            events.add("restart");
            if (restartError != null) throw restartError;
        }
    }
}
