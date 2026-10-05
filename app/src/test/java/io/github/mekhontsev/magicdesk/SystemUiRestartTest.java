package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.io.IOException;
import org.junit.Test;

public class SystemUiRestartTest {
    @Test public void targetsOnlyTheObservedProcessNotAndroidUserspace() {
        assertEquals("/system/bin/am crash --user 0 4001", SystemUiRestart.restartCommand(4001));
        for (int pid : new int[]{-1, 0, 1}) {
            assertThrows(IllegalArgumentException.class, () -> SystemUiRestart.restartCommand(pid));
        }
    }

    @Test public void absenceOrTheOldProcessIsNotRecovery() {
        assertFalse(SystemUiRestart.replaced(4001, 0));
        assertFalse(SystemUiRestart.replaced(4001, 4001));
        assertTrue(SystemUiRestart.replaced(4001, 4002));
    }

    @Test public void processObservationRejectsAmbiguousAndInvalidResults() throws Exception {
        assertEquals(0, SystemUiRestart.parsePid("\n"));
        assertEquals(4001, SystemUiRestart.parsePid("4001\n"));
        for (String invalid : new String[]{"4001 4002", "denied", "-1", "1", "0"}) {
            assertThrows(IOException.class, () -> SystemUiRestart.parsePid(invalid));
        }
    }

    @Test public void persistentAttemptLimitsSurviveActivityRecreationButNotDeviceBoot() {
        assertTrue(SystemUiRestart.intervalElapsed(2, -2, 1000, -1));
        assertFalse(SystemUiRestart.intervalElapsed(2, 2, 1000, 1000));
        assertFalse(SystemUiRestart.intervalElapsed(2, 2, 60_999, 1000));
        assertTrue(SystemUiRestart.intervalElapsed(2, 2, 61_000, 1000));
        assertTrue(SystemUiRestart.intervalElapsed(3, 2, 2000, 1000));
        assertTrue(SystemUiRestart.intervalElapsed(-1, -1, 100, 1000));
    }
}
