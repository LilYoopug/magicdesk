package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import android.content.ComponentName;
import android.graphics.Rect;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

public final class ShellProcessFailureTrackerTest {
    private static final int DISPLAY_ID = 2;
    private static final int TASK_ID = 42;
    private static final int WINDOWING_MODE_FREEFORM = 5;
    private static final String APP_PACKAGE = "com.example.app";
    private static final String PERMISSION_PACKAGE =
            "com.android.permissioncontroller";

    @Test
    public void reportsCrashForDesktopProcessAndItsSubprocess() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = tracker(listener);

        tracker.onProcessCrashed(
                APP_PACKAGE + ":renderer", 123, "Illegal state", "Detail", "at example.Main.run(Main.java:1)");

        assertEquals(DesktopProcessFailure.CRASH, listener.type);
        assertEquals(APP_PACKAGE + ":renderer", listener.processName);
        assertEquals(123, listener.pid);
        assertEquals(TASK_ID, listener.taskId);
        assertEquals(DISPLAY_ID, listener.displayId);
        assertEquals(WINDOWING_MODE_FREEFORM, listener.windowingMode);
        assertEquals("", listener.topActivity);
        assertEquals("Illegal state", listener.reason);
        assertEquals("Detail", listener.failure.message);
        assertEquals("at example.Main.run(Main.java:1)", listener.failure.stackTrace);
        assertEquals(APP_PACKAGE, listener.failure.packageName());
    }

    @Test
    public void matchesTransientSystemProcessByTopPackage() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = emptyTracker(listener);
        tracker.configure(DISPLAY_ID);
        tracker.observeTasks(
                DISPLAY_ID,
                Collections.singletonList(task(
                        APP_PACKAGE,
                        PERMISSION_PACKAGE)));

        tracker.onProcessCrashed(
                PERMISSION_PACKAGE, 321, "Permission UI failed", "", "");

        assertEquals(TASK_ID, listener.taskId);
        assertEquals("", listener.topActivity);
    }

    @Test
    public void ignoresProcessOutsideDesktopTaskSnapshot() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = tracker(listener);

        tracker.onProcessCrashed("com.example.other", 123, "Failure", "", "");

        assertNull(listener.processName);
    }

    @Test
    public void matchesExactUiProcessBeforeEarlierWindowFromTheSamePackage() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = emptyTracker(listener);
        tracker.configure(DISPLAY_ID);
        tracker.observeTasks(DISPLAY_ID, List.of(
                task(APP_PACKAGE, APP_PACKAGE, 41, APP_PACKAGE),
                task(APP_PACKAGE, APP_PACKAGE, 42, APP_PACKAGE + ":editor")));
        tracker.onProcessCrashed(APP_PACKAGE + ":editor", 123, "Failure", "", "stack");
        assertEquals(42, listener.taskId);
        tracker.onProcessEarlyNotResponding(APP_PACKAGE + ":editor", 123, "ANR");
        tracker.observeTasks(DISPLAY_ID, Collections.emptyList());
        tracker.onProcessNotResponding(APP_PACKAGE + ":editor", 123);
        assertEquals(42, listener.taskId);
    }

    @Test
    public void retainsEarlyAnrTaskContextUntilFinalCallback() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = tracker(listener);

        tracker.onProcessEarlyNotResponding(
                APP_PACKAGE, 123, "Input dispatching\n timed out");
        tracker.observeTasks(DISPLAY_ID, Collections.emptyList());
        tracker.onProcessNotResponding(APP_PACKAGE, 123);

        assertEquals(DesktopProcessFailure.ANR, listener.type);
        assertEquals(TASK_ID, listener.taskId);
        assertEquals("Input dispatching timed out", listener.reason);
    }

    @Test
    public void abandonedEarlyAnrsRetainOnlyTheMostRecentContexts() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = tracker(listener);
        for (int pid = 0; pid <= ShellProcessFailureTracker.MAX_PENDING_ANRS; pid++) {
            tracker.onProcessEarlyNotResponding(APP_PACKAGE, pid, "pending " + pid);
        }
        tracker.observeTasks(DISPLAY_ID, Collections.emptyList());
        tracker.onProcessNotResponding(APP_PACKAGE, 0);
        assertNull(listener.processName);
        tracker.onProcessNotResponding(APP_PACKAGE, ShellProcessFailureTracker.MAX_PENDING_ANRS);
        assertEquals(TASK_ID, listener.taskId);
        assertEquals("pending " + ShellProcessFailureTracker.MAX_PENDING_ANRS, listener.reason);
    }

    @Test
    public void ignoresFinalAnrWithoutDesktopContext() {
        final RecordingListener listener = new RecordingListener();
        final ShellProcessFailureTracker tracker = tracker(listener);
        tracker.observeTasks(DISPLAY_ID, Collections.emptyList());

        tracker.onProcessNotResponding(APP_PACKAGE, 123);

        assertNull(listener.processName);
    }

    private static ShellProcessFailureTracker tracker(
            final RecordingListener listener) {
        final ShellProcessFailureTracker tracker = emptyTracker(listener);
        tracker.configure(DISPLAY_ID);
        tracker.observeTasks(
                DISPLAY_ID,
                Collections.singletonList(task(
                        APP_PACKAGE,
                        APP_PACKAGE)));
        return tracker;
    }

    private static ShellProcessFailureTracker emptyTracker(
            final RecordingListener listener) {
        return new ShellProcessFailureTracker(listener);
    }

    private static FrameworkTaskSnapshot task(
            final String packageName,
            final String topPackage) {
        return task(packageName, topPackage, TASK_ID, null);
    }

    private static FrameworkTaskSnapshot task(
            final String packageName, final String topPackage,
            final int taskId, final String processName) {
        return new FrameworkTaskSnapshot(
                null,
                taskId,
                taskId,
                DISPLAY_ID,
                1,
                WINDOWING_MODE_FREEFORM,
                1,
                new ComponentName(packageName, packageName + ".MainActivity"),
                null,
                packageName + "/.MainActivity",
                "",
                packageName,
                topPackage,
                -1,
                processName,
                new Rect(10, 20, 800, 600),
                true,
                false,
                Integer.valueOf(0));
    }

    private static final class RecordingListener implements
            ShellProcessFailureTracker.Listener {
        int type;
        String processName;
        int pid;
        int taskId;
        int displayId;
        int windowingMode;
        String topActivity;
        String reason;
        DesktopProcessFailureEvent failure;

        @Override
        public void onDesktopProcessFailure(
                final DesktopProcessFailureEvent event) {
            failure = event;
            type = event.type;
            processName = event.processName;
            pid = event.pid;
            taskId = event.taskId;
            displayId = event.displayId;
            windowingMode = event.windowingMode;
            topActivity = event.topActivity;
            reason = event.reason;
        }
    }
}
