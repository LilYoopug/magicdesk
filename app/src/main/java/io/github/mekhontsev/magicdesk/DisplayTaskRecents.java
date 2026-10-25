package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Intent;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.Looper;
import android.view.Display;
import java.util.HashMap;
import java.util.Map;

/** A presented virtual source keeps its graphics hosts behind the output's Recents entry. */
final class DisplayTaskRecents implements DisplayManager.DisplayListener {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final java.util.Set<Integer> SOURCES = new java.util.HashSet<>();
    private static final Map<Integer, Boolean> ORIGINAL_FLAGS = new HashMap<>();
    private static DisplayTaskRecents observer;
    private static boolean refreshPending;

    private DisplayTaskRecents() { }

    static void presentationChanged(DisplayPresentations.Session session) {
        if (!session.closed && session.ready && session.outputAttachment && session.taskId >= 0
                && session.source.id != Display.DEFAULT_DISPLAY
                && DisplayPresentationMode.forSource(session.source) == DisplayPresentationMode.DIRECT) {
            if (observer == null) {
                observer = new DisplayTaskRecents();
                MagicDeskApplication.applicationContext().getSystemService(DisplayManager.class)
                        .registerDisplayListener(observer, MAIN);
            }
            // Closing/switching an output does not turn retained source windows into phone windows.
            // The source's display-removal event, not the Viewer's Surface lifetime, ends this role.
            SOURCES.add(session.source.id);
        }
        requestRefresh();
    }

    static void requestRefresh() {
        if (refreshPending) return;
        refreshPending = true;
        MAIN.post(() -> {
            refreshPending = false;
            DesktopTaskDescription.refresh();
        });
    }

    static boolean represented(Activity activity) {
        Display display = activity.getDisplay();
        return activity instanceof HostedWindowPresentation.ContentHost
                && display != null && display.isValid() && display.getDisplayId() != Display.DEFAULT_DISPLAY
                && SOURCES.contains(display.getDisplayId());
    }

    /** Overrides belong to tasks, so Activity recreation cannot lose the original flag. */
    static void update(Activity activity) {
        int taskId = activity.getTaskId();
        Boolean original = ORIGINAL_FLAGS.get(taskId);
        boolean exclude = represented(activity);
        if (exclude == (original != null)) return;
        try {
            for (ActivityManager.AppTask task : activity.getSystemService(ActivityManager.class).getAppTasks()) {
                ActivityManager.RecentTaskInfo info = task.getTaskInfo();
                if (info.taskId != taskId) continue;
                if (activity.getDisplay() == null) return;
                boolean excluded = info.baseIntent != null
                        && (info.baseIntent.getFlags() & Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS) != 0;
                if (exclude) {
                    if (!excluded) task.setExcludeFromRecents(true);
                    ORIGINAL_FLAGS.put(taskId, excluded);
                    return;
                }
                if (excluded && !original) task.setExcludeFromRecents(false);
                ORIGINAL_FLAGS.remove(taskId);
                return;
            }
        } catch (RuntimeException error) {
            CompatibilityDiagnostics.record("DISPLAY-RECENTS-001", "Could not update presented task in Recents",
                    "task=" + activity.getTaskId() + " | " + ShellAccess.usefulMessage(error));
        }
    }

    static void forget(Activity activity) {
        if (activity.isFinishing()) ORIGINAL_FLAGS.remove(activity.getTaskId());
    }

    @Override public void onDisplayAdded(int displayId) { onDisplayRemoved(displayId); }
    @Override public void onDisplayChanged(int displayId) { }
    @Override public void onDisplayRemoved(int displayId) {
        if (SOURCES.remove(displayId)) requestRefresh();
    }
}
