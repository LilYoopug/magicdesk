package io.github.mekhontsev.magicdesk;

import android.content.ComponentName;
import android.view.Display;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Correlates process failures with tasks on the active desktop display. */
final class ShellProcessFailureTracker implements
        ShellActivityStartController.ProcessFailureListener {
    static final int MAX_PENDING_ANRS = 64;

    interface Listener {
        void onDesktopProcessFailure(DesktopProcessFailureEvent failure);
    }

    private final Listener mListener;
    private final List<TaskContext> mTasks = new ArrayList<>();
    private final Map<ProcessIdentity, PendingAnr> mPendingAnrs =
            new LinkedHashMap<>();

    private int mDisplayId = Display.INVALID_DISPLAY;

    ShellProcessFailureTracker(final Listener listener) {
        mListener = listener;
    }

    synchronized void configure(final int displayId) {
        if (mDisplayId == displayId) {
            return;
        }
        mDisplayId = displayId;
        mTasks.clear();
        mPendingAnrs.clear();
    }

    synchronized void observeTasks(
            final int displayId,
            final List<FrameworkTaskSnapshot> tasks) {
        if (displayId != mDisplayId) {
            return;
        }
        mTasks.clear();
        if (tasks == null) {
            return;
        }
        for (final FrameworkTaskSnapshot task : tasks) {
            if (task.activityType != FrameworkTaskSnapshot.ACTIVITY_TYPE_STANDARD
                    || (task.packageName == null
                            && task.topPackage == null)) {
                continue;
            }
            mTasks.add(new TaskContext(task, displayId));
        }
    }

    @Override
    public void onProcessCrashed(
            final String processName,
            final int pid,
            final String shortMessage,
            final String longMessage,
            final String stackTrace) {
        final DesktopProcessFailureEvent failure;
        synchronized (this) {
            final ProcessIdentity identity =
                    new ProcessIdentity(processName, pid);
            mPendingAnrs.remove(identity);
            failure = createFailure(
                    DesktopProcessFailure.CRASH,
                    processName,
                    pid,
                    shortMessage,
                    longMessage,
                    stackTrace,
                    null);
        }
        report(failure);
    }

    @Override
    public synchronized void onProcessEarlyNotResponding(
            final String processName,
            final int pid,
            final String annotation) {
        final TaskContext task = findTask(processName);
        if (task == null) {
            return;
        }
        final ProcessIdentity identity = new ProcessIdentity(processName, pid);
        mPendingAnrs.remove(identity);
        mPendingAnrs.put(
                identity,
                new PendingAnr(task, DesktopProcessFailure.compactReason(annotation)));
        // Android may abandon an early ANR without delivering the final callback.
        if (mPendingAnrs.size() > MAX_PENDING_ANRS) {
            mPendingAnrs.remove(mPendingAnrs.keySet().iterator().next());
        }
    }

    @Override
    public void onProcessNotResponding(
            final String processName,
            final int pid) {
        final DesktopProcessFailureEvent failure;
        synchronized (this) {
            final ProcessIdentity identity =
                    new ProcessIdentity(processName, pid);
            final PendingAnr pending = mPendingAnrs.remove(identity);
            failure = createFailure(
                    DesktopProcessFailure.ANR,
                    processName,
                    pid,
                    pending == null ? "" : pending.annotation,
                    "",
                    "",
                    pending == null ? null : pending.task);
        }
        report(failure);
    }

    private DesktopProcessFailureEvent createFailure(
            final int type,
            final String processName,
            final int pid,
            final String reason,
            final String message,
            final String stackTrace,
            final TaskContext capturedTask) {
        final TaskContext task = capturedTask == null
                ? findTask(processName) : capturedTask;
        if (task == null) {
            return null;
        }
        return new DesktopProcessFailureEvent(
                type,
                processName,
                pid,
                task.taskId, task.userId, task.displayId, task.windowingMode,
                task.topActivity, reason, message, stackTrace);
    }

    private TaskContext findTask(final String processName) {
        if (mDisplayId == Display.INVALID_DISPLAY) {
            return null;
        }
        final String packageName = packageFromProcessName(processName);
        if (packageName.isEmpty()) {
            return null;
        }
        // Several independent UI processes can share a package. Prefer the
        // process identity already published by the task observer; no new query.
        for (final TaskContext task : mTasks) {
            if (processName.equals(task.topProcessName)) {
                return task;
            }
        }
        TaskContext rootMatch = null;
        for (final TaskContext task : mTasks) {
            if (packageName.equals(task.topPackage)) {
                return task;
            }
            if (rootMatch == null
                    && packageName.equals(task.packageName)) {
                rootMatch = task;
            }
        }
        return rootMatch;
    }

    private void report(final DesktopProcessFailureEvent failure) {
        if (failure == null || mListener == null) {
            return;
        }
        final String operation = failure.type == DesktopProcessFailure.ANR
                ? "anr" : "crash";
        try {
            DesktopAutomationEventJournal.record(
                    "process",
                    operation,
                    false,
                    failure.processName,
                    failure.summary());
        } catch (org.json.JSONException ignored) {
            DesktopAutomationEventJournal.record(
                    "process", operation, false, failure.processName);
        }
        mListener.onDesktopProcessFailure(failure);
    }

    private static String packageFromProcessName(final String processName) {
        if (processName == null) {
            return "";
        }
        final int separator = processName.indexOf(':');
        return separator < 0 ? processName
                : processName.substring(0, separator);
    }

    private static final class TaskContext {
        final int taskId;
        final int userId;
        final int displayId;
        final int windowingMode;
        final String packageName;
        final String topPackage;
        final String topProcessName;
        final String topActivity;

        TaskContext(
                final FrameworkTaskSnapshot task,
                final int observedDisplayId) {
            taskId = task.taskId;
            userId = task.userId;
            displayId = observedDisplayId;
            windowingMode = task.windowingMode;
            packageName = task.packageName;
            topPackage = task.topPackage;
            topProcessName = task.topProcessName;
            final ComponentName component = task.topComponent;
            topActivity = component == null
                    ? "" : component.flattenToShortString();
        }
    }

    private static final class PendingAnr {
        final TaskContext task;
        final String annotation;

        PendingAnr(
                final TaskContext capturedTask,
                final String detail) {
            task = capturedTask;
            annotation = detail;
        }
    }

    private static final class ProcessIdentity {
        final String processName;
        final int pid;

        ProcessIdentity(final String observedProcessName, final int observedPid) {
            processName = observedProcessName == null
                    ? "" : observedProcessName;
            pid = observedPid;
        }

        @Override
        public boolean equals(final Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof ProcessIdentity)) {
                return false;
            }
            final ProcessIdentity identity = (ProcessIdentity) other;
            return pid == identity.pid
                    && processName.equals(identity.processName);
        }

        @Override
        public int hashCode() {
            return 31 * processName.hashCode() + pid;
        }
    }
}
