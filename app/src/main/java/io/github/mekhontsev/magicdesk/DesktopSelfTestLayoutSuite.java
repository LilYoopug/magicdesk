package io.github.mekhontsev.magicdesk;

import android.graphics.Rect;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Exercises policy preparation through production geometry and focus gateways. */
final class DesktopSelfTestLayoutSuite {
    private DesktopSelfTestLayoutSuite() { }

    static void run(DesktopSelfTestResult result, int displayId, int first, int second,
            Rect left, Rect right) throws DesktopSelfTestSteps.AbortSelfTest {
        var leftBounds = DesktopWindowLayoutController.bounds(left);
        var rightBounds = DesktopWindowLayoutController.bounds(right);
        WindowLayoutPolicy policy = (workspace, request) -> {
            if (request.event() != WindowLayoutPolicy.Event.REVEAL
                    || !workspace.requireWindow(request.taskId()).freeform()) {
                return new FloatingWindowLayoutPolicy().plan(workspace, request);
            }
            return new WindowLayoutPolicy.Plan(List.of(
                    new WindowLayoutPolicy.Placement(first, rightBounds, WindowLayoutPolicy.Retention.LAYOUT),
                    new WindowLayoutPolicy.Placement(second, leftBounds, WindowLayoutPolicy.Retention.LAYOUT)));
        };
        try {
            DesktopSelfTestSteps.require(result, "LAYOUT-001", "Prepare geometry before activating a task", () -> {
                setPolicy(displayId, policy);
                DesktopSelfTestInputSuite.focusTaskThroughDesktop(displayId, first);
                awaitBounds(displayId, first, right);
                awaitBounds(displayId, second, left);
                DesktopSelfTestInputSuite.waitForTaskInputFocus(displayId, first);
                return "batch geometry and input focus confirmed";
            });
        } finally {
            DesktopSelfTestSteps.require(result, "LAYOUT-002", "Release temporary layout and restore floating bounds", () -> {
                setPolicy(displayId, new FloatingWindowLayoutPolicy());
                awaitBounds(displayId, first, left);
                awaitBounds(displayId, second, right);
                return "original geometry restored without changing task mode";
            });
        }
    }

    private static void awaitBounds(int displayId, int taskId, Rect expected) throws IOException {
        TaskRepository.Snapshot snapshot = BoundedStateAwaiter.awaitIo(
                BoundedStateAwaiter.Reason.TASK_HIERARCHY, 10_000, 100,
                () -> TaskRepository.loadNow(displayId), value -> matches(value, taskId, expected));
        if (!matches(snapshot, taskId, expected)) throw new IOException("layout bounds not observed: " + taskId);
    }

    private static boolean matches(TaskRepository.Snapshot snapshot, int taskId, Rect expected) {
        return snapshot.available && snapshot.tasks.stream().anyMatch(task -> task.taskId == taskId
                && task.isFreeform() && task.bounds.equals(expected));
    }

    private static void setPolicy(int displayId, WindowLayoutPolicy policy) throws IOException {
        CountDownLatch completion = new CountDownLatch(1);
        TaskRepository.ActionResult[] result = new TaskRepository.ActionResult[1];
        MagicDeskRuntime.setWindowLayoutPolicy(displayId, policy, value -> {
            result[0] = value;
            completion.countDown();
        });
        try {
            // EVENT_WAIT: workspace policy replacement acknowledgement; timeout fails the check.
            if (!completion.await(10_000, TimeUnit.MILLISECONDS)) {
                throw new IOException("layout policy replacement timed out");
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("layout policy replacement interrupted", error);
        }
        if (result[0] == null || !result[0].success) {
            throw new IOException(result[0] == null ? "missing layout acknowledgement" : result[0].message);
        }
    }
}
