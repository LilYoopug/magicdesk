package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public final class WindowLayoutPolicyTest {
    private static final WindowLayoutPolicy.Bounds AREA = new WindowLayoutPolicy.Bounds(0, 0, 1200, 800);
    private static final WindowLayoutPolicy.Bounds FLOATING = new WindowLayoutPolicy.Bounds(50, 50, 700, 600);
    private static final WindowLayoutPolicy.Bounds TILE = new WindowLayoutPolicy.Bounds(0, 0, 600, 800);
    private final FloatingWindowLayoutPolicy policy = new FloatingWindowLayoutPolicy();

    private WindowLayoutPolicy.Workspace workspace() {
        return new WindowLayoutPolicy.Workspace(3, AREA, List.of(
                new WindowLayoutPolicy.Window(10, true, false, FLOATING, null),
                new WindowLayoutPolicy.Window(20, false, false, AREA, FLOATING),
                new WindowLayoutPolicy.Window(30, true, true, TILE, FLOATING)), 10);
    }

    @Test public void floatingObservationAndRevealNeverChangeGeometry() {
        assertTrue(policy.plan(workspace(), WindowLayoutPolicy.Request.observe()).placements().isEmpty());
        for (int id : new int[] {10, 20, 30}) {
            assertTrue(policy.plan(workspace(), WindowLayoutPolicy.Request.reveal(id)).placements().isEmpty());
        }
    }

    @Test public void explicitResizeAndArrangementSharePlans() {
        for (WindowLayoutPolicy.Retention retention : List.of(WindowLayoutPolicy.Retention.FLOATING,
                WindowLayoutPolicy.Retention.ARRANGEMENT)) {
            var placement = new WindowLayoutPolicy.Placement(10, TILE, retention);
            var plan = policy.plan(workspace(), WindowLayoutPolicy.Request.place(placement));
            plan.validate(workspace());
            assertEquals(List.of(placement), plan.placements());
        }
    }

    @Test public void releaseRestoresHiddenWindowsWithoutRestoringFullscreen() {
        var plan = policy.plan(workspace(), WindowLayoutPolicy.Request.release());
        assertEquals(List.of(new WindowLayoutPolicy.Placement(30, FLOATING,
                WindowLayoutPolicy.Retention.RELEASE_LAYOUT)), plan.placements());
        plan.validate(workspace());
    }

    @Test public void rejectsForeignTasksFullscreenAndDuplicatesBeforeExecution() {
        for (int id : new int[] {20, 999}) {
            var plan = new WindowLayoutPolicy.Plan(List.of(new WindowLayoutPolicy.Placement(
                    id, TILE, WindowLayoutPolicy.Retention.LAYOUT)));
            assertThrows(IllegalArgumentException.class, () -> plan.validate(workspace()));
        }
        var placement = new WindowLayoutPolicy.Placement(10, TILE, WindowLayoutPolicy.Retention.LAYOUT);
        assertThrows(IllegalArgumentException.class, () -> new WindowLayoutPolicy.Plan(List.of(placement, placement)));
    }

    @Test public void snapshotAndPlanDoNotRetainMutableLists() {
        var windows = new ArrayList<>(workspace().windows());
        var snapshot = new WindowLayoutPolicy.Workspace(3, AREA, windows, 10);
        windows.clear();
        assertEquals(3, snapshot.windows().size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.windows().clear());
    }

    @Test public void temporaryOwnershipPreservesFirstFloatingGeometryAcrossReflows() {
        var ownership = new WindowLayoutOwnership();
        ownership.acquire(FLOATING, TILE);
        var saved = ownership.save();
        ownership.acquire(TILE, AREA);
        assertEquals(FLOATING, ownership.floatingBounds());
        assertEquals(AREA, ownership.target());
        ownership.restore(saved);
        assertEquals(TILE, ownership.target());
        ownership.release();
        assertFalse(ownership.isOwned());
    }
}
