package io.github.mekhontsev.magicdesk;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Pure application geometry policy. Coordinates are logical display pixels. */
interface WindowLayoutPolicy {
    record Bounds(int left, int top, int right, int bottom) {
        public Bounds {
            if (right <= left || bottom <= top) {
                throw new IllegalArgumentException("empty window bounds");
            }
        }
    }

    record Window(int taskId, boolean freeform, boolean concealed,
            Bounds bounds, Bounds floatingBounds) { }

    record Workspace(int displayId, Bounds workArea, List<Window> windows, int focusedTaskId) {
        public Workspace {
            if (displayId < 0) throw new IllegalArgumentException("invalid display");
            Objects.requireNonNull(workArea);
            windows = List.copyOf(windows);
        }

        Window requireWindow(int taskId) {
            return windows.stream().filter(window -> window.taskId == taskId)
                    .findFirst().orElseThrow(() -> new IllegalArgumentException("task unavailable"));
        }
    }

    enum Retention {
        FLOATING, ARRANGEMENT, LAYOUT, RELEASE_LAYOUT
    }

    record Placement(int taskId, Bounds bounds, Retention retention) {
        public Placement {
            if (taskId < 0) throw new IllegalArgumentException("invalid task");
            Objects.requireNonNull(bounds);
            Objects.requireNonNull(retention);
        }
    }

    enum Event { OBSERVE, REVEAL, PLACE, RELEASE }

    record Request(Event event, int taskId, Placement placement) {
        public Request {
            Objects.requireNonNull(event);
            if ((event == Event.PLACE) != (placement != null)
                    || (placement != null && placement.taskId != taskId)) {
                throw new IllegalArgumentException("layout request mismatch");
            }
        }

        static Request reveal(int taskId) { return new Request(Event.REVEAL, taskId, null); }
        static Request observe() { return new Request(Event.OBSERVE, -1, null); }
        static Request release() { return new Request(Event.RELEASE, -1, null); }
        static Request place(Placement placement) {
            return new Request(Event.PLACE, placement.taskId, placement);
        }
    }

    record Plan(List<Placement> placements, WindowLayoutPolicy continuation) {
        static final Plan EMPTY = new Plan(List.of());

        public Plan(List<Placement> placements) { this(placements, null); }

        public Plan {
            placements = List.copyOf(placements);
            var ids = new HashSet<Integer>();
            for (Placement placement : placements) {
                if (!ids.add(placement.taskId)) {
                    throw new IllegalArgumentException("duplicate layout task");
                }
            }
        }

        void validate(Workspace workspace) {
            for (Placement placement : placements) {
                if (!workspace.requireWindow(placement.taskId).freeform) {
                    throw new IllegalArgumentException("layout cannot place a non-freeform task");
                }
            }
        }

        boolean isEmpty() { return placements.isEmpty() && continuation == null; }
    }

    default boolean observesWorkspace() { return true; }

    // Planning is side-effect free. A continuation commits policy state only
    // after successful submission; a rejected or cancelled plan cannot advance it.
    Plan plan(Workspace workspace, Request request);
}
