package io.github.mekhontsev.magicdesk;

import java.util.List;

/** Native moves remain authoritative; explicit arrangements share the plan executor. */
final class FloatingWindowLayoutPolicy implements WindowLayoutPolicy {
    @Override public boolean observesWorkspace() { return false; }

    @Override
    public Plan plan(Workspace workspace, Request request) {
        return switch (request.event()) {
            case PLACE -> new Plan(List.of(request.placement()));
            case REVEAL -> {
                workspace.requireWindow(request.taskId());
                yield Plan.EMPTY;
            }
            case OBSERVE -> Plan.EMPTY;
            case RELEASE -> new Plan(workspace.windows().stream()
                    .filter(window -> window.freeform() && window.floatingBounds() != null)
                    .map(window -> new Placement(window.taskId(), window.floatingBounds(),
                            Retention.RELEASE_LAYOUT)).toList());
        };
    }
}
