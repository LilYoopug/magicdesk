package io.github.mekhontsev.magicdesk;

import android.graphics.Rect;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Checks the host against the committed layout, independently of a theme's topology. */
final class DesktopSelfTestShellProbe {
    record Panel(String id, ShellPanel.Edge edge, ShellBounds content,
            ShellBounds paint, ShellBounds output) { }
    record Point(int x, int y) { }

    static String mismatch(DesktopViewport viewport, Rect workArea, DesktopUiSnapshot ui) {
        return mismatch(viewport, bounds(workArea), ui.shellLayout, panels(ui));
    }

    static List<Panel> panels(DesktopUiSnapshot ui) {
        return ui.panels.stream().map(panel -> new Panel(panel.id(), panel.edge(),
                bounds(panel.bounds()), bounds(panel.paintBounds()), bounds(panel.outputBounds()))).toList();
    }

    private static ShellBounds bounds(Rect value) {
        return new ShellBounds(value.left, value.top, value.right, value.bottom);
    }

    static String mismatch(DesktopViewport viewport, ShellBounds workArea,
            DesktopShellLayout.Observation expected, List<Panel> actual) {
        if (expected == null || expected.layout() == null) return "shell layout unavailable";
        final var layout = expected.layout();
        if (!viewport.outputGeometry().equals(layout.output())
                || !viewport.contentGeometry().equals(layout.content())) return "stale shell viewport";
        if (workArea.isEmpty() || !workArea.equals(layout.workArea())
                || !layout.content().intersect(workArea).equals(workArea)) return "work area differs from shell layout";
        if (expected.panels().isEmpty() || actual.size() != expected.panels().size()) return "native panel count differs";
        final var ids = new HashSet<String>();
        for (Panel panel : actual) {
            if (!ids.add(panel.id())) return "duplicate native panel: " + panel.id();
            final var planned = expected.panels().stream().filter(value -> value.id().equals(panel.id()))
                    .findFirst().orElse(null);
            if (planned == null || planned.surface() == null) return "unresolved native panel: " + panel.id();
            final var surface = planned.surface();
            if (!surface.request().mapped() || panel.edge() != planned.edge()
                    || panel.content().isEmpty() || panel.paint().isEmpty()
                    || !panel.content().equals(surface.content())
                    || !panel.paint().equals(surface.paint())
                    || !panel.output().equals(layout.output())
                    || !layout.content().intersect(panel.content()).equals(panel.content())
                    || !layout.output().intersect(panel.paint()).equals(panel.paint())) {
                return "native panel differs from shell layout: " + panel.id() + " actual=" + panel
                        + " expected=" + surface.content() + "/" + surface.paint();
            }
        }
        return null;
    }

    static List<Point> concealedSamples(List<Panel> panels, ShellBounds content) {
        final var result = new ArrayList<Point>();
        for (Panel panel : panels) {
            final var bounds = panel.content().intersect(content);
            if (bounds.isEmpty()) throw new IllegalArgumentException("Empty panel: " + panel.id());
            // Keep samples away from the fixture's centered editor and its lower underline.
            final int x = bounds.left() + bounds.width() / (panel.edge().vertical() ? 4 : 8);
            final int y = bounds.top() + bounds.height() / (panel.edge().vertical() ? 8 : 4);
            result.add(new Point(x, y));
            // Check the reveal edge too, including a floating panel's gap, but not system bars.
            result.add(switch (panel.edge()) {
                case TOP -> new Point(x, content.top());
                case BOTTOM -> new Point(x, content.bottom() - 1);
                case LEFT -> new Point(content.left(), y);
                case RIGHT -> new Point(content.right() - 1, y);
            });
        }
        return List.copyOf(result);
    }
}
