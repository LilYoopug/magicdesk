package io.github.mekhontsev.magicdesk;

import static io.github.mekhontsev.magicdesk.ShellLayoutTestSupport.geometry;
import static io.github.mekhontsev.magicdesk.ShellLayoutTestSupport.panel;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public final class DesktopSelfTestShellProbeTest {
    private static final DesktopViewport OUTPUT = new DesktopViewport(0, 0, 1920, 1080, 0, 0, 0, 0);

    @Test public void bottomPanelWithPhoneInsetsMatchesContentAndPaintSeparately() {
        final var viewport = new DesktopViewport(0, 0, 1216, 2688, 0, 147, 0, 126);
        final var layout = new DesktopShellLayout();
        ShellLayoutTestSupport.update(layout, viewport, 169, false);
        assertNotEquals(layout.taskbar().content(), layout.taskbar().paint());
        assertValid(viewport, layout);
    }

    @Test public void topStatusAndFloatingDockUseBothReservations() {
        final var layout = new DesktopShellLayout();
        layout.update(OUTPUT, List.of(
                geometry(panel("status", ShellPanel.Edge.TOP, ShellAppearance.PanelStyle.defaults(),
                        ShellComposition.Kind.START), OUTPUT, 40),
                geometry(panel("dock", ShellPanel.Edge.BOTTOM, ShellAppearance.PanelStyle.floating(),
                        ShellComposition.Kind.TASKS), OUTPUT, 76)), false);
        assertEquals(new ShellBounds(0, 40, 1920, 992), layout.snapshot().workArea());
        assertTrue(layout.panel("dock").content().width() < OUTPUT.contentWidth());
        assertValid(OUTPUT, layout);
    }

    @Test public void everyEdgeSupportsDensityAndAutoHideWithoutChangingPanelGeometry() {
        final var viewport = new DesktopViewport(100, 200, 1100, 1000, 20, 30, 40, 50);
        for (float density : new float[] {1, 1.25f, 3.25f}) {
            for (ShellPanel.Edge edge : ShellPanel.Edge.values()) {
                final var layout = new DesktopShellLayout();
                final var geometry = PanelGeometry.resolve(panel("main", edge,
                        ShellAppearance.PanelStyle.floating(), ShellComposition.Kind.START),
                        density, viewport.contentWidth(), viewport.contentHeight(), 60, 500, 100);
                layout.update(viewport, List.of(geometry), false);
                assertValid(viewport, layout);
                final var before = layout.observe();
                layout.update(viewport, List.of(geometry), true);
                assertValid(viewport, layout);
                assertEquals(viewport.contentGeometry(), layout.snapshot().workArea());
                assertEquals(before.panels().get(0).surface().content(), layout.taskbar().content());
                assertEquals(before.panels().get(0).surface().paint(), layout.taskbar().paint());
            }
        }
    }

    @Test public void sameEdgePanelsAndNonReservingPanelsUseSharedWorkAreaPolicy() {
        final var layout = new DesktopShellLayout();
        final var base = ShellAppearance.PanelStyle.defaults();
        final var nonReserving = new ShellAppearance.PanelStyle(base.length(), base.alignment(),
                base.maxLengthDp(), base.sideGapDp(), base.edgeGapDp(), base.thicknessDp(),
                base.paddingDp(), base.radiusDp(), base.backdrop(), false, base.hover());
        for (ShellPanel.Edge edge : ShellPanel.Edge.values()) {
            layout.update(OUTPUT, List.of(
                    geometry(panel("outer", edge, base, ShellComposition.Kind.START), OUTPUT, 40),
                    geometry(panel("inner", edge, nonReserving, ShellComposition.Kind.TASKS), OUTPUT, 60)), false);
            assertNotEquals(layout.snapshot().panelArea(), layout.snapshot().workArea());
            assertValid(OUTPUT, layout);
        }
    }

    @Test public void externalReservationsRemainPartOfTheSameLayout() {
        final var layout = new DesktopShellLayout();
        ShellLayoutTestSupport.update(layout, OUTPUT, 64, false);
        final var external = layout.bind();
        external.commit(List.of(new ShellSurface("linux", true, ShellSurface.Layer.TOP, ShellSurface.Keyboard.NONE,
                new ShellSurface.Placement(ShellSurface.Reference.OUTPUT,
                        ShellSurface.TOP | ShellSurface.LEFT | ShellSurface.RIGHT, 0, 80, ShellSurface.Margins.NONE),
                ShellSurface.Margins.NONE, ShellSurface.Input.CONTENT,
                List.of(ShellReservation.absolute(ShellReservation.Edge.TOP, 80, 0, 1920)))));
        assertEquals(80, layout.snapshot().workArea().top());
        assertEquals(1, layout.observe().panels().size());
        assertValid(OUTPUT, layout);
        external.close();
        assertValid(OUTPUT, layout);
    }

    @Test public void observationRetainsCommittedStateAfterReplacementAndRelease() {
        final var layout = new DesktopShellLayout();
        ShellLayoutTestSupport.update(layout, OUTPUT, 64, false);
        final var before = layout.observe();
        final var actual = observed(before);
        ShellLayoutTestSupport.update(layout, OUTPUT, 80, false);
        assertNotNull(check(OUTPUT, layout, actual));
        layout.release();
        assertNotNull(check(OUTPUT, layout, List.of()));
        assertNull(DesktopSelfTestShellProbe.mismatch(OUTPUT, before.layout().workArea(), before, actual));
        assertThrows(UnsupportedOperationException.class, () -> before.panels().clear());
    }

    @Test public void missingExtraDuplicateOrUnknownPanelsFail() {
        final var layout = new DesktopShellLayout();
        layout.update(OUTPUT, List.of(
                geometry(panel("top", ShellPanel.Edge.TOP, ShellAppearance.PanelStyle.defaults(),
                        ShellComposition.Kind.START), OUTPUT, 40),
                geometry(panel("bottom", ShellPanel.Edge.BOTTOM, ShellAppearance.PanelStyle.defaults(),
                        ShellComposition.Kind.TASKS), OUTPUT, 60)), false);
        final var actual = observed(layout.observe());
        assertNotNull(check(OUTPUT, layout, List.of(actual.get(0))));
        assertNotNull(check(OUTPUT, layout, List.of(actual.get(0), actual.get(1), actual.get(1))));
        assertNotNull(check(OUTPUT, layout, List.of(actual.get(0), actual.get(0))));
        final var first = actual.get(0);
        assertNotNull(check(OUTPUT, layout, List.of(new DesktopSelfTestShellProbe.Panel("unknown",
                first.edge(), first.content(), first.paint(), first.output()), actual.get(1))));
    }

    @Test public void incorrectHostBoundsEdgeViewportOrWorkAreaFail() {
        final var layout = new DesktopShellLayout();
        ShellLayoutTestSupport.update(layout, OUTPUT, 64, false);
        final var state = layout.observe();
        final var panel = observed(state).get(0);
        final var wrong = new ShellBounds(1, 1, 100, 100);
        for (var changed : List.of(
                new DesktopSelfTestShellProbe.Panel(panel.id(), ShellPanel.Edge.TOP, panel.content(), panel.paint(), panel.output()),
                new DesktopSelfTestShellProbe.Panel(panel.id(), panel.edge(), wrong, panel.paint(), panel.output()),
                new DesktopSelfTestShellProbe.Panel(panel.id(), panel.edge(), panel.content(), wrong, panel.output()),
                new DesktopSelfTestShellProbe.Panel(panel.id(), panel.edge(), panel.content(), panel.paint(), wrong))) {
            assertNotNull(check(OUTPUT, layout, List.of(changed)));
        }
        assertNotNull(DesktopSelfTestShellProbe.mismatch(OUTPUT, OUTPUT.contentGeometry(), state, List.of(panel)));
        assertNotNull(check(new DesktopViewport(0, 0, 1920, 1080, 0, 20, 0, 0), layout, List.of(panel)));
        assertNotNull(DesktopSelfTestShellProbe.mismatch(OUTPUT, state.layout().workArea(), null, List.of(panel)));
    }

    @Test public void concealmentSamplesEveryPanelAndItsRevealEdgeWithoutSystemBars() {
        final var viewport = new DesktopViewport(100, 200, 1100, 1000, 20, 30, 40, 50);
        final var content = viewport.contentGeometry();
        final var layout = new DesktopShellLayout();
        layout.update(viewport, java.util.Arrays.stream(ShellPanel.Edge.values()).map(edge ->
                geometry(panel(edge.name().toLowerCase(java.util.Locale.ROOT), edge,
                        ShellAppearance.PanelStyle.floating(), ShellComposition.Kind.SPACER), viewport, 40)).toList(), false);
        final var panels = observed(layout.observe());
        final var points = DesktopSelfTestShellProbe.concealedSamples(panels, content);
        assertEquals(panels.size() * 2, points.size());
        for (int i = 0; i < panels.size(); i++) {
            final var panel = panels.get(i);
            assertInside(panel.content(), points.get(2 * i));
            final var edge = points.get(2 * i + 1);
            assertInside(content, edge);
            switch (panel.edge()) {
                case TOP -> assertEquals(content.top(), edge.y());
                case BOTTOM -> assertEquals(content.bottom() - 1, edge.y());
                case LEFT -> assertEquals(content.left(), edge.x());
                case RIGHT -> assertEquals(content.right() - 1, edge.x());
            }
        }
    }

    private static void assertInside(ShellBounds bounds, DesktopSelfTestShellProbe.Point point) {
        assertTrue(point.x() >= bounds.left() && point.x() < bounds.right());
        assertTrue(point.y() >= bounds.top() && point.y() < bounds.bottom());
    }

    private static List<DesktopSelfTestShellProbe.Panel> observed(DesktopShellLayout.Observation state) {
        final var result = new ArrayList<DesktopSelfTestShellProbe.Panel>();
        for (var panel : state.panels()) {
            result.add(new DesktopSelfTestShellProbe.Panel(panel.id(), panel.edge(),
                    panel.surface().content(), panel.surface().paint(), state.layout().output()));
        }
        return List.copyOf(result);
    }

    private static String check(DesktopViewport viewport, DesktopShellLayout layout,
            List<DesktopSelfTestShellProbe.Panel> actual) {
        return DesktopSelfTestShellProbe.mismatch(viewport, layout.snapshot().workArea(), layout.observe(), actual);
    }

    private static void assertValid(DesktopViewport viewport, DesktopShellLayout layout) {
        assertNull(check(viewport, layout, observed(layout.observe())));
    }
}
