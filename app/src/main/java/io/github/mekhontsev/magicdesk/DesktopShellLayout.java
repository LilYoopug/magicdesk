package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Desktop shell policy expressed as layout intents; contains no Android window operations. */
final class DesktopShellLayout {
    record NativePanel(String id, ShellPanel.Edge edge, ShellLayout.Surface surface) { }
    record Observation(ShellLayout.Snapshot layout, List<NativePanel> panels) {
        Observation { panels = List.copyOf(panels); }
    }

    private final ShellLayoutScope mScope = new ShellLayoutScope();
    private ShellLayoutScope.Binding mNative = mScope.bind();
    private List<PanelGeometry> mPanels = List.of();

    void update(final DesktopViewport viewport, final List<PanelGeometry> panels, final boolean autoHide) {
        final List<PanelGeometry> next = List.copyOf(panels);
        final var ids = new HashSet<String>();
        final List<ShellSurface> surfaces = new ArrayList<>();
        for (PanelGeometry geometry : next) {
            final ShellPanel panel = geometry.panel();
            if (!ids.add(panel.id())) throw new IllegalArgumentException("Duplicate native panel identity");
            surfaces.add(new ShellSurface(panel.id(), true, ShellSurface.Layer.TOP, ShellSurface.Keyboard.NONE,
                    geometry.placement(), geometry.paintExtension(viewport),
                    ShellSurface.PaintPolicy.CONTENT_EDGE, ShellSurface.Input.PAINT,
                    // Native panels always avoid one another and shell popups. Only the window
                    // reservation follows reserveSpace and auto-hide; concealment never moves them.
                    List.of(ShellReservation.exclusive(geometry.reservationEdge(), geometry.thickness(),
                            panel.style().reserveSpace() && !autoHide))));
        }
        // Scope listeners read the current component-to-panel mapping during this atomic commit.
        mPanels = next;
        mNative.commit(viewport.outputGeometry(), viewport.contentGeometry(), surfaces);
    }

    ShellLayout.Snapshot snapshot() { return mScope.snapshot(); }
    Observation observe() {
        return new Observation(snapshot(), mPanels.stream().map(geometry ->
                new NativePanel(geometry.panel().id(), geometry.panel().edge(),
                        panel(geometry.panel().id()))).toList());
    }
    ShellLayoutScope scope() { return mScope; }
    ShellLayout.Surface panel(final String id) { return mNative.surface(id); }
    ShellLayout.Surface panelFor(final ShellComposition.Kind component) {
        for (PanelGeometry geometry : mPanels) {
            if (geometry.panel().components().stream().anyMatch(value -> value.type() == component)) {
                return panel(geometry.panel().id());
            }
        }
        return taskbar();
    }
    ShellLayout.Surface taskbar() { return mPanels.isEmpty() ? null : panel(mPanels.get(0).panel().id()); }
    ShellLayoutScope.Binding bind() { return mScope.bind(); }
    void listen(final Runnable listener) { mScope.listen(listener); }
    void unlisten(final Runnable listener) { mScope.unlisten(listener); }

    void release() {
        mPanels = List.of();
        mScope.clear();
        mNative = mScope.bind();
    }
}
