package io.github.mekhontsev.magicdesk;

import android.graphics.Rect;

import java.util.List;
import java.util.Objects;

/** Immutable state exported by the live desktop host to automation clients. */
final class DesktopUiSnapshot {
    static final DesktopUiSnapshot UNAVAILABLE = new DesktopUiSnapshot(
            false, -1, false, null, false, false, null, "",
            false, false, List.of(), null);

    record Panel(String id, ShellPanel.Edge edge, Rect bounds, Rect paintBounds, Rect outputBounds) {
        Panel {
            Objects.requireNonNull(id);
            Objects.requireNonNull(edge);
            bounds = copy(bounds);
            paintBounds = copy(paintBounds);
            outputBounds = copy(outputBounds);
        }
        @Override public Rect bounds() { return copy(bounds); }
        @Override public Rect paintBounds() { return copy(paintBounds); }
        @Override public Rect outputBounds() { return copy(outputBounds); }
    }

    final boolean available;
    final int displayId;
    final boolean taskbarVisible;
    final Rect taskbarBounds;
    final List<Panel> panels;
    final DesktopShellLayout.Observation shellLayout;
    final boolean startVisible;
    final boolean popupVisible;
    final Rect popupBounds;
    final String popupTitle;
    final boolean wallpaperRendered;
    final boolean fallbackWallpaper;

    DesktopUiSnapshot(
            final boolean available,
            final int displayId,
            final boolean taskbarVisible,
            final Rect taskbarBounds,
            final boolean startVisible,
            final boolean popupVisible,
            final Rect popupBounds,
            final String popupTitle,
            final boolean wallpaperRendered,
            final boolean fallbackWallpaper,
            final List<Panel> panels,
            final DesktopShellLayout.Observation shellLayout) {
        this.available = available;
        this.displayId = displayId;
        this.taskbarVisible = taskbarVisible;
        this.taskbarBounds = copy(taskbarBounds);
        this.panels = List.copyOf(panels);
        this.shellLayout = shellLayout;
        this.startVisible = startVisible;
        this.popupVisible = popupVisible;
        this.popupBounds = copy(popupBounds);
        this.popupTitle = popupTitle == null ? "" : popupTitle;
        this.wallpaperRendered = wallpaperRendered;
        this.fallbackWallpaper = fallbackWallpaper;
    }

    private static Rect copy(final Rect value) {
        return value == null ? new Rect() : new Rect(value);
    }
}
