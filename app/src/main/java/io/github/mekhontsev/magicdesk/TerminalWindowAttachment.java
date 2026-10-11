package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import java.lang.ref.WeakReference;
import java.util.function.Consumer;

/** The sole optional window of a retained PTY. All mutations run on the UI thread. */
final class TerminalWindowAttachment {
    interface Host {
        void onTerminalDetached();
    }
    private WeakReference<Activity> owner = new WeakReference<>(null);
    private WeakReference<ConsoleTerminalView> surface = new WeakReference<>(null);
    private long generation;

    Activity owner() { return owner.get(); }
    ConsoleTerminalView view() { return surface.get(); }
    long generation() { return generation; }
    boolean present() { return owner.get() != null && surface.get() != null; }

    void replace(Activity activity, ConsoleTerminalView view) {
        if (owner.get() == activity && surface.get() == view) return;
        release();
        owner = new WeakReference<>(activity);
        surface = new WeakReference<>(view);
        generation++;
    }

    boolean detach(Activity activity) {
        if (owner.get() != activity) return false;
        release();
        return true;
    }

    void release() {
        Activity activity = owner.get();
        ConsoleTerminalView view = surface.get();
        // Revoke input/resize ownership before notifying the former host.
        if (view != null) view.attach(null, null);
        owner.clear();
        surface.clear();
        if (activity instanceof Host host && !activity.isDestroyed()) host.onTerminalDetached();
    }

    void prune() {
        Activity activity = owner.get();
        if (activity != null && activity.isDestroyed()) release();
    }

    void notifyListener(Consumer<ConsoleTerminalSession.Listener> action) {
        Activity activity = owner.get();
        if (activity instanceof ConsoleTerminalSession.Listener listener
                && !activity.isDestroyed() && !activity.isFinishing()) action.accept(listener);
    }
}
