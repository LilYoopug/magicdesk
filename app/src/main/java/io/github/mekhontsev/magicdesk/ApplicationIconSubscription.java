package io.github.mekhontsev.magicdesk;

import android.content.Context;
import java.util.Objects;

/** Explicit consumer lifetime, shared by retained window presentations and attached views. */
final class ApplicationIconSubscription implements AutoCloseable {
    private final Context context;
    private final Runnable changed;
    private ApplicationIconKey key;
    private Runnable release;

    ApplicationIconSubscription(Context context, Runnable changed) {
        this.context = context;
        this.changed = changed;
    }

    void set(ApplicationIconKey next) {
        if (Objects.equals(key, next)) return;
        close();
        key = next;
        if (key != null) release = ApplicationIcons.get(context).subscribe(key, changed);
    }

    void set(RecentApplicationStore.Entry recipe) {
        set(recipe == null ? null : ApplicationIcons.key(recipe.shortcut(), recipe.termuxPackage()));
    }

    @Override public void close() {
        if (release != null) release.run();
        release = null;
        key = null;
    }
}
