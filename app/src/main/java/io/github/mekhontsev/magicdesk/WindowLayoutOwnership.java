package io.github.mekhontsev.magicdesk;

/** Temporary layout residency, independent of native snap and fullscreen restore history. */
final class WindowLayoutOwnership {
    private WindowLayoutPolicy.Bounds mFloatingBounds;
    private WindowLayoutPolicy.Bounds mTarget;

    record Saved(WindowLayoutPolicy.Bounds floatingBounds, WindowLayoutPolicy.Bounds target) { }

    synchronized Saved save() { return new Saved(mFloatingBounds, mTarget); }

    synchronized void restore(Saved saved) {
        mFloatingBounds = saved.floatingBounds;
        mTarget = saved.target;
    }

    synchronized void acquire(WindowLayoutPolicy.Bounds observed, WindowLayoutPolicy.Bounds target) {
        if (mFloatingBounds == null) mFloatingBounds = observed;
        mTarget = target;
    }

    synchronized void release() {
        mFloatingBounds = null;
        mTarget = null;
    }

    synchronized boolean isOwned() { return mFloatingBounds != null; }
    synchronized WindowLayoutPolicy.Bounds floatingBounds() { return mFloatingBounds; }
    synchronized WindowLayoutPolicy.Bounds target() { return mTarget; }
}
