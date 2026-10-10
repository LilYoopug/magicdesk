package io.github.mekhontsev.magicdesk;

/** One host-owned capture lease, confirmed by Android rather than by requesting it. */
final class HostedPointerCapture {
    interface Host {
        void request();
        void release();
    }
    private final Host host;
    private HostedSurfaceOutput output;
    private long requested, active;
    private boolean eligible;

    HostedPointerCapture(Host host) { this.host = host; }

    void bind(HostedSurfaceOutput next) {
        cancel();
        if (output != null) output.captureListener(null);
        output = next;
        if (next != null) next.captureListener(serial -> {
            if (output != next || requested == serial) return;
            cancel();
            requested = serial;
            if (serial == 0) return;
            if (eligible) host.request();
            else cancel();
        });
    }

    void eligible(boolean value) {
        eligible = value;
        if (!value) cancel();
    }

    void changed(boolean captured) {
        if (!captured) { cancel(); return; }
        if (!eligible || requested == 0 || output == null) { host.release(); return; }
        if (active != requested) {
            active = requested;
            output.pointerCapture(active, true);
        }
    }

    long serial() { return active; }

    void cancel() {
        long serial = requested;
        requested = active = 0;
        if (serial != 0) {
            host.release();
            if (output != null) output.pointerCapture(serial, false);
        }
    }
}
