package io.github.mekhontsev.magicdesk;

import android.content.Context;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit device policy change; never called by Desktop session startup or cleanup. */
final class DesktopDecorationSettings {
    private static final DesktopDecorationSettings INSTANCE = new DesktopDecorationSettings();
    private final AtomicBoolean busy = new AtomicBoolean();

    interface Access {
        boolean canChange();
        boolean read() throws IOException;
        void prepareRestart() throws IOException;
        void write(boolean enabled) throws IOException;
        void restart() throws IOException;
    }

    static boolean canChange(PlatformWindowingDriver driver) {
        return driver.canChangeDeviceRestrictions() && !INSTANCE.busy.get()
                && SystemDesktopModeSetting.canChange();
    }

    static void apply(Context context, PlatformWindowingDriver driver, boolean expected) throws IOException {
        final Context app = context.getApplicationContext();
        try {
            INSTANCE.apply(new Access() {
                private SystemUiRestart restart;
                public boolean canChange() {
                    return driver.canChangeDeviceRestrictions() && SystemDesktopModeSetting.canChange();
                }
                public boolean read() throws IOException { return driver.deviceRestrictionsEnabled(); }
                public void prepareRestart() throws IOException { restart = SystemUiRestart.prepare(app); }
                public void write(boolean enabled) throws IOException { driver.setDeviceRestrictionsEnabled(enabled); }
                public void restart() throws IOException { restart.execute(); }
            }, expected);
        } finally {
            DesktopSetupStatus.refresh(app);
        }
    }

    void apply(Access access, boolean expected) throws IOException {
        if (!busy.compareAndSet(false, true)) throw new IOException("desktop decoration change is already running");
        try {
            requireAvailable(access);
            if (access.read() != expected) throw new IOException("desktop device restrictions changed; review the current value");
            access.prepareRestart();
            requireAvailable(access);
            access.write(!expected);
            if (access.read() != !expected) throw new IOException("desktop device restrictions did not retain the requested value");
            try {
                requireAvailable(access);
                access.restart();
            } catch (IOException | RuntimeException error) {
                throw new IOException("Device restrictions=" + !expected
                        + "; System UI restart was not confirmed. No automatic retry: "
                        + ShellAccess.usefulMessage(error), error);
            }
        } finally {
            busy.set(false);
        }
    }

    private static void requireAvailable(Access access) throws IOException {
        if (!access.canChange()) throw new IOException("close Desktop and connect the privileged service before changing desktop decorations");
    }
}
