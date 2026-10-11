package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class DesktopSystemThemePreparationTest {
    @Test public void startupAndRefreshShareOneOverrideBeforeHome() throws Exception {
        verify("""
                DesktopRuntimeBridge.active = true;
                DesktopSystemTheme.refresh();
                DesktopSystemTheme.prepare();
                check(current == SystemNightMode.LIGHT, "HOME would use the old system theme");
                check(writes.equals(List.of(SystemNightMode.LIGHT)), "startup reapplied the override");
                check(pending.previous() == SystemNightMode.DARK, "lost original policy");
                DesktopRuntimeBridge.active = false;
                DesktopSystemTheme.refresh();
                check(current == SystemNightMode.DARK && pending == null, "failed start was not restored");
                """);
    }

    @Test public void timeoutAbortsPreparationAndCancelsItsQueuedWrite() throws Exception {
        verify("""
                DesktopRuntimeBridge.active = true;
                TaskCommandQueue.drain = false;
                try { DesktopSystemTheme.prepare(); throw new AssertionError("unacknowledged preparation passed"); }
                catch (IOException expected) {
                    check(expected.getCause() instanceof TimeoutException, "wrong timeout result");
                }
                TaskCommandQueue.drain = true;
                TaskCommandQueue.execute(() -> {});
                check(writes.isEmpty(), "timed-out operation applied a late theme");
                """);
    }

    @Test public void optionalThemeFailureIsRecordedWithoutBlockingDesktop() throws Exception {
        verify("""
                DesktopRuntimeBridge.active = true;
                failWrite = true;
                DesktopSystemTheme.prepare();
                check(errors == 1, "denied theme write was not reported");
                check(DesktopSystemTheme.sInstance.mStatus.startsWith("error="), "failure presented as success");
                check(pending != null, "lost write-ahead recovery journal");
                DesktopSystemTheme.refresh();
                check(errors == 1, "ordinary refresh retried the failed theme write");
                failWrite = false;
                DesktopRuntimeBridge.active = false;
                DesktopSystemTheme.refresh();
                check(pending == null, "failed start retained a needless recovery journal");
                """);
    }

    @Test public void preparationCannotBlockTheUiThread() throws Exception {
        verify("""
                Looper.ui = true;
                try { DesktopSystemTheme.prepare(); throw new AssertionError("UI thread accepted"); }
                catch (IllegalStateException expected) {}
                check(writes.isEmpty(), "UI thread mutated the system theme");
                """);
    }

    private static void verify(String body) throws Exception {
        RuntimeSourceFixture.verify("io.github.mekhontsev.magicdesk", """
                static SystemNightMode current = SystemNightMode.DARK;
                static DesktopSystemThemeSession.Override pending;
                static List<SystemNightMode> writes = new ArrayList<>();
                static int errors;
                static boolean failWrite;
                static class DesktopRuntimeBridge {
                    static boolean active;
                    static boolean hasWorkspaces() { return active; }
                }
                static class MagicDeskSettings {
                    DesktopSystemThemeSession.Preference systemTheme = DesktopSystemThemeSession.Preference.LIGHT;
                    static MagicDeskSettings load() { return new MagicDeskSettings(); }
                }
                static class ShellAccess {
                    static boolean isReady() { return true; }
                    static String usefulMessage(Throwable error) { return error.getMessage(); }
                }
                static class CompatibilityDiagnostics {
                    static void record(String code, String label, String status, Throwable error) { errors++; }
                }
                static class Looper {
                    static final Object MAIN = new Object();
                    static boolean ui;
                    static Object myLooper() { return ui ? MAIN : null; }
                    static Object getMainLooper() { return MAIN; }
                }
                static class ExternalDisplayController { static final long START_TIMEOUT_MS = 5; }
                static class TaskCommandQueue {
                    static boolean drain = true;
                    static ArrayDeque<Runnable> queue = new ArrayDeque<>();
                    static void execute(Runnable operation) {
                        queue.add(operation);
                        if (drain) while (!queue.isEmpty()) queue.remove().run();
                    }
                }
                static class DesktopSystemTheme {
                    static DesktopSystemTheme sInstance = new DesktopSystemTheme();
                    String mStatus = "idle";
                    interface Operation { void run() throws IOException; }
                    final DesktopSystemThemeSession mSession = new DesktopSystemThemeSession(
                        new DesktopSystemThemeSession.Access() {
                            public SystemNightMode read() { return current; }
                            public void write(SystemNightMode mode) throws IOException {
                                if (failWrite) throw new IOException("theme denied");
                                writes.add(mode);
                                current = mode;
                            }
                        }, new DesktopSystemThemeSession.Storage() {
                            public DesktopSystemThemeSession.Override read() { return pending; }
                            public void write(DesktopSystemThemeSession.Override value) { pending = value; }
                        });
                """ + RuntimeSourceFixture.methods("DesktopSystemTheme", "refresh", "prepare", "reconcile", "run")
                + "}\npublic static void verify() throws Exception {" + body + "}\n",
                "DesktopSystemThemeSession", "SystemNightMode");
    }
}
