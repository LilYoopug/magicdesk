package io.github.mekhontsev.magicdesk;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;
import java.io.IOException;

/** One user-confirmed SystemUI process restart, not an Android userspace reboot. */
final class SystemUiRestart {
    static final long MIN_INTERVAL_MILLIS = 60_000;
    private final Context context;
    private final SharedPreferences attempts;
    private final int pid;
    private final int boot;

    private SystemUiRestart(Context context, int pid) {
        this.context = context;
        this.pid = pid;
        attempts = context.getSharedPreferences("magicdesk_system_ui_restart", Context.MODE_PRIVATE);
        boot = Settings.Global.getInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, -1);
    }

    static SystemUiRestart prepare(Context context) throws IOException {
        final int pid = readPid();
        if (pid <= 1) throw new IOException("System UI process is unavailable");
        final var restart = new SystemUiRestart(context, pid);
        restart.checkInterval();
        return restart;
    }

    void execute() throws IOException {
        checkInterval();
        if (readPid() != pid) throw new IOException("System UI process changed before restart");
        // Persist before issuing the crash so Activity/app recreation cannot replay it.
        if (!attempts.edit().putInt("boot", boot).putLong("attempt", SystemClock.elapsedRealtime()).commit()) {
            throw new IOException("could not record System UI restart attempt");
        }
        ShellAccess.run(restartCommand(pid));
        // No completion callback is exposed by am crash. Observe a replacement process
        // and its WMShell endpoint; a timeout never triggers another crash command.
        boolean ready = BoundedStateAwaiter.awaitIo(BoundedStateAwaiter.Reason.SYSTEM_UI_RESTART,
                20_000, 500, () -> {
                    final int current = readPid();
                    if (!replaced(pid, current)) return false;
                    return NativeDesktopController.refresh().mode() != FrameworkDesktopShellApi.Mode.UNKNOWN
                            && readPid() == current;
                }, value -> value);
        if (!ready) throw new IOException("System UI did not confirm recovery after restart");
    }

    private void checkInterval() throws IOException {
        if (!intervalElapsed(boot, attempts.getInt("boot", -2),
                SystemClock.elapsedRealtime(), attempts.getLong("attempt", -1))) {
            throw new IOException(context.getString(R.string.setup_system_ui_restart_wait));
        }
    }

    static boolean intervalElapsed(int boot, int previousBoot, long now, long previous) {
        return boot != previousBoot || previous < 0 || now < previous || now - previous >= MIN_INTERVAL_MILLIS;
    }

    static boolean replaced(int previous, int current) { return current > 1 && current != previous; }

    static String restartCommand(int pid) {
        if (pid <= 1) throw new IllegalArgumentException("invalid System UI process");
        return "/system/bin/am crash --user 0 " + pid;
    }

    private static int readPid() throws IOException {
        return parsePid(ShellAccess.run("/system/bin/pidof com.android.systemui || [ $? -eq 1 ]"));
    }

    static int parsePid(String output) throws IOException {
        if (output.trim().isEmpty()) return 0;
        try {
            final int pid = Integer.parseInt(output.trim());
            if (pid <= 1) throw new NumberFormatException();
            return pid;
        } catch (NumberFormatException error) {
            throw new IOException("System UI process identity is ambiguous: " + output.trim(), error);
        }
    }
}
