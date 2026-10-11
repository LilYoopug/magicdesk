package io.github.mekhontsev.magicdesk;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Android permission-gated adapter. No MCP grants, Desktop ownership, or implicit privilege startup. */
public final class RunCommandService extends Service {
    private static final String CHANNEL = "external_commands";
    private static final int NOTIFICATION = 17042;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService workers = Executors.newFixedThreadPool(4);
    private final ExecutorService cleanup = Executors.newSingleThreadExecutor();
    private final HashMap<String, Job> jobs = new HashMap<>();
    private int lastStart;

    @Override public void onCreate() {
        super.onCreate();
        var manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL,
                getString(R.string.run_command_title), NotificationManager.IMPORTANCE_LOW));
    }

    private void foreground() {
        startForeground(NOTIFICATION, new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_file_console).setContentTitle(getString(R.string.run_command_title))
                .setOngoing(true).build());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        foreground();
        lastStart = startId;
        PendingIntent callback = null;
        String id = UUID.randomUUID().toString();
        try {
            if (intent == null || !(getPackageName() + ".RUN_COMMAND").equals(intent.getAction()))
                throw new IllegalArgumentException("Unknown command action");
            callback = intent.getParcelableExtra("result", PendingIntent.class);
            if (intent.hasExtra("result") && (callback == null || callback.isImmutable()))
                throw new IllegalArgumentException("Result must be a mutable PendingIntent");
            if (!RunCommandPreferences.enabled(this)) throw new SecurityException("External commands are disabled");
            if (jobs.size() >= 4) throw new IllegalStateException("Too many active external commands");
            var request = RunCommandRequest.parse(intent.getStringExtra("request"));
            Job job = new Job(id, callback, request);
            jobs.put(id, job);
            // EVENT_WAIT: command exit or window handoff; expiry cancels this request's unhanded resources.
            main.postDelayed(job.timeout, request.timeoutMillis());
            workers.execute(job::start);
        } catch (Exception error) {
            deliver(callback, id, "failed", null, "", false, error);
            idle();
        }
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() {
        for (var job : java.util.List.copyOf(jobs.values())) job.finish("cancelled", null, new IOException("Command service stopped"));
        workers.shutdown();
        cleanup.shutdown();
        super.onDestroy();
    }

    private void idle() {
        if (jobs.isEmpty()) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(lastStart); }
    }

    private final class Job {
        final String id;
        final PendingIntent callback;
        final RunCommandRequest request;
        final CancellationSignal cancellation = new CancellationSignal();
        final BoundedText output = new BoundedText();
        final Runnable timeout = () -> finish("timed_out", null, new IOException("Command request timed out"));
        private Closeable execution;
        private boolean done;

        Job(String id, PendingIntent callback, RunCommandRequest request) {
            this.id = id; this.callback = callback; this.request = request;
        }
        synchronized boolean active() { return !done && !cancellation.isCanceled(); }
        void start() {
            try {
                if (!active()) return;
                var plan = new RunCommandLaunch(RunCommandService.this, request, cancellation);
                synchronized (this) { if (done) return; }
                if (request.mode().equals("background")) {
                    Closeable handle = plan.executor.start(plan.command, plan.directory, request.stdin(), output::write,
                            (result, error) -> main.post(() -> finish(error == null ? "exited" : "failed", result, error)));
                    synchronized (this) { if (!done) { execution = handle; return; } }
                    handle.close();
                } else {
                    var target = ToolLaunchTarget.resolve("auto", request.displayId(), DesktopRuntimeBridge.workspaceDisplayIds());
                    var display = DesktopDisplayCatalog.require(target.displayId, null);
                    main.post(() -> {
                        if (!active()) return;
                        ApplicationEntryLauncher.launch(RunCommandService.this,
                                ApplicationEntryLauncher.present(plan.request(), target, DesktopLaunchPresentation.automatic()),
                                target, display.uniqueId, cancellation, this::active,
                                error -> finish(error == null ? "launched" : "failed", null, error));
                    });
                }
            } catch (Exception error) { main.post(() -> finish("failed", null, error)); }
        }
        void finish(String status, ShellCommandOutput.Result result, Throwable error) {
            final Closeable handle;
            synchronized (this) {
                if (done) return;
                done = true; handle = execution; execution = null;
            }
            main.removeCallbacks(timeout);
            // Closing a shell relay may wait for its process. Never hold the Android UI thread there.
            cleanup.execute(() -> {
                if (!status.equals("launched")) cancellation.cancel();
                if (handle != null) try { handle.close(); } catch (IOException ignored) { }
                main.post(() -> {
                    jobs.remove(id);
                    deliver(callback, id, status, result, output.text(), output.truncated, error);
                    idle();
                });
            });
        }
    }

    private void deliver(PendingIntent callback, String id, String status, ShellCommandOutput.Result result,
            String stdout, boolean stdoutTruncated, Throwable error) {
        if (callback == null) return;
        try {
            BoundedText stderr = new BoundedText();
            if (result != null) stderr.accept(result.stderr());
            else if (error instanceof ShellCommandOutput.Failure failure) stderr.accept(failure.stderr);
            Intent value = new Intent().putExtra("requestId", id).putExtra("status", status)
                    .putExtra("stdout", stdout).putExtra("stderr", stderr.text())
                    .putExtra("stdoutTruncated", stdoutTruncated)
                    .putExtra("stderrTruncated", stderr.truncated || result != null && result.stderrTruncated()
                            || error instanceof ShellCommandOutput.Failure failure && failure.stderrTruncated);
            if (result != null) value.putExtra("exitCode", result.exitCode());
            if (error != null) {
                BoundedText message = new BoundedText(); message.accept(error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage());
                value.putExtra("error", message.text());
            }
            callback.send(this, 0, value);
        } catch (PendingIntent.CanceledException | RuntimeException ignored) {
            // Lost result delivery never replays execution.
        }
    }

    static final class BoundedText {
        final java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        boolean truncated;
        synchronized void write(byte[] input, int offset, int count) {
            int accepted = Math.min(count, RunCommandRequest.MAX_OUTPUT_BYTES - bytes.size());
            bytes.write(input, offset, accepted); truncated |= accepted != count;
        }
        void accept(String text) { byte[] input = text.getBytes(java.nio.charset.StandardCharsets.UTF_8); write(input, 0, input.length); }
        synchronized String text() { return bytes.toString(java.nio.charset.StandardCharsets.UTF_8); }
    }
}
