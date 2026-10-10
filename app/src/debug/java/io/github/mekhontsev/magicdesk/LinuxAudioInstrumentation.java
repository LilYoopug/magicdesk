package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Real protocol/UID/output lifecycle check; PCM is silence and system volume is untouched. */
public final class LinuxAudioInstrumentation extends Instrumentation {
    private String command;
    private DesktopExecBackend backend;
    private boolean lifecycle;
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        backend = DesktopExecBackend.parse(arguments.getString("backend", "termux"));
        lifecycle = Boolean.parseBoolean(arguments.getString("lifecycle", "false"));
        command = arguments.getString("command", "head -c 384000 /dev/zero | paplay --raw --format=float32le --rate=48000 --channels=2 --latency-msec=30");
        start();
    }
    @Override public void onStart() {
        new Thread(() -> {
            Bundle result = new Bundle();
            try {
                if (backend == DesktopExecBackend.SHELL) awaitShell();
                var execution = new CommandExecution(getTargetContext(), backend);
                try (var audio = LinuxAudio.acquire(getTargetContext(), execution)) {
                    if (audio.snapshot()[2] != 0) throw new AssertionError("Audio started without a client");
                    CompletableFuture<String> completed = new CompletableFuture<>();
                    try (var process = execution.start(audio.exports() + command, "", "Audio verification", null,
                            (code, output, error) -> {
                                if (error != null || code != 0) completed.completeExceptionally(
                                        new IOException("Audio client exit=" + code + " " + output, error));
                                else completed.complete(output);
                            })) {
                        // EVENT_WAIT: real client's drain/exit; expiry cancels only this test command.
                        try { result.putString("client", completed.get(40, TimeUnit.SECONDS)); }
                        catch (Exception failure) {
                            result.putString("failureCounters", Arrays.toString(audio.snapshot()));
                            throw failure;
                        }
                    }
                    long[] counters = audio.snapshot();
                    result.putString("counters", Arrays.toString(counters));
                    if (counters[1] != 0 || counters[2] < 40000 || counters[3] < 35000 || counters[5] != 0)
                        throw new AssertionError("Android audio output did not drain correctly: " + Arrays.toString(counters));
                    if (lifecycle) verifyLifetime(execution, audio, result);
                    result.putString("result", "PASS executorUid=" + execution.uid + " serverUid=" + android.os.Process.myUid());
                }
                finish(Activity.RESULT_OK, result);
            } catch (Throwable error) {
                android.util.Log.e("MagicDeskAudioTest", "Failed", error);
                result.putString("error", android.util.Log.getStackTraceString(error));
                finish(Activity.RESULT_CANCELED, result);
            }
        }, "LinuxAudioVerification").start();
    }
    private void verifyLifetime(CommandExecution execution, LinuxAudio first, Bundle result) throws Exception {
        if (backend != DesktopExecBackend.TERMUX) throw new IllegalArgumentException("Lifecycle fixture requires Termux clients");
        try (var second = LinuxAudio.acquire(getTargetContext(), execution)) {
            CompletableFuture<Integer> revoked = new CompletableFuture<>();
            try (var live = execution.start(first.exports() +
                    "paplay --raw --format=float32le --rate=48000 --channels=2 --latency-msec=30 /dev/zero",
                    "", "Audio lease revocation", null, (code, output, error) -> revoked.complete(code))) {
                // An unused owner must not stop the graph used by either active owner.
                try (var unused = LinuxAudio.acquire(getTargetContext(), execution)) {
                    if (unused.snapshot()[2] == 0) throw new AssertionError("Graph unexpectedly replaced");
                }
                play(execution, second);
                first.close();
                // EVENT_WAIT: revoked protocol connection terminates its client; expiry fails custody check.
                if (revoked.get(15, TimeUnit.SECONDS) == 0) throw new AssertionError("Revoked stream completed normally");
                long before = second.snapshot()[3];
                play(execution, second);
                long[] after = second.snapshot();
                if (after[3] - before < 35000 || after[1] != 0 || after[5] != 0)
                    throw new AssertionError("Revocation disturbed the remaining owner: " + Arrays.toString(after));
                result.putString("lifecycle", "PASS concurrent owners, unused lease, connection revocation, remaining playback");
            }
        }
    }
    private void play(CommandExecution execution, LinuxAudio audio) throws Exception {
        CompletableFuture<Void> completed = new CompletableFuture<>();
        try (var process = execution.start(audio.exports() + command, "", "Audio lifetime verification", null,
                (code, output, error) -> {
                    if (code != 0 || error != null) completed.completeExceptionally(new IOException(output, error));
                    else completed.complete(null);
                })) {
            // EVENT_WAIT: client drain and exit, with command cancellation on expiry.
            completed.get(40, TimeUnit.SECONDS);
        }
    }
    private static void awaitShell() throws Exception {
        ShellAccess.initialize();
        CompletableFuture<Void> ready = new CompletableFuture<>();
        ShellAccess.StateListener listener = snapshot -> { if (snapshot.isReady()) ready.complete(null); };
        ShellAccess.addStateListener(listener);
        try {
            if (ShellAccess.isReady()) ready.complete(null);
            // EVENT_WAIT: existing authorized shell binding; expiry fails without switching identity.
            ready.get(30, TimeUnit.SECONDS);
        } finally { ShellAccess.removeStateListener(listener); }
    }
}
