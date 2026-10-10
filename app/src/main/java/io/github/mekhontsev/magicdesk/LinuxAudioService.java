package io.github.mekhontsev.magicdesk;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.MessageQueue;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import io.github.mekhontsev.magicdesk.audio.AudioEngine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** App-UID audio process. No Desktop, shell startup, or Linux hardware discovery. */
public final class LinuxAudioService extends Service {
    private static final String CHANNEL = "linux-audio";
    private static final int NOTIFICATION = 206;
    private final HandlerThread thread = new HandlerThread("LinuxAudioControl");
    private Handler control;
    private AudioManager manager;
    private AudioFocusRequest focus;
    private AudioEngine engine;
    private ParcelFileDescriptor event;
    private Path directory;
    private boolean focusHeld, focusRequested, interrupted, foreground, failed, ducked, stopping;
    private int routeRetries;
    private long rendered;
    private final HashSet<Lease> leases = new HashSet<>();

    @Override public void onCreate() {
        super.onCreate();
        thread.start();
        control = new Handler(thread.getLooper());
        manager = getSystemService(AudioManager.class);
        focus = new AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN)
                .setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC).build())
                .setAcceptsDelayedFocusGain(true)
                .setOnAudioFocusChangeListener(this::focusChanged, control).build();
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel(
                CHANNEL, getString(R.string.linux_audio), NotificationManager.IMPORTANCE_LOW));
    }

    @Override public IBinder onBind(Intent intent) {
        return new ILinuxAudioService.Stub() {
            @Override public ILinuxAudioLease acquire(String owner, IBinder lifetime) {
                checkCaller();
                if (owner == null || !owner.matches("audio-[a-f0-9-]{36}") || lifetime == null)
                    throw new IllegalArgumentException("Invalid audio owner");
                return call(() -> {
                    if (stopping) throw new IOException("Audio service is stopping");
                    Lease lease = new Lease(owner, lifetime);
                    lifetime.linkToDeath(lease, 0);
                    leases.add(lease);
                    return lease;
                }, Lease::release, null);
            }
        };
    }

    private final class Lease extends ILinuxAudioLease.Stub implements IBinder.DeathRecipient {
        final String owner;
        final IBinder lifetime;
        boolean closed;
        Lease(String owner, IBinder lifetime) { this.owner = owner; this.lifetime = lifetime; }
        @Override public void accept(int protocol, ParcelFileDescriptor socket) {
            checkCaller();
            if (socket == null) throw new IllegalArgumentException("Missing audio connection");
            try (socket) {
                ParcelFileDescriptor owned = ParcelFileDescriptor.dup(socket.getFileDescriptor());
                call(() -> {
                    if (closed) throw new IOException("Audio lease is closed");
                    ensureEngine();
                    engine.accept(protocol, owned.detachFd(), owner);
                    return null;
                }, ignored -> { }, owned);
            } catch (IOException error) { throw new IllegalStateException(error); }
        }
        @Override public long[] snapshot() {
            checkCaller();
            return call(() -> {
                if (closed) throw new IOException("Audio lease is closed");
                return engine == null ? new long[10] : engine.snapshot();
            });
        }
        @Override public void close() { checkCaller(); control.post(this::release); }
        @Override public void binderDied() { control.post(this::release); }
        private void release() {
            if (closed) return;
            closed = true;
            lifetime.unlinkToDeath(this, 0);
            leases.remove(this);
            if (engine != null) engine.revoke(owner);
            if (leases.isEmpty()) releaseEngine();
        }
    }

    private void ensureEngine() throws IOException {
        if (engine != null) return;
        if (stopping) throw new IOException("Audio service is stopping");
        directory = getCacheDir().toPath().resolve("linux-audio");
        try {
            // This service is the sole graph owner; remove files left by process death.
            FileTreeDeletion.deleteIfExists(directory);
            Files.createDirectories(directory);
            try (var input = getAssets().open("audio/pipewire.conf")) {
                Files.copy(input, directory.resolve("pipewire.conf"));
            }
            engine = new AudioEngine(directory.toString(), getApplicationInfo().nativeLibraryDir);
            event = ParcelFileDescriptor.fromFd(engine.eventFd());
            Looper.myQueue().addOnFileDescriptorEventListener(event.getFileDescriptor(),
                    MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT, (fd, events) -> {
                        if ((events & MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR) != 0) {
                            failed = true;
                            updatePlayback(false);
                            return 0;
                        }
                        observe();
                        return MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT;
                    });
        } catch (IOException | RuntimeException error) { releaseEngine(); throw error; }
    }

    private void observe() {
        if (engine == null) return;
        engine.acknowledge();
        long[] state = engine.snapshot();
        if (state[3] != rendered) { rendered = state[3]; routeRetries = 0; }
        if (state[1] != 0) {
            // A disconnected Android route can be reopened once from this control thread.
            if (state[1] == -899 && !failed && routeRetries++ == 0) {
                engine.playback(focusHeld && state[0] != 0, ducked);
                return;
            }
            failed = true;
            android.util.Log.e("MagicDeskAudio", "Android output failed: " + state[1]);
        }
        updatePlayback(state[0] != 0 && !failed);
    }

    private void updatePlayback(boolean active) {
        if (!active) {
            if (engine != null) engine.playback(false, false);
            if (focusRequested) manager.abandonAudioFocusRequest(focus);
            focusHeld = false;
            focusRequested = false;
            interrupted = false;
            ducked = false;
            if (foreground) stopForeground(STOP_FOREGROUND_REMOVE);
            foreground = false;
            return;
        }
        try {
            if (!foreground) {
                var notification = new Notification.Builder(this, CHANNEL)
                        .setSmallIcon(R.drawable.ic_volume)
                        .setContentTitle(getString(R.string.linux_audio))
                        .setCategory(Notification.CATEGORY_TRANSPORT).setOngoing(true).build();
                startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK);
                foreground = true;
            }
            if (!focusRequested && !interrupted) {
                int result = manager.requestAudioFocus(focus);
                focusRequested = result != AudioManager.AUDIOFOCUS_REQUEST_FAILED;
                focusHeld = result == AudioManager.AUDIOFOCUS_REQUEST_GRANTED;
                interrupted = !focusRequested;
            }
            engine.playback(focusHeld, ducked);
        } catch (RuntimeException error) {
            failed = true;
            android.util.Log.e("MagicDeskAudio", "Audio focus or background playback unavailable", error);
            updatePlayback(false);
        }
    }

    private void focusChanged(int change) {
        if (engine == null) return;
        if (change == AudioManager.AUDIOFOCUS_GAIN) { focusHeld = true; ducked = false; }
        else if (change == AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK) { ducked = true; }
        else {
            focusHeld = false;
            if (change == AudioManager.AUDIOFOCUS_LOSS) {
                manager.abandonAudioFocusRequest(focus);
                focusRequested = false;
                interrupted = true;
            }
        }
        engine.playback(focusHeld && engine.snapshot()[0] != 0, ducked);
    }

    private void releaseEngine() {
        updatePlayback(false);
        if (event != null) {
            Looper.myQueue().removeOnFileDescriptorEventListener(event.getFileDescriptor());
            try { event.close(); } catch (IOException ignored) { }
            event = null;
        }
        if (engine != null) { engine.close(); engine = null; }
        if (directory != null) {
            try { FileTreeDeletion.deleteIfExists(directory); }
            catch (IOException error) { android.util.Log.w("MagicDeskAudio", "Audio directory cleanup failed", error); }
            directory = null;
        }
        failed = false;
        routeRetries = 0;
        rendered = 0;
    }

    @Override public void onDestroy() {
        control.post(() -> {
            stopping = true;
            for (Lease lease : new HashSet<>(leases)) lease.release();
            releaseEngine();
            thread.quitSafely();
        });
        super.onDestroy();
    }
    private static void checkCaller() {
        if (Binder.getCallingUid() != android.os.Process.myUid())
            throw new SecurityException("Not the audio service owner");
    }
    private <T> T call(Callable<T> action) {
        return call(action, ignored -> { }, null);
    }
    private <T> T call(Callable<T> action, java.util.function.Consumer<T> discard, java.io.Closeable input) {
        CompletableFuture<T> result = new CompletableFuture<>();
        if (!control.post(() -> {
            try {
                if (result.isCancelled()) return;
                T value = action.call();
                if (!result.complete(value)) discard.accept(value);
            }
            catch (Exception error) { result.completeExceptionally(error); }
            finally { closeInput(input); }
        })) {
            closeInput(input);
            throw new IllegalStateException("Audio service stopped");
        }
        try {
            // EVENT_WAIT: serialized audio operation; expiry fails the Binder request.
            return result.get(15, TimeUnit.SECONDS);
        } catch (InterruptedException error) {
            result.cancel(false); Thread.currentThread().interrupt(); throw new IllegalStateException(error);
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException error) {
            result.cancel(false); throw new IllegalStateException("Audio operation failed", error);
        }
    }
    private static void closeInput(java.io.Closeable input) {
        if (input != null) try { input.close(); } catch (IOException ignored) { }
    }
}
