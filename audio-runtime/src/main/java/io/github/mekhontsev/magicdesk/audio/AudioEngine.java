package io.github.mekhontsev.magicdesk.audio;

import java.io.Closeable;
import java.io.IOException;

/** Native protocol graph and Android output, loaded only by the audio process. */
public final class AudioEngine implements Closeable {
    static { System.loadLibrary("magicdesk_audio"); }
    private long handle;

    public AudioEngine(String directory, String libraries) throws IOException {
        handle = create(directory, libraries);
        if (handle == 0) throw new IOException("Cannot initialize PipeWire audio runtime");
    }
    public synchronized int eventFd() { requireOpen(); return eventFd(handle); }
    public synchronized long[] snapshot() { requireOpen(); return snapshot(handle); }
    public synchronized void acknowledge() { requireOpen(); acknowledge(handle); }
    public synchronized void revoke(String owner) { requireOpen(); revoke(handle, owner); }
    public synchronized void playback(boolean allowed, boolean duck) {
        requireOpen(); playback(handle, allowed, duck);
    }
    /** Consumes fd on success and failure. */
    public synchronized void accept(int protocol, int fd, String owner) throws IOException {
        if (handle == 0) {
            try { android.os.ParcelFileDescriptor.adoptFd(fd).close(); } catch (IOException ignored) { }
            throw new IOException("Audio runtime closed");
        }
        int result = accept(handle, protocol, fd, owner);
        if (result < 0) throw new IOException("Audio connection rejected: " + result);
    }
    @Override public synchronized void close() {
        if (handle != 0) { destroy(handle); handle = 0; }
    }
    private void requireOpen() { if (handle == 0) throw new IllegalStateException("Audio runtime closed"); }
    private static native long create(String directory, String libraries);
    private static native int eventFd(long handle);
    private static native long[] snapshot(long handle);
    private static native void acknowledge(long handle);
    private static native void revoke(long handle, String owner);
    private static native void playback(long handle, boolean allowed, boolean duck);
    private static native int accept(long handle, int protocol, int fd, String owner);
    private static native void destroy(long handle);
}
