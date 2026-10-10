package io.github.mekhontsev.magicdesk;

import android.content.Context;
import java.io.Closeable;
import java.io.IOException;

/** Optional launch capabilities; neither belongs to a display protocol or Desktop. */
final class LinuxLaunchServices implements Closeable {
    private final LinuxAudio audio;
    final LinuxGamepads gamepads;

    private LinuxLaunchServices(LinuxAudio audio, LinuxGamepads gamepads) {
        this.audio = audio;
        this.gamepads = gamepads;
    }

    static LinuxLaunchServices prepare(Context context, CommandExecution commands) {
        LinuxAudio audio = LinuxAudio.prepare(context, commands);
        LinuxGamepads gamepads = null;
        try { gamepads = LinuxGamepads.prepare(context, commands); }
        catch (IOException error) {
            CompatibilityDiagnostics.record("LINUX-GAMEPAD-001", "Linux gamepad input is unavailable",
                    ShellAccess.usefulMessage(error), error);
        } catch (RuntimeException error) { audio.close(); throw error; }
        return new LinuxLaunchServices(audio, gamepads);
    }

    String exports() { return audio.exports() + (gamepads == null ? "" : gamepads.exports()); }

    @Override public void close() {
        if (gamepads != null) gamepads.close();
        audio.close();
    }
}
