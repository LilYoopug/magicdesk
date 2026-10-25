package io.github.mekhontsev.magicdesk;

import android.view.KeyEvent;
import java.util.HashSet;
import java.util.Set;

/** One physical keyboard's chord lease. Ordinary typing stays in InputDispatcher. */
final class HostedKeyboardShortcuts {
    interface Target {
        boolean key(KeyEvent event);
        void release();
    }

    private final Set<Integer> forwarded = new HashSet<>();
    private final Set<Integer> nativeKeys = new HashSet<>();
    private Target target;

    boolean accept(KeyEvent event, boolean reserved, java.util.function.Supplier<Target> destination) {
        int key = event.getKeyCode();
        boolean down = event.getAction() == KeyEvent.ACTION_DOWN;
        if (hardwareKey(key)) return false;
        boolean nativeKey = nativeKeys.contains(key);
        if (reserved) cancel();
        if (down && !reserved && !nativeKey && forwarded.isEmpty() && target == null
                && event.getRepeatCount() == 0 && startsChord(event)
                && nativeKeys.stream().noneMatch(KeyEvent::isModifierKey)) {
            target = destination.get();
        }
        boolean consumed = forwarded.contains(key)
                || down && (target != null || !forwarded.isEmpty()) && !nativeKey;
        if (consumed) {
            if (down) forwarded.add(key);
            else forwarded.remove(key);
            if (target != null && !target.key(event)) cancel();
            if (forwarded.isEmpty()) cancel();
        } else if (down) nativeKeys.add(key);
        if (!down) nativeKeys.remove(key);
        return consumed;
    }

    // Keep consumed down/up pairs owned until release even after focus or route loss.
    void cancel() {
        if (target != null) target.release();
        target = null;
    }

    private static boolean startsChord(KeyEvent event) {
        return KeyEvent.isModifierKey(event.getKeyCode()) || event.isSystem()
                || event.getKeyCode() == KeyEvent.KEYCODE_APP_SWITCH;
    }

    private static boolean hardwareKey(int key) {
        return key == KeyEvent.KEYCODE_POWER || key == KeyEvent.KEYCODE_SLEEP
                || key == KeyEvent.KEYCODE_WAKEUP || key == KeyEvent.KEYCODE_VOLUME_UP
                || key == KeyEvent.KEYCODE_VOLUME_DOWN || key == KeyEvent.KEYCODE_VOLUME_MUTE;
    }
}
