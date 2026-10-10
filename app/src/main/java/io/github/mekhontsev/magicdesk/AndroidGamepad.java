package io.github.mekhontsev.magicdesk;

import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.MotionEvent;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/** Canonical Linux gamepad capabilities derived from the actual Android device. */
final class AndroidGamepad {
    private static final int[] ANDROID_KEYS = {KeyEvent.KEYCODE_BUTTON_A, KeyEvent.KEYCODE_BUTTON_B,
            KeyEvent.KEYCODE_BUTTON_X, KeyEvent.KEYCODE_BUTTON_Y, KeyEvent.KEYCODE_BUTTON_L1,
            KeyEvent.KEYCODE_BUTTON_R1, KeyEvent.KEYCODE_BUTTON_L2, KeyEvent.KEYCODE_BUTTON_R2,
            KeyEvent.KEYCODE_BUTTON_SELECT, KeyEvent.KEYCODE_BUTTON_START, KeyEvent.KEYCODE_BUTTON_MODE,
            KeyEvent.KEYCODE_BUTTON_THUMBL, KeyEvent.KEYCODE_BUTTON_THUMBR,
            KeyEvent.KEYCODE_DPAD_UP, KeyEvent.KEYCODE_DPAD_DOWN, KeyEvent.KEYCODE_DPAD_LEFT, KeyEvent.KEYCODE_DPAD_RIGHT};
    private static final int[] LINUX_KEYS = {304, 305, 307, 308, 310, 311, 312, 313, 314, 315, 316, 317, 318, 544, 545, 546, 547};
    final InputDevice device;
    final int slot;
    private final boolean[] supported;
    private final boolean[] pressed = new boolean[ANDROID_KEYS.length];
    private final ArrayList<Axis> axes = new ArrayList<>();
    private record Axis(int android, int linux, InputDevice.MotionRange range, boolean centered) { }
    private final int[] values = new int[GamepadWire.AXES];
    private final int[] nextValues = new int[GamepadWire.AXES];
    final boolean rumble;

    static boolean accepts(InputDevice device) {
        return device != null && !device.isVirtual() && (device.supportsSource(InputDevice.SOURCE_GAMEPAD)
                || (device.supportsSource(InputDevice.SOURCE_JOYSTICK)
                    && device.getKeyboardType() != InputDevice.KEYBOARD_TYPE_ALPHABETIC
                    && device.getMotionRange(MotionEvent.AXIS_X, InputDevice.SOURCE_JOYSTICK) != null
                    && device.getMotionRange(MotionEvent.AXIS_Y, InputDevice.SOURCE_JOYSTICK) != null));
    }

    AndroidGamepad(InputDevice device, int slot) {
        this.device = device; this.slot = slot;
        supported = device.hasKeys(ANDROID_KEYS);
        add(MotionEvent.AXIS_X, 0, true); add(MotionEvent.AXIS_Y, 1, true);
        add(first(MotionEvent.AXIS_Z, MotionEvent.AXIS_RX), 3, true);
        add(first(MotionEvent.AXIS_RZ, MotionEvent.AXIS_RY), 4, true);
        add(first(MotionEvent.AXIS_LTRIGGER, MotionEvent.AXIS_BRAKE), 2, false);
        add(first(MotionEvent.AXIS_RTRIGGER, MotionEvent.AXIS_GAS), 5, false);
        add(MotionEvent.AXIS_HAT_X, 16, true); add(MotionEvent.AXIS_HAT_Y, 17, true);
        rumble = device.getVibratorManager().getDefaultVibrator().hasVibrator();
    }

    private InputDevice.MotionRange range(int axis) {
        return device.getMotionRange(axis, InputDevice.SOURCE_JOYSTICK);
    }
    private int first(int primary, int alternate) { return range(primary) != null ? primary : alternate; }
    private void add(int android, int linux, boolean centered) {
        InputDevice.MotionRange range = range(android);
        if (range != null && range.getRange() > 0) axes.add(new Axis(android, linux, range, centered));
    }

    byte[] description() {
        ByteBuffer b = GamepadWire.packet(GamepadWire.ADD, slot, GamepadWire.DESCRIPTION);
        byte[] name = device.getName().getBytes(StandardCharsets.UTF_8);
        b.put(name, 0, Math.min(127, name.length)); b.position(GamepadWire.HEADER + 128);
        b.putShort((short) 6).putShort((short) device.getVendorId()).putShort((short) device.getProductId()).putShort((short) 1);
        byte[] keys = new byte[GamepadWire.KEYS / 8], abs = new byte[GamepadWire.AXES / 8];
        for (int i = 0; i < supported.length; ++i) if (supported[i]) GamepadWire.bit(keys, LINUX_KEYS[i]);
        for (Axis axis : axes) GamepadWire.bit(abs, axis.linux);
        b.put(keys).put(abs);
        for (int i = 0; i < GamepadWire.AXES; ++i) {
            Axis selected = null;
            for (Axis axis : axes) if (axis.linux == i) { selected = axis; break; }
            if (selected == null) { b.position(b.position() + 24); continue; }
            int maximum = selected.linux == 16 || selected.linux == 17 ? 1 : 32767;
            float units = (selected.centered ? 2f * maximum : maximum) / selected.range.getRange();
            b.putInt(0).putInt(selected.centered ? -maximum : 0).putInt(maximum)
                    .putInt(Math.max(0, Math.round(selected.range.getFuzz() * units)))
                    .putInt(Math.max(0, Math.round(selected.range.getFlat() * units))).putInt(0);
        }
        b.putInt(rumble ? 1 : 0);
        return b.array();
    }

    byte[] key(KeyEvent event) {
        int code = event.getKeyCode();
        for (int i = 0; i < ANDROID_KEYS.length; ++i) if (ANDROID_KEYS[i] == code && supported[i]) {
            boolean down = event.getAction() == KeyEvent.ACTION_DOWN;
            if (pressed[i] == down) return null;
            pressed[i] = down;
            return GamepadWire.packet(GamepadWire.FRAME, slot, 8).putShort((short) 1)
                    .putShort((short) LINUX_KEYS[i]).putInt(down ? 1 : 0).array();
        }
        return null;
    }

    boolean handlesKey(int code) {
        for (int i = 0; i < ANDROID_KEYS.length; ++i)
            if (ANDROID_KEYS[i] == code && supported[i]) return true;
        return false;
    }

    byte[] motion(MotionEvent event) {
        int changed = 0;
        int[] next = nextValues;
        for (int i = 0; i < axes.size(); ++i) {
            Axis axis = axes.get(i);
            next[i] = GamepadWire.scale(event.getAxisValue(axis.android), axis.range.getMin(), axis.range.getMax(), axis.centered);
            if (axis.linux == 16 || axis.linux == 17) next[i] = Integer.signum(next[i]);
            if (next[i] != values[axis.linux]) changed++;
        }
        if (changed == 0) return null;
        ByteBuffer b = GamepadWire.packet(GamepadWire.FRAME, slot, changed * 8);
        for (int i = 0; i < axes.size(); ++i) {
            Axis axis = axes.get(i);
            if (next[i] == values[axis.linux]) continue;
            values[axis.linux] = next[i];
            b.putShort((short) 3).putShort((short) axis.linux).putInt(next[i]);
        }
        return b.array();
    }

    void neutralize() {
        java.util.Arrays.fill(pressed, false); java.util.Arrays.fill(values, 0);
        if (rumble) try { device.getVibratorManager().cancel(); }
        catch (RuntimeException error) {
            android.util.Log.d("MagicDeskGamepads", "Controller vibration unavailable", error);
        }
    }
}
