package io.github.mekhontsev.magicdesk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Launch-private Shroot device stream. No Android or display-protocol types. */
final class GamepadWire {
    static final int MAGIC = 0x4d444750, VERSION = 1, HEADER = 20, MAX_PAYLOAD = 4096;
    static final int ADD = 1, REMOVE = 2, FRAME = 3, NEUTRAL = 4, READY = 5, RUMBLE = 6;
    static final int DEVICES = 32, KEYS = 768, AXES = 64, DESCRIPTION = 1780;

    static ByteBuffer packet(int operation, int device, int size) {
        if (size < 0 || size > MAX_PAYLOAD || device < 0 || device >= DEVICES)
            throw new IllegalArgumentException("Invalid gamepad packet");
        ByteBuffer b = ByteBuffer.allocate(HEADER + size).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(MAGIC).putInt(VERSION).putInt(operation).putInt(device).putInt(size);
        return b;
    }

    static int scale(float value, float minimum, float maximum, boolean centered) {
        if (!Float.isFinite(value) || !Float.isFinite(minimum) || !Float.isFinite(maximum) || maximum <= minimum) return 0;
        float clamped = Math.max(minimum, Math.min(maximum, value));
        return centered ? Math.round((clamped - minimum) * 65534f / (maximum - minimum)) - 32767
                : Math.round((clamped - minimum) * 32767f / (maximum - minimum));
    }

    static void bit(byte[] bits, int index) { bits[index / 8] |= (byte) (1 << (index % 8)); }
    static String shrootArguments() {
        return "if [ -n \"${MAGICDESK_GAMEPAD_ENDPOINT:-}\" ]; then\n"
                + "set -- --gamepad-endpoint \"$MAGICDESK_GAMEPAD_ENDPOINT\" \"$@\"\nfi\n";
    }
    private GamepadWire() { }
}
