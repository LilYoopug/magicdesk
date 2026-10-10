package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.nio.ByteOrder;
import org.junit.Test;

public final class GamepadWireTest {
    @Test public void boundedLittleEndianFrames() {
        var frame = GamepadWire.packet(GamepadWire.FRAME, 2, 8);
        assertEquals(ByteOrder.LITTLE_ENDIAN, frame.order());
        assertEquals(28, frame.capacity());
        frame.rewind();
        assertEquals(GamepadWire.MAGIC, frame.getInt());
        assertEquals(1, frame.getInt());
        assertEquals(GamepadWire.FRAME, frame.getInt());
        assertEquals(2, frame.getInt());
        assertEquals(8, frame.getInt());
        assertThrows(IllegalArgumentException.class, () -> GamepadWire.packet(1, 32, 0));
        assertThrows(IllegalArgumentException.class, () -> GamepadWire.packet(1, 0, 4097));
    }

    @Test public void scalesActualDeviceRangesWithoutApplyingDeadzoneTwice() {
        assertEquals(-32767, GamepadWire.scale(-2, -1, 1, true));
        assertEquals(0, GamepadWire.scale(0, -1, 1, true));
        assertEquals(32767, GamepadWire.scale(2, -1, 1, true));
        assertEquals(0, GamepadWire.scale(-1, 0, 255, false));
        assertEquals(32767, GamepadWire.scale(255, 0, 255, false));
        assertEquals(0, GamepadWire.scale(Float.NaN, 0, 1, true));
        assertEquals(0, GamepadWire.scale(1, 1, 1, true));
    }

    @Test public void inputAttachmentIsExplicitAndShellQuoted() throws Exception {
        org.junit.Assume.assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        String shell = System.getenv("PREFIX") == null ? "/bin/sh" : System.getenv("PREFIX") + "/bin/sh";
        for (boolean enabled : new boolean[]{false, true}) {
            var process = new ProcessBuilder(shell, "-c", "set -- -- /bin/echo 'a b'\n"
                    + GamepadWire.shrootArguments() + "printf '%s\\n' \"$@\"");
            process.environment().remove("MAGICDESK_GAMEPAD_ENDPOINT");
            if (enabled) process.environment().put("MAGICDESK_GAMEPAD_ENDPOINT", "endpoint a' b");
            var result = BoundedProcessRunner.run(process.start(), 5000, 4096);
            assertEquals(0, result.exitCode);
            assertEquals((enabled ? "--gamepad-endpoint\nendpoint a' b\n" : "") + "--\n/bin/echo\na b\n", result.output);
        }
    }
}
