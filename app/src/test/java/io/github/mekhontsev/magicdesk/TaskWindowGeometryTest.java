package io.github.mekhontsev.magicdesk;

import android.graphics.Rect;
import org.junit.Test;
import static org.junit.Assert.assertThrows;

public final class TaskWindowGeometryTest {
    @Test public void validatesEntireBatchAndAcceptsOffscreenCoordinates() {
        Rect bounds = DesktopWindowLayoutController.rect(new WindowLayoutPolicy.Bounds(-200, 10, 900, 800));
        TaskWindowingCommand.validateGeometry(3, new int[] {10, 20}, new Rect[] {bounds, bounds});
        assertThrows(IllegalArgumentException.class, () -> TaskWindowingCommand.validateGeometry(
                3, new int[] {10, 10}, new Rect[] {bounds, bounds}));
        assertThrows(IllegalArgumentException.class, () -> TaskWindowingCommand.validateGeometry(
                3, new int[] {10, 20}, new Rect[] {bounds, null}));
        assertThrows(IllegalArgumentException.class, () -> TaskWindowingCommand.validateGeometry(
                3, new int[] {10}, new Rect[] {}));
    }
}
