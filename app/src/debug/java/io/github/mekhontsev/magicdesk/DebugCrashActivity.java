package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.os.Bundle;
import android.os.Parcel;
import android.widget.Button;

/** Separate-process fixture for the real framework crash callback and Binder payload. */
public final class DebugCrashActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        verifyParcel();
        Button crash = new Button(this);
        crash.setText("Generate test crash");
        crash.setOnClickListener(view -> {
            throw new IllegalStateException("MagicDesk diagnostic crash fixture",
                    new IndexOutOfBoundsException("diagnostic nested cause"));
        });
        setContentView(crash);
    }

    private static void verifyParcel() {
        DesktopProcessFailureEvent original = new DesktopProcessFailureEvent(1,
                "example:renderer", 10, 20, 30, 40, 5, "example/.Main",
                "failure", "message", "frame\nCaused by: nested");
        Parcel parcel = Parcel.obtain();
        try {
            original.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            DesktopProcessFailureEvent decoded = DesktopProcessFailureEvent.CREATOR.createFromParcel(parcel);
            if (!original.technicalDetail("version").equals(decoded.technicalDetail("version"))) {
                throw new AssertionError("Process failure parcel lost evidence");
            }
        } finally {
            parcel.recycle();
        }
    }
}
