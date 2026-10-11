package io.github.mekhontsev.magicdesk.commandtest;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;

/** Separate UID exercises the public Android contract, including denied permission. */
public final class ClientActivity extends Activity {
    private boolean sent;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this); text.setText("RUN_COMMAND fixture"); setContentView(text);
    }
    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused || sent) return;
        sent = true;
        String id = getIntent().getStringExtra("case");
        if (id == null || !id.matches("[a-zA-Z0-9_-]+")) { finish(); return; }
        Intent destination = new Intent(this, ResultReceiver.class).setAction(id);
        PendingIntent result = PendingIntent.getBroadcast(this, id.hashCode(), destination,
                PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        try {
            Intent command = new Intent("io.github.mekhontsev.magicdesk.RUN_COMMAND")
                    .setClassName("io.github.mekhontsev.magicdesk", "io.github.mekhontsev.magicdesk.RunCommandService")
                    .putExtra("request", getIntent().getStringExtra("request"));
            if (!getIntent().getBooleanExtra("noResult", false)) command.putExtra("result", result);
            startForegroundService(command);
        } catch (RuntimeException error) {
            ResultReceiver.save(this, id, new Intent().putExtra("status", "rejected")
                    .putExtra("error", error.toString()));
        }
        finish();
    }
}
