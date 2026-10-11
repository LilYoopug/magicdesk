package io.github.mekhontsev.magicdesk.launcher;

import android.app.Activity;
import android.app.ActivityOptions;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.Toast;

/** No commands or credentials: Android supplies our authenticated calling package to the host. */
public final class LaunchActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) return;
        try {
            String host = getPackageManager().getApplicationInfo(getPackageName(),
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA))
                    .metaData.getString("magicdesk.package");
            var options = ActivityOptions.makeBasic().setLaunchDisplayId(getDisplay().getDisplayId());
            startActivityForResult(new Intent().setClassName(host, host + ".LauncherEntryActivity"), 1,
                    options.toBundle());
        } catch (PackageManager.NameNotFoundException | RuntimeException error) {
            Toast.makeText(this, "MagicDesk is unavailable", Toast.LENGTH_LONG).show();
            finish();
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        finish();
    }
}
