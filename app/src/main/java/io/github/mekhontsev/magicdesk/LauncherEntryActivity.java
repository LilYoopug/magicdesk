package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.os.Bundle;

/** Narrow launcher-only adapter. No command, environment, profile or destination comes from Intent extras. */
public final class LauncherEntryActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        // A recreated entry must not replay an already accepted launch.
        if (state != null) { finish(); return; }
        String caller = getCallingPackage();
        int displayId = getDisplay().getDisplayId();
        LauncherExports.IO.execute(() -> {
            try {
                var export = LauncherExports.authenticate(this, caller);
                String uniqueId = DesktopDisplayCatalog.require(displayId, null).uniqueId;
                var shortcut = LauncherExports.resolve(this, export.target());
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    try {
                        LauncherExports.requireIdentity(this, export.target());
                        var target = ToolLaunchTarget.resolve("auto", displayId, DesktopRuntimeBridge.workspaceDisplayIds());
                        var request = DesktopLaunchRequest.from(shortcut, DesktopLaunchArguments.empty(), export.target().path());
                        request = ApplicationEntryLauncher.present(request, target, DesktopLaunchPresentation.automatic());
                        ApplicationEntryLauncher.launch(this, request, target, uniqueId, () -> current(export.target()),
                                error -> { if (error == null) { setResult(RESULT_OK); finish(); } else failed(error); });
                    } catch (RuntimeException error) { failed(error); }
                });
            } catch (Exception error) { runOnUiThread(() -> failed(error)); }
        });
    }

    private boolean current(LauncherExportStore.Target target) {
        if (isFinishing() || isDestroyed()) return false;
        try { LauncherExports.requireIdentity(this, target); return true; }
        catch (RuntimeException error) { runOnUiThread(() -> failed(error)); return false; }
    }

    private void failed(Throwable error) {
        if (isFinishing() || isDestroyed()) return;
        CompatibilityDiagnostics.record("LAUNCHER-OPEN-001", "Could not launch exported application", "", error);
        UiDialogs.builder(this).setTitle(R.string.launcher_export_title)
                .setMessage(getString(R.string.launcher_export_failed, ShellAccess.usefulMessage(error)))
                .setPositiveButton(android.R.string.ok, null).setOnDismissListener(dialog -> finish()).show();
    }
}
