package io.github.mekhontsev.magicdesk;

import android.content.Context;

final class RunCommandPreferences {
    static boolean enabled(Context context) {
        return context.getSharedPreferences("external_commands", Context.MODE_PRIVATE).getBoolean("enabled", false);
    }
    static boolean setEnabled(Context context, boolean enabled) {
        boolean saved = context.getSharedPreferences("external_commands", Context.MODE_PRIVATE)
                .edit().putBoolean("enabled", enabled).commit();
        if (saved && !enabled) context.stopService(new android.content.Intent(context, RunCommandService.class));
        return saved;
    }
    private RunCommandPreferences() { }
}
