package io.github.mekhontsev.magicdesk;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;

/** Resolves Android icons or cached Linux artwork; never performs command/file I/O. */
final class DesktopApplicationIconResolver {
    private DesktopApplicationIconResolver() {
    }

    static android.graphics.Bitmap hostedIcon(android.graphics.Bitmap client, RecentApplicationStore.Entry recipe) {
        return client != null ? client : recipe == null ? null
                : ApplicationIcons.cached(ApplicationIcons.key(recipe.shortcut(), recipe.termuxPackage()));
    }

    static Drawable resolve(
            final Context context,
            final DesktopApplicationShortcut shortcut) {
        return resolve(context, shortcut, null);
    }

    static Drawable resolve(Context context, DesktopApplicationShortcut shortcut, String termuxPackage) {
        if (shortcut.icon.startsWith("guest:") || shortcut.hasExecLaunch() && shortcut.execBackend == DesktopExecBackend.TERMUX) {
            final var bitmap = ApplicationIcons.cached(ApplicationIcons.key(shortcut, termuxPackage));
            return bitmap == null ? UiAppearance.symbol(context, R.drawable.ic_file_console, UiColor.TEXT)
                    : new android.graphics.drawable.BitmapDrawable(context.getResources(), bitmap);
        }
        final String packageName = shortcut.launchTarget != null
                ? shortcut.launchTarget.packageName : shortcut.icon;
        if (packageName != null && !packageName.isEmpty()) {
            try {
                return context.getPackageManager()
                        .getApplicationIcon(packageName);
            } catch (PackageManager.NameNotFoundException
                    | RuntimeException ignored) {
                // Freedesktop icon names do not map to Android packages.
            }
        }
        return UiAppearance.symbol(context, R.drawable.ic_file_console, UiColor.TEXT);
    }
}
