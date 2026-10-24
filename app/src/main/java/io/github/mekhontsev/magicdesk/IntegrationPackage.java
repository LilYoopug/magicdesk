package io.github.mekhontsev.magicdesk;

import android.content.Context;
import android.content.pm.PackageManager;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/** Package selection is separate from the compatible application's wire protocol. */
enum IntegrationPackage {
    SHIZUKU("shizukuManagerPackage", "com.hamondev.shevery;moe.shizuku.privileged.api"),
    TERMUX("termuxPackage", "com.termux");

    static final int MAX_LENGTH = 2048;
    private static final int MAX_PACKAGE_LENGTH = 255;
    private static final Pattern NAME = Pattern.compile(
            "[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+");
    final String key;
    final String defaultPackages;

    IntegrationPackage(final String key, final String defaultPackages) {
        this.key = key;
        this.defaultPackages = defaultPackages;
    }

    String selected() {
        return active().get(this);
    }

    String activeConfigured() {
        return Active.CONFIGURED.get(this);
    }

    boolean restartRequired(final Context context) {
        return !configured(context).equals(activeConfigured());
    }

    String configured(final Context context) {
        return context.getSharedPreferences("integration_packages", Context.MODE_PRIVATE)
                .getString(key, defaultPackages);
    }

    boolean save(final Context context, final String value) {
        return context.getSharedPreferences("integration_packages", Context.MODE_PRIVATE)
                .edit().putString(key, normalize(value)).commit();
    }

    static Map<IntegrationPackage, String> active() {
        return Active.PACKAGES;
    }

    private static final class Active {
        // Initialized once at application startup. Saving Settings affects only the next process.
        static final Map<IntegrationPackage, String> CONFIGURED = load();
        static final Map<IntegrationPackage, String> PACKAGES = snapshot(CONFIGURED, name -> {
            try {
                MagicDeskApplication.applicationContext().getPackageManager().getPackageInfo(name,
                        PackageManager.PackageInfoFlags.of(0));
                return true;
            } catch (PackageManager.NameNotFoundException error) {
                return false;
            }
        });

        private static Map<IntegrationPackage, String> load() {
            final Map<IntegrationPackage, String> configured = new EnumMap<>(IntegrationPackage.class);
            for (final IntegrationPackage integration : values()) {
                configured.put(integration, normalize(integration.configured(MagicDeskApplication.applicationContext())));
            }
            return Map.copyOf(configured);
        }
    }

    static Map<IntegrationPackage, String> snapshot(final Map<IntegrationPackage, String> configured,
            final Predicate<String> installed) {
        final Map<IntegrationPackage, String> result = new EnumMap<>(IntegrationPackage.class);
        for (final IntegrationPackage integration : values()) {
            result.put(integration, select(configured.getOrDefault(integration, integration.defaultPackages), installed));
        }
        return Map.copyOf(result);
    }

    static String select(final String value, final Predicate<String> installed) {
        final String[] packages = normalize(value).split(";");
        for (final String name : packages) {
            if (installed.test(name)) return name;
        }
        // Retain an explicit destination for the existing not-installed diagnostics/install link.
        return packages[0];
    }

    static String normalize(final String value) {
        if (value == null || value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("invalid application package list");
        }
        final var packages = new ArrayList<String>();
        for (final String part : value.split(";", -1)) {
            final String name = part.trim();
            if (name.isEmpty()) continue;
            if (name.length() > MAX_PACKAGE_LENGTH || !NAME.matcher(name).matches()) {
                throw new IllegalArgumentException("invalid application package name");
            }
            packages.add(name);
        }
        if (packages.isEmpty()) throw new IllegalArgumentException("empty application package list");
        return String.join(";", packages);
    }
}
