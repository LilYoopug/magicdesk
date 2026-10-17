package io.github.mekhontsev.magicdesk;

import android.content.Context;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.UUID;

/** The APK owns its Android interpreter; no system-shell or privilege fallback. */
public final class AndroidShell {
    static final String LIBRARY = "libmagicdesk_mksh.so";
    static final String PATH_ENV = "MAGICDESK_ANDROID_SHELL";

    public static String path(Context context) {
        if (context == null) throw new IllegalStateException("Android shell context is unavailable");
        return path(context.getApplicationInfo().nativeLibraryDir);
    }

    static String path(String libraries) {
        if (libraries == null || !libraries.startsWith("/"))
            throw new IllegalArgumentException("Missing APK native directory");
        // This is an Android script path, not a path on the JVM's build host.
        return libraries + (libraries.endsWith("/") ? "" : "/") + LIBRARY;
    }

    static String requireExecutable(String libraries) throws IOException {
        String shell = path(libraries);
        checkExecutable(Path.of(shell));
        return shell;
    }

    static void checkExecutable(Path shell) throws IOException {
        if (!Files.isRegularFile(shell) || !Files.isExecutable(shell))
            throw new IOException("Bundled Android shell is unavailable: " + shell);
    }

    public static ProcessBuilder command(Context context, String command) throws IOException {
        String shell = requireExecutable(context.getApplicationInfo().nativeLibraryDir);
        ProcessBuilder builder = new ProcessBuilder(shell, "-c", command);
        apply(builder.environment(), shell);
        return builder;
    }

    static void apply(Map<String, String> environment, String shell) {
        environment.put("SHELL", shell);
        environment.put(PATH_ENV, shell);
        environment.remove("EXECSHELL");
        environment.remove("ENV");
        environment.remove("HISTFILE");
        environment.remove("HISTSIZE");
    }

    static String script(String shell, String body) {
        // A shebang cannot quote its interpreter; reject an unrepresentable APK path.
        if (!shell.startsWith("/") || shell.chars().anyMatch(c -> c <= 32)
                || shell.getBytes(StandardCharsets.UTF_8).length > 250)
            throw new IllegalArgumentException("Invalid bundled shell script path");
        return "#!" + shell + "\nexport " + PATH_ENV + "=" + ShellCommandLine.quote(shell) + "\n" + body;
    }

    static void installAliases(Path directory, String shell) throws IOException {
        Path executable = Path.of(shell);
        for (String name : new String[]{"sh", "mksh"}) {
            Path alias = directory.resolve(name);
            if (Files.isSymbolicLink(alias) && Files.readSymbolicLink(alias).equals(executable)) continue;
            Path temporary = directory.resolve(".shell-" + UUID.randomUUID());
            try {
                Files.createSymbolicLink(temporary, executable);
                Files.move(temporary, alias, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } finally { Files.deleteIfExists(temporary); }
        }
    }

    private AndroidShell() { }
}
