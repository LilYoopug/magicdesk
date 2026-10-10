package io.github.mekhontsev.magicdesk;

import java.util.LinkedHashMap;
import java.util.Map;

/** Explicit per-PTY variables, not process-global state or shell source text. */
final class TerminalLaunchEnvironment {
    static Map<String, String> decode(String[] values) {
        var result = new LinkedHashMap<String, String>();
        if (values == null || values.length > 64) throw new IllegalArgumentException("Invalid terminal environment");
        int bytes = 0;
        for (String value : values) {
            int separator = value == null ? -1 : value.indexOf('=');
            if (separator <= 0 || value.indexOf('\0') >= 0 || (bytes += value.length()) > 65536
                    || !value.substring(0, separator).matches("[A-Za-z_][A-Za-z0-9_]*"))
                throw new IllegalArgumentException("Invalid terminal variable");
            result.put(value.substring(0, separator), value.substring(separator + 1));
        }
        return result;
    }
    static String[] encode(Map<String, String> values) {
        return values.entrySet().stream().map(entry -> entry.getKey() + "=" + entry.getValue()).toArray(String[]::new);
    }
    static String exports(Map<String, String> environment) {
        return environment.entrySet().stream().map(entry -> "export " + entry.getKey() + "="
                + ShellCommandLine.quote(entry.getValue()) + "\n").collect(java.util.stream.Collectors.joining());
    }
    private TerminalLaunchEnvironment() { }
}
