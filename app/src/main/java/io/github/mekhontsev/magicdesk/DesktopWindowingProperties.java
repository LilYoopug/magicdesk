package io.github.mekhontsev.magicdesk;

import java.io.IOException;

/**
 * Owns the allowlisted Android desktop properties and verified value changes.
 *
 * <p>Property names and semantics are shared Android behavior. Write access is
 * platform-specific: shell cannot set these properties on every firmware.</p>
 */
public final class DesktopWindowingProperties {
    private static final String GETPROP = "/system/bin/getprop";
    private static final long COMMAND_TIMEOUT_MILLIS = 5_000L;
    private static final int MAX_OUTPUT_BYTES = 32 * 1024;

    @FunctionalInterface
    interface PropertyReader {
        String read(Property property) throws IOException;
    }

    @FunctionalInterface
    public interface Writer {
        /** Writes one validated value and returns the bounded transport reply. */
        String write(Property property, String value) throws IOException;
    }

    public enum Property {
        DEVICE_RESTRICTIONS(
                "persist.wm.debug.desktop_mode_enforce_device_restrictions"),
        ROUNDED_CORNERS(
                "persist.wm.debug.desktop_use_rounded_corners");

        public final String key;

        Property(final String key) {
            this.key = key;
        }
    }

    private DesktopWindowingProperties() {
    }

    public static String read(final Property property) throws IOException {
        requireProperty(property);
        final BoundedProcessRunner.Result result = run(
                new ProcessBuilder(GETPROP, property.key));
        requireSuccess("read " + property.key, result);
        final String value = result.output.trim();
        requireBooleanOrEmpty(value);
        return value;
    }

    public static boolean write(final Property property, final String value, final Writer writer)
            throws IOException {
        return write(property, value, DesktopWindowingProperties::read, writer);
    }

    static boolean write(final Property property, final String value,
            final PropertyReader reader, final Writer writer) throws IOException {
        requireProperty(property);
        requireBooleanOrEmpty(value);
        if (value.equals(reader.read(property))) {
            return false;
        }

        final String output = writer.write(property, value);

        // service can exit successfully with a Binder exception in its reply.
        // Only readback proves the write; retain the reply when verification fails.
        final String observed;
        try {
            observed = reader.read(property);
        } catch (IOException error) {
            throw new IOException("could not verify desktop property " + property.key
                    + ": " + error.getMessage() + outputSuffix(output), error);
        }
        if (!value.equals(observed)) {
            throw new IOException(
                    "Desktop property verification failed for "
                            + property.key
                            + ": expected=" + printable(value)
                            + " observed=" + printable(observed)
                            + outputSuffix(output));
        }
        return true;
    }

    static boolean isBooleanOrEmpty(final String value) {
        return value != null
                && (value.isEmpty()
                        || "true".equals(value)
                        || "false".equals(value));
    }

    private static BoundedProcessRunner.Result run(final ProcessBuilder builder)
            throws IOException {
        builder.redirectErrorStream(true);
        final Process process = builder.start();
        try {
            return BoundedProcessRunner.run(
                    process,
                    COMMAND_TIMEOUT_MILLIS,
                    MAX_OUTPUT_BYTES);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("Desktop property command interrupted", error);
        } finally {
            process.destroy();
        }
    }

    private static void requireSuccess(
            final String operation,
            final BoundedProcessRunner.Result result) throws IOException {
        if (result.exitCode != 0) {
            throw new IOException(
                    "could not " + operation
                            + ": exit=" + result.exitCode
                            + outputSuffix(result.output));
        }
        if (result.truncated) {
            throw new IOException(
                    "could not " + operation + ": command output was truncated");
        }
    }

    private static void requireProperty(final Property property) {
        if (property == null) {
            throw new IllegalArgumentException("property is null");
        }
    }

    private static void requireBooleanOrEmpty(final String value) {
        if (!isBooleanOrEmpty(value)) {
            throw new IllegalArgumentException(
                    "desktop property value must be true, false, or empty");
        }
    }

    private static String printable(final String value) {
        return value.isEmpty() ? "<empty>" : value;
    }

    private static String outputSuffix(final String output) {
        final String bounded = output.length() <= MAX_OUTPUT_BYTES
                ? output : output.substring(0, MAX_OUTPUT_BYTES) + " [truncated]";
        final String oneLine = bounded.trim()
                .replace('\n', ' ')
                .replace('\r', ' ');
        return oneLine.isEmpty() ? "" : ": " + oneLine;
    }
}
