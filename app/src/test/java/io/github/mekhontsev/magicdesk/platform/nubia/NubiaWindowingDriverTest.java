package io.github.mekhontsev.magicdesk.platform.nubia;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import io.github.mekhontsev.magicdesk.DesktopWindowingProperties;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public final class NubiaWindowingDriverTest {
    @Test
    public void explicitRestrictionChangeOnlyWritesThatProperty() throws Exception {
        final List<String> values = new ArrayList<>();
        final var driver = new NubiaWindowingDriver((property, value) -> {
            assertEquals(DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS, property);
            values.add(value);
            return true;
        }, (property, error) -> { throw new AssertionError(error); });
        assertTrue(driver.canChangeDeviceRestrictions());
        driver.setDeviceRestrictionsEnabled(true);
        driver.setDeviceRestrictionsEnabled(false);
        assertEquals(List.of("true", "false"), values);
    }

    @Test
    public void explicitRestrictionDenialIsNotSwallowedAsOptionalSetup() {
        final var driver = new NubiaWindowingDriver((property, value) -> {
            throw new IOException("denied");
        }, (property, error) -> { throw new AssertionError(error); });
        org.junit.Assert.assertThrows(IOException.class, () -> driver.setDeviceRestrictionsEnabled(true));
    }

    @Test
    public void deniedPropertiesDoNotThrowOrRequireReboot() {
        final List<DesktopWindowingProperties.Property> warnings = new ArrayList<>();
        final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                (property, value) -> {
                    assertEquals("false", value);
                    throw new IOException("expected=false observed=<empty>");
                }, (property, error) -> {
                    warnings.add(property);
                    assertEquals("expected=false observed=<empty>", error.getMessage());
                });

        assertFalse(windowing.configure(false, false));
        assertEquals(List.of(DesktopWindowingProperties.Property.values()), warnings);
    }

    @Test
    public void eachPropertyIsIndependentAndVerifiedChangesRequireReboot() {
        for (final DesktopWindowingProperties.Property denied
                : DesktopWindowingProperties.Property.values()) {
            final List<DesktopWindowingProperties.Property> attempts = new ArrayList<>();
            final List<DesktopWindowingProperties.Property> warnings = new ArrayList<>();
            final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                    (property, value) -> {
                        attempts.add(property);
                        if (property == denied) {
                            throw new IOException("permission denied");
                        }
                        return true;
                    }, (property, error) -> warnings.add(property));

            assertTrue(windowing.configure(false, false));
            assertEquals(List.of(DesktopWindowingProperties.Property.values()), attempts);
            assertEquals(List.of(denied), warnings);
        }
    }

    @Test
    public void writesOnlyMissingProperties() {
        for (int mask = 0; mask < 4; mask++) {
            final List<DesktopWindowingProperties.Property> attempts = new ArrayList<>();
            final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                    (property, value) -> {
                        attempts.add(property);
                        assertEquals("false", value);
                        return true;
                    }, (property, error) -> { throw new AssertionError(error); });
            final boolean restrictionsDisabled = (mask & 1) != 0;
            final boolean cornersDisabled = (mask & 2) != 0;

            assertEquals(mask != 3, windowing.configure(restrictionsDisabled, cornersDisabled));
            assertEquals(!restrictionsDisabled, attempts.contains(
                    DesktopWindowingProperties.Property.DEVICE_RESTRICTIONS));
            assertEquals(!cornersDisabled, attempts.contains(
                    DesktopWindowingProperties.Property.ROUNDED_CORNERS));
        }
    }

    @Test
    public void alreadyAppliedWritesDoNotRequireReboot() {
        final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                (property, value) -> false,
                (property, error) -> { throw new AssertionError(error); });
        assertFalse(windowing.configure(false, false));
    }

    @Test
    public void processSecurityDenialsRemainOptional() {
        final List<DesktopWindowingProperties.Property> warnings = new ArrayList<>();
        final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                (property, value) -> { throw new SecurityException("not permitted"); },
                (property, error) -> warnings.add(property));
        assertFalse(windowing.configure(false, false));
        assertEquals(List.of(DesktopWindowingProperties.Property.values()), warnings);
    }

    @Test
    public void restoreContinuesAfterAPropertyDenial() {
        final List<DesktopWindowingProperties.Property> attempts = new ArrayList<>();
        final List<DesktopWindowingProperties.Property> warnings = new ArrayList<>();
        final NubiaWindowingDriver windowing = new NubiaWindowingDriver(
                (property, value) -> {
                    attempts.add(property);
                    assertEquals("", value);
                    throw new IOException("permission denied");
                }, (property, error) -> warnings.add(property));
        windowing.restoreDefaults();
        assertEquals(List.of(DesktopWindowingProperties.Property.values()), attempts);
        assertEquals(attempts, warnings);
    }

    @Test public void vendorCommandPreservesEmptyRestoreAsAnArgument() {
        for (final var property : DesktopWindowingProperties.Property.values()) {
            for (final String value : List.of("false", "true", "")) {
                assertEquals("/system/bin/service call redmagic.app.manager 2 s16 '"
                                + property.key + "' s16 '" + value + "'",
                        NubiaWindowingDriver.propertyWriteCommand(property, value));
            }
        }
    }

    @Test public void productionWritesUseSharedVerificationAndAuthorizedShell() throws Exception {
        final String source = java.nio.file.Files.readString(java.nio.file.Path.of(
                "src/main/java/io/github/mekhontsev/magicdesk/platform/nubia/NubiaWindowingDriver.java"));
        assertTrue(source.contains("DesktopWindowingProperties.write("));
        assertTrue(source.contains("ShellAccess.run(propertyWriteCommand(property, value))"));
        assertFalse(source.contains("ProcessBuilder"));
        assertFalse(source.contains("Runtime.getRuntime()"));
        assertFalse(source.contains("su "));
    }
}
