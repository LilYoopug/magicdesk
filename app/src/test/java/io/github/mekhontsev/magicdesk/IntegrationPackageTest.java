package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.Test;

public final class IntegrationPackageTest {
    @Test
    public void defaultPackagesAreVisibleBeforePrivilegeStartup() throws Exception {
        final var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        final var manifest = factory.newDocumentBuilder().parse(Path.of("src/main/AndroidManifest.xml").toFile());
        final var queries = (org.w3c.dom.Element) manifest.getElementsByTagName("queries").item(0);
        final var packages = queries.getElementsByTagName("package");
        final var visible = new HashSet<String>();
        for (int i = 0; i < packages.getLength(); i++) {
            visible.add(((org.w3c.dom.Element) packages.item(i))
                    .getAttributeNS("http://schemas.android.com/apk/res/android", "name"));
        }
        for (final var integration : IntegrationPackage.values()) {
            assertTrue(visible.containsAll(List.of(integration.defaultPackages.split(";"))));
        }
    }

    @Test
    public void defaultsSelectInstalledManagersWithoutChangingSavedLists() {
        assertEquals("com.hamondev.shevery;moe.shizuku.privileged.api", IntegrationPackage.SHIZUKU.defaultPackages);
        final var values = IntegrationPackage.snapshot(Map.of(),
                Set.of("com.termux", "moe.shizuku.privileged.api")::contains);
        assertEquals("com.termux", values.get(IntegrationPackage.TERMUX));
        assertEquals("moe.shizuku.privileged.api", values.get(IntegrationPackage.SHIZUKU));
        assertEquals("com.hamondev.shevery", IntegrationPackage.snapshot(Map.of(), name -> true)
                .get(IntegrationPackage.SHIZUKU));
    }

    @Test
    public void arbitraryPackagesAreFrozenForTheProcessWithoutAForkCatalog() {
        final var configured = new HashMap<>(Map.of(
                IntegrationPackage.TERMUX, "example.compat.terminal",
                IntegrationPackage.SHIZUKU, "example.compat.manager"));
        final var active = IntegrationPackage.snapshot(configured, name -> true);
        configured.put(IntegrationPackage.TERMUX, "other.terminal");
        assertEquals("example.compat.terminal", active.get(IntegrationPackage.TERMUX));
        assertEquals("example.compat.manager", active.get(IntegrationPackage.SHIZUKU));
        assertEquals("other.terminal", IntegrationPackage.snapshot(configured, name -> true).get(IntegrationPackage.TERMUX));
        assertThrows(UnsupportedOperationException.class,
                () -> active.put(IntegrationPackage.TERMUX, "other.terminal"));
    }

    @Test
    public void packageListSelectsFirstInstalledAndStopsSearching() {
        var checked = new ArrayList<String>();
        assertEquals("second.manager", IntegrationPackage.select(
                " first.manager ; second.manager ; third.manager ", name -> {
                    checked.add(name);
                    return !name.equals("first.manager");
                }));
        assertEquals(List.of("first.manager", "second.manager"), checked);
        assertEquals("first.manager", IntegrationPackage.select("first.manager;second.manager", name -> true));
    }

    @Test
    public void missingCandidatesRetainExplicitDestinationForUnavailableDiagnostics() {
        assertEquals("first.manager", IntegrationPackage.select("first.manager;second.manager", name -> false));
        assertEquals("com.termux", IntegrationPackage.snapshot(Map.of(), name -> false).get(IntegrationPackage.TERMUX));
    }

    @Test
    public void packageListIsNormalizedWithoutStoringItsResolvedChoice() {
        assertEquals("first.manager;second.manager", IntegrationPackage.normalize(" ; first.manager ; ; second.manager; "));
        var configured = Map.of(IntegrationPackage.SHIZUKU, "first.manager;second.manager");
        var installed = new HashSet<>(Set.of("second.manager"));
        var active = IntegrationPackage.snapshot(configured, installed::contains);
        installed.add("first.manager");
        assertEquals("second.manager", active.get(IntegrationPackage.SHIZUKU));
        assertEquals("first.manager;second.manager", configured.get(IntegrationPackage.SHIZUKU));
        assertEquals("first.manager", IntegrationPackage.snapshot(configured, installed::contains).get(IntegrationPackage.SHIZUKU));
    }

    @Test
    public void packageInputRejectsIntentsPathsAndEmptyValues() {
        assertEquals("org.example.Terminal_2", IntegrationPackage.normalize(" org.example.Terminal_2 "));
        for (final String value : new String[]{"", "; ;", "com", "com..termux", "com.2termux", "com.termux/.Main",
                "com.termux;id", "com.termux\nother.app", "com." + "a".repeat(256), "com.example;".repeat(200)}) {
            assertThrows(value, IllegalArgumentException.class, () -> IntegrationPackage.normalize(value));
        }
        assertThrows(IllegalArgumentException.class, () -> IntegrationPackage.select("com.termux;id", name -> true));
    }

    @Test
    public void incompatibleSavedPackageIsNotSilentlyReplacedByOriginal() {
        assertThrows(IllegalArgumentException.class, () -> IntegrationPackage.snapshot(
                Map.of(IntegrationPackage.TERMUX, "not a package"), name -> true));
    }

    @Test
    public void serviceCompatibilityDoesNotDependOnJavaClassOrApplicationName() {
        assertEquals("", TermuxIntegration.serviceError(true, true, TermuxIntegration.RUN_COMMAND_PERMISSION));
        assertEquals("", TermuxIntegration.serviceError(true, true, null));
        assertTrue(TermuxIntegration.serviceError(true, true, "example.permission.COMMAND")
                .contains("Unsupported RUN_COMMAND permission"));
        assertTrue(!TermuxIntegration.serviceError(false, true, null).isEmpty());
        assertTrue(!TermuxIntegration.serviceError(true, false, null).isEmpty());
    }
}
