package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GuestEnvironmentLibraryTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();

    private static final class Images implements GuestEnvironmentLibrary.Images {
        final Map<Path, JSONObject> stores = new HashMap<>();
        final List<List<String>> commands = new ArrayList<>();
        final Map<Path, String> applications = new HashMap<>();
        final Map<String, String> icons = new HashMap<>();
        boolean busy;
        String importer = "1";
        String schema = "1";
        @Override public String invoke(String... args) throws Exception {
            commands.add(List.of(args));
            if (args[0].equals("import-version")) return importer;
            Path path = Path.of(args[1]);
            switch (args[0]) {
                case "applications" -> {
                    String value = applications.getOrDefault(path, "");
                    if (value.equals("unavailable")) throw new IOException("Unreadable environment");
                    return value;
                }
                case "icon" -> {
                    if (args[2].equals("broken")) throw new IOException("Unreadable artwork");
                    return icons.getOrDefault(path + ":" + args[2], "");
                }
                case "recover-staging", "launches" -> { }
                case "prepare" -> {
                    if (busy) throw new IOException("Busy");
                    stores.get(path).put("schemaRevision", schema);
                }
                case "rootfs", "import", "restore" -> {
                    Path target = Path.of(args[2]); Files.createDirectory(target);
                    stores.put(target, new JSONObject().put("kind", args[0].equals("restore") ? "instance" : "image")
                            .put("schemaRevision", schema).put("sources", new JSONArray()));
                }
                case "create" -> {
                    Path target = Path.of(args[2]); Files.createDirectory(target);
                    stores.put(target, new JSONObject().put("kind", "instance").put("sources", new JSONArray()
                            .put(new JSONObject().put("path", path.resolve("objects").toString()))));
                }
                case "inspect" -> {
                    if (!stores.containsKey(path)) throw new IOException("Missing store");
                    return stores.get(path).toString();
                }
                case "sources" -> {
                    if (!stores.containsKey(path)) throw new IOException("Missing store");
                    return stores.get(path).getJSONArray("sources").toString();
                }
                case "remove", "remove-layer" -> {
                    if (busy) throw new IOException("Busy");
                    Files.delete(path); stores.remove(path);
                }
                case "backup" -> { if (busy) throw new IOException("Busy"); Files.writeString(Path.of(args[2]), "backup"); }
                default -> throw new AssertionError(args[0]);
            }
            return "";
        }
    }

    private GuestEnvironmentLibrary library(Path root, Images images) throws Exception {
        return new GuestEnvironmentLibrary(root, images, new GuestOciRegistry(message -> { }), message -> { },
                GuestImageFilesTest::assertDirectorySync);
    }

    @Test public void instancesShareImageButKeepIndependentStablePaths() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Files.writeString(archive, "rootfs input");
        Images images = new Images(); var library = library(root, images);
        var a = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "work");
        var b = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "other");
        assertEquals(a.image(), b.image()); assertNotEquals(a.store(), b.store());
        assertNotEquals(a.id(), a.store().getFileName().toString());
        assertEquals(1, images.commands.stream().filter(c -> c.get(0).equals("rootfs")).count());
        assertEquals(2, library.list().size());
        library.remove("work");
        var c = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "work");
        assertNotEquals(a.store(), c.store());
        assertEquals(b, library.resolve("other"));
    }

    @Test public void schemaUpgradeReusesImageWithoutRetargetingExistingInstances() throws Exception {
        // Exercise canonical library paths even without Windows temporary-directory aliases.
        Path root = temporary.newFolder().toPath().resolve("."), archive = temporary.newFile().toPath();
        Files.writeString(archive, "rootfs input");
        Images images = new Images(); var library = library(root, images);
        Path legacy = Files.createDirectory(root.resolve("images/v16-rootfs-" + GuestImageFiles.digest(archive)));
        var old = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "old");
        images.schema = "2";
        var current = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "current");
        var shared = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "shared");
        assertEquals(old.image(), current.image());
        assertEquals(current.image(), shared.image());
        assertTrue(current.image().startsWith("import-v1-rootfs-"));
        Path base = root.resolve("images").resolve(old.image()).toRealPath();
        assertEquals("2", images.stores.get(base).getString("schemaRevision"));
        assertEquals(old, library.resolve("old"));
        assertTrue(Files.isDirectory(legacy));
        assertTrue(Files.isDirectory(old.store()));
        assertEquals(1, images.commands.stream().filter(c -> c.get(0).equals("rootfs")).count());
        assertFalse(images.commands.stream().anyMatch(c -> c.get(0).startsWith("remove")));
        assertFalse(images.commands.stream().anyMatch(c -> c.contains(legacy.toString())));
    }

    @Test public void environmentIdentityIsIndependentOfSelectedStorage() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var a = library.restore(archive, "work");
        var b = library.restore(archive, "prepared");
        Path path = root.resolve("names/work.json");
        JSONObject record = new JSONObject(Files.readString(path));
        assertEquals(2, record.getInt("format"));
        assertEquals(a.store().getFileName().toString(), record.getString("store"));
        // Exercise the record contract, not a public snapshot/switch operation.
        GuestImageFiles.write(path, record.put("store", b.store().getFileName().toString()).toString(),
                GuestImageFilesTest::assertDirectorySync);
        Files.delete(root.resolve("names/prepared.json"));
        var selected = library.resolve("work");
        assertEquals(a.id(), selected.id());
        assertEquals(a.name(), selected.name());
        assertEquals(b.store(), selected.store());
        assertEquals(a.id(), library.catalog().getJSONObject(0).getString("id"));
        library.prune();
        assertFalse(Files.exists(a.store()));
        assertTrue(Files.isDirectory(b.store()));
        library.remove("work");
        assertFalse(Files.exists(b.store()));
    }

    @Test public void legacyRecordKeepsIdentityAndPathWithoutRewritingOrNativeAdmission() throws Exception {
        // Exercise canonical paths without relying on Windows temporary-directory aliases.
        Path root = temporary.newFolder().toPath().resolve(".");
        Images images = new Images(); var library = library(root, images);
        String id = "3f18c2be-79cb-4dda-92da-2d4d0f8fc7ab";
        Path store = Files.createDirectory(root.resolve("instances").resolve(id));
        Path record = root.resolve("names/old.json");
        String json = "{\"format\":1,\"name\":\"old\",\"id\":\"" + id
                + "\",\"image\":\"\",\"source\":\"archive\"}";
        Files.writeString(record, json);
        var old = library.resolve("old");
        assertEquals(id, old.id()); assertEquals(store.toRealPath(), old.store());
        assertEquals(List.of(old), library.list());
        assertEquals(json, Files.readString(record));
        assertTrue(images.commands.isEmpty());
    }

    @Test public void storageReferenceIsRequiredAndCannotEscapeTheLibrary() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var environment = library.restore(archive, "work");
        Path path = root.resolve("names/work.json");
        JSONObject record = new JSONObject(Files.readString(path));
        images.commands.clear();
        for (String key : List.of("", "..", "../outside", environment.store().toString(),
                "3F18C2BE-79CB-4DDA-92DA-2D4D0F8FC7AB", "1-1-1-1-1")) {
            Files.writeString(path, record.put("store", key).toString());
            assertThrows(IOException.class, () -> library.resolve("work"));
        }
        record.remove("store"); Files.writeString(path, record.toString());
        assertThrows(org.json.JSONException.class, () -> library.resolve("work"));
        record.put("format", 3); Files.writeString(path, record.toString());
        assertThrows(IOException.class, () -> library.resolve("work"));
        assertTrue(images.commands.isEmpty());
        assertTrue(Files.isDirectory(environment.store()));
    }

    private static void references(Images images, Path owner, Path... sources) throws Exception {
        JSONArray values = new JSONArray();
        for (Path source : sources) values.put(new JSONObject().put("path", source.resolve("objects").toString()));
        images.stores.get(owner).put("sources", values);
    }

    @Test public void closedDependentStoresProtectSourcesAndPruneRemovesDependentsFirst() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var base = library.restore(archive, "base");
        var middle = library.restore(archive, "middle");
        var work = library.restore(archive, "work");
        references(images, middle.store(), base.store());
        references(images, work.store(), middle.store());
        assertThrows(IOException.class, () -> library.remove("base"));
        assertThrows(IOException.class, () -> library.remove("middle"));
        Files.delete(root.resolve("names/base.json"));
        Files.delete(root.resolve("names/middle.json"));
        library.prune();
        assertTrue(Files.exists(base.store())); assertTrue(Files.exists(middle.store()));
        Files.delete(root.resolve("names/work.json"));
        images.commands.clear();
        library.prune();
        assertEquals(List.of(work.store().toString(), middle.store().toString(), base.store().toString()),
                images.commands.stream().filter(c -> c.get(0).equals("remove")).map(c -> c.get(1)).toList());
        assertTrue(images.stores.isEmpty());
    }

    @Test public void pruneRejectsUnknownOrCyclicDependenciesBeforeAnyStoreRemoval() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var a = library.restore(archive, "a"); var b = library.restore(archive, "b");
        Files.delete(root.resolve("names/a.json")); Files.delete(root.resolve("names/b.json"));
        JSONObject saved = images.stores.remove(b.store());
        images.commands.clear();
        assertThrows(IOException.class, library::prune);
        assertFalse(images.commands.stream().anyMatch(c -> c.get(0).equals("remove")));
        images.stores.put(b.store(), saved);
        references(images, a.store(), b.store()); references(images, b.store(), a.store());
        images.commands.clear();
        assertThrows(IOException.class, library::prune);
        assertFalse(images.commands.stream().anyMatch(c -> c.get(0).equals("remove")));
        assertTrue(Files.isDirectory(a.store()) && Files.isDirectory(b.store()));
    }

    @Test public void localProjectionReferencesDoNotPreventPruneAndBusyDependentKeepsItsSources() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var base = library.restore(archive, "base"); var work = library.restore(archive, "work");
        references(images, base.store(), base.store());
        references(images, work.store(), work.store(), base.store());
        Files.delete(root.resolve("names/base.json")); Files.delete(root.resolve("names/work.json"));
        images.commands.clear(); images.busy = true;
        assertThrows(IOException.class, library::prune);
        assertEquals(List.of(List.of("remove", work.store().toString())),
                images.commands.stream().filter(c -> c.get(0).equals("remove")).toList());
        assertTrue(Files.isDirectory(base.store()) && Files.isDirectory(work.store()));
        images.busy = false; library.prune();
        assertTrue(images.stores.isEmpty());
    }

    @Test public void removalRefusesAnotherNameSelectingTheSameStore() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var a = library.restore(archive, "a"); library.restore(archive, "b");
        Path record = root.resolve("names/b.json");
        Files.writeString(record, new JSONObject(Files.readString(record))
                .put("store", a.store().getFileName().toString()).toString());
        images.commands.clear();
        assertThrows(IOException.class, () -> library.remove("a"));
        assertEquals(a.store(), library.resolve("b").store());
        assertFalse(images.commands.stream().anyMatch(c -> c.get(0).equals("remove")));
    }

    @Test public void importerChangeAffectsOnlyNewImagesAndBusyUpgradeDoesNotPublishAnInstance() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var old = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "old");
        images.busy = true;
        assertThrows(IOException.class, () -> library.install(archive.toString(),
                GuestEnvironmentLibrary.SourceKind.ROOTFS, "blocked"));
        assertEquals(List.of(old), library.list());
        images.busy = false; images.importer = "2";
        var current = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "new");
        assertNotEquals(old.image(), current.image());
        assertTrue(current.image().startsWith("import-v2-rootfs-"));
        assertEquals(old, library.resolve("old"));
        assertEquals(2, images.commands.stream().filter(c -> c.get(0).equals("rootfs")).count());
    }

    @Test public void invalidNativeImportVersionStopsBeforeImageOrInstanceCreation() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        for (String importer : List.of("", "0", "../1", "1\n2", "99999999999999999999")) {
            images.importer = importer; images.commands.clear();
            assertThrows(IOException.class, () -> library.install(archive.toString(),
                    GuestEnvironmentLibrary.SourceKind.ROOTFS, "work"));
            assertEquals(List.of(List.of("import-version")), images.commands);
            assertTrue(library.list().isEmpty());
        }
    }

    @Test public void opaqueImageIdentityPreservesPathsButRejectsTraversal() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var environment = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "work");
        Path path = root.resolve("names/work.json");
        JSONObject record = new JSONObject(Files.readString(path));
        images.commands.clear();
        for (String key : List.of("future-image-key", "a".repeat(128))) {
            Files.writeString(path, record.put("image", key).toString());
            var resolved = library.resolve("work");
            assertEquals(key, resolved.image());
            assertEquals(environment.id(), resolved.id());
            assertEquals(environment.store(), resolved.store());
        }
        for (String key : List.of("..", "../instances", "/other", "image/other", "image\\other",
                "image\n", "a".repeat(129))) {
            Files.writeString(path, record.put("image", key).toString());
            assertThrows(IOException.class, () -> library.resolve("work"));
        }
        assertTrue(images.commands.isEmpty());
        assertTrue(Files.isDirectory(environment.store()));
    }

    @Test public void resolutionDoesNotBlockNativeUpgradeOrStoppingOlderLaunches() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var environment = library.restore(archive, "work");
        images.stores.remove(environment.store()); // Native inspection is unavailable.
        images.commands.clear();
        assertEquals(environment, library.resolve("work"));
        assertEquals(List.of(environment), library.list());
        assertTrue(images.commands.isEmpty());
        assertEquals(0, library.launches("work").length());
        assertEquals(List.of(List.of("launches", environment.store().toString())), images.commands);
        assertThrows(IOException.class, () -> library.inspect("work"));
        Files.delete(environment.store());
        assertThrows(IOException.class, () -> library.resolve("work"));
        Files.createSymbolicLink(environment.store(), root);
        assertThrows(IOException.class, () -> library.resolve("work"));
    }

    @Test public void failedOrBusyRemovalKeepsNameAndPruneKeepsDependencies() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var environment = library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "work");
        images.busy = true;
        assertThrows(IOException.class, () -> library.remove("work"));
        assertEquals(environment, library.resolve("work"));
        library.prune();
        assertTrue(Files.exists(root.resolve("images").resolve(environment.image())));
        images.busy = false; library.remove("work"); library.prune();
        assertTrue(images.stores.isEmpty());
    }

    @Test public void removalDoesNotInspectTheSelectedStoreOrAdmitOtherSchemas() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var old = library.restore(archive, "old");
        var other = library.restore(archive, "other");
        images.stores.remove(old.store());
        images.commands.clear();
        library.remove("old");
        assertEquals(List.of(List.of("sources", other.store().toString()),
                List.of("remove", old.store().toString())), images.commands);
        assertFalse(Files.exists(old.store()));
        assertEquals(List.of(other), library.list());
    }

    @Test public void restoreHasNoLowerImageAndDuplicateNamesAreRejected() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var restored = library.restore(archive, "saved");
        assertEquals("", restored.image());
        assertThrows(IOException.class, () -> library.restore(archive, "saved"));
        assertEquals(1, library.list().size());
        for (String name : List.of("", "../oops", "-option", "a/b", "a\n", ".", ".."))
            assertThrows(IllegalArgumentException.class, () -> library.resolve(name));
    }

    @Test public void catalogMutationFailsExplicitlyWhenAnotherOwnerHoldsLock() throws Exception {
        Path root = temporary.newFolder().toPath();
        var library = library(root, new Images());
        try (var channel = FileChannel.open(root.resolve("library.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             var ignored = channel.lock()) {
            assertThrows(IOException.class, library::prune);
            assertTrue(library.list().isEmpty());
        }
    }

    @Test public void publicationSyncFailureRetainsTheCommittedName() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        IOException failure = new IOException("directory sync failed");
        var library = new GuestEnvironmentLibrary(root, new Images(), new GuestOciRegistry(message -> { }),
                message -> { }, directory -> { throw failure; });
        assertSame(failure, assertThrows(IOException.class,
                () -> library.install(archive.toString(), GuestEnvironmentLibrary.SourceKind.ROOTFS, "work")));
        assertEquals("work", library.resolve("work").name());
        assertEquals(1, library.list().size());
    }

    @Test public void namedLaunchRetainsArgumentsInOriginalShell() {
        String script = GuestRuntimeCommand.BODY;
        assertTrue(script.contains("md_store=$(md_library resolve \"${1-}\")"));
        assertTrue(script.contains("exec \"$md_guest/libmagicdesk_guest_image.so\" \"$md_action\" \"$md_store\" \"$@\""));
        assertFalse(script.contains("eval "));
        assertFalse(script.contains("exec /system/bin/app_process"));
    }

    private static String desktop(String path, String icon, boolean hidden) throws Exception {
        return new JSONObject().put("path", path).put("text", "[Desktop Entry]\nType=Application\nName=Test\nExec=test\nIcon="
                + icon + "\nHidden=" + hidden + "\n").toString() + "\n";
    }

    @Test public void metadataDoesNotFetchArtworkAndIconsResolveOnlyRequestedImmutableOwners() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var a = library.restore(archive, "first"); var b = library.restore(archive, "second");
        images.applications.put(a.store(), desktop("/usr/share/applications/editor.desktop", "editor", false));
        images.applications.put(b.store(), desktop("/usr/share/applications/editor.desktop", "editor", false));
        images.icons.put(a.store() + ":editor", "aa"); images.icons.put(b.store() + ":editor", "bb");
        assertEquals(2, library.applications().length());
        assertFalse(images.commands.stream().anyMatch(c -> c.get(0).equals("icon")));
        images.commands.clear();
        String key = "guest:" + a.id() + ":editor.desktop";
        assertEquals("aa", library.icons(List.of(key)).getJSONObject(0).getString("png"));
        assertFalse(images.commands.stream().anyMatch(c -> c.contains(b.store().toString())));
        library.remove("first"); library.restore(archive, "first");
        assertFalse(library.icons(List.of(key)).getJSONObject(0).has("png"));
        assertThrows(IllegalArgumentException.class, () -> library.icons(List.of("guest:../bad:file.desktop")));
        assertThrows(IllegalArgumentException.class, () -> library.icons(java.util.Collections.nCopies(5, key)));
    }

    @Test public void hiddenEntriesMaskLowerArtworkAndOneFailureDoesNotDiscardOtherIcons() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var a = library.restore(archive, "first");
        images.applications.put(a.store(), desktop("/root/.local/share/applications/hidden.desktop", "editor", true)
                + desktop("/usr/share/applications/hidden.desktop", "editor", false)
                + desktop("/usr/share/applications/bad.desktop", "broken", false)
                + desktop("/usr/share/applications/good.desktop", "editor", false)
                + desktop("/usr/share/applications/also.desktop", "editor", false));
        images.icons.put(a.store() + ":editor", "aabb");
        images.commands.clear();
        String prefix = "guest:" + a.id() + ":";
        var result = library.icons(List.of(prefix + "hidden.desktop", prefix + "bad.desktop", prefix + "good.desktop", prefix + "also.desktop"));
        assertFalse(result.getJSONObject(0).has("png"));
        assertTrue(result.getJSONObject(1).has("error"));
        assertEquals("aabb", result.getJSONObject(2).getString("png"));
        assertEquals("aabb", result.getJSONObject(3).getString("png"));
        assertEquals(1, images.commands.stream().filter(c -> c.get(0).equals("applications")).count());
        assertEquals(1, images.commands.stream().filter(c -> c.contains("editor")).count());
    }

    @Test public void unavailableEnvironmentDoesNotHideHealthyApplicationsOrArtwork() throws Exception {
        Path root = temporary.newFolder().toPath(), archive = temporary.newFile().toPath();
        Images images = new Images(); var library = library(root, images);
        var bad = library.restore(archive, "bad"); var good = library.restore(archive, "good");
        images.applications.put(bad.store(), "unavailable");
        images.applications.put(good.store(), desktop("/usr/share/applications/editor.desktop", "editor", false));
        images.icons.put(good.store() + ":editor", "abcd");
        var records = library.applications();
        assertEquals(2, records.length());
        var byOwner = new HashMap<String, JSONObject>();
        for (int i = 0; i < records.length(); ++i) {
            var record = records.getJSONObject(i);
            byOwner.put(record.getJSONObject("environment").getString("id"), record);
        }
        assertTrue(byOwner.get(bad.id()).getString("error").contains("Unreadable environment"));
        var healthy = byOwner.get(good.id());
        assertFalse(healthy.has("error"));
        assertEquals(good.store().toString(), healthy.getJSONObject("environment").getString("store"));
        assertEquals("/usr/share/applications/editor.desktop", healthy.getString("path"));
        assertTrue(healthy.getString("text").contains("Icon=editor"));
        var icons = library.icons(List.of("guest:" + bad.id() + ":editor.desktop", "guest:" + good.id() + ":editor.desktop"));
        assertTrue(icons.getJSONObject(0).has("error"));
        assertEquals("abcd", icons.getJSONObject(1).getString("png"));
    }
}
