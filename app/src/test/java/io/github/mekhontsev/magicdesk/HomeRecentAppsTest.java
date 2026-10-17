package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class HomeRecentAppsTest {
    private static final String PREVIOUS_HOME = "com.example.launcher";

    @Test
    public void selectsPhoneTasksRegardlessOfLaunchSource() {
        final List<AppItem> apps = Arrays.asList(app("com.example.phone"),
                app("com.example.notification"), app("com.example.external"));
        assertEquals(Arrays.asList(app("com.example.phone").reference, app("com.example.notification").reference),
                selectReferences(Arrays.asList(
                        task(1, 1, 0, "com.example.phone", "fullscreen", false),
                        task(2, 2, 0, "com.example.notification", "fullscreen", false),
                        task(3, 3, 4, "com.example.external", "fullscreen", false)),
                        apps, PREVIOUS_HOME, 0));
    }

    @Test
    public void excludesHomeAndNonLaunchableTasks() {
        final List<AppItem> apps = Arrays.asList(app("com.example.home"),
                app(PREVIOUS_HOME));
        assertTrue(selectReferences(Arrays.asList(
                task(1, 1, 0, "com.example.home", "fullscreen", true),
                task(2, 2, 0, PREVIOUS_HOME, "fullscreen", false),
                task(4, 4, 0, "com.example.unlisted", "fullscreen", false),
                null), apps, PREVIOUS_HOME, 0).isEmpty());
    }

    @Test
    public void phoneApplicationModeDoesNotMakeItAnExternalTask() {
        assertEquals(Collections.singletonList(app("com.example.floating").reference),
                selectReferences(Collections.singletonList(
                        task(1, 1, 0, "com.example.floating", "freeform", false)),
                        Collections.singletonList(app("com.example.floating")), PREVIOUS_HOME, 0));
    }

    @Test
    public void keepsTopRootEntryAndDeduplicatesApplicationsInSnapshotOrder() {
        final List<AppItem> apps = Arrays.asList(app("com.example.first"),
                app("com.example.second"), app("com.example.child"));
        assertEquals(Arrays.asList(app("com.example.second").reference, app("com.example.first").reference),
                selectReferences(Arrays.asList(
                        task(2, 2, 0, "com.example.second", "fullscreen", false),
                        task(1, 1, 0, "com.example.first", "fullscreen", false),
                        task(1, 5, 0, "com.example.child", "fullscreen", false),
                        task(3, 3, 0, "com.example.second", "fullscreen", false)),
                        apps, PREVIOUS_HOME, 0));
    }

    @Test
    public void externalInstanceOfSameApplicationDoesNotMakeItPhoneRecent() {
        final AppItem app = app("com.example.shared");
        assertTrue(selectReferences(Collections.singletonList(
                task(1, 1, 4, app.packageName, "freeform", false)),
                Collections.singletonList(app), PREVIOUS_HOME, 0).isEmpty());
        assertEquals(Collections.singletonList(app.reference),
                selectReferences(Arrays.asList(
                        task(1, 1, 4, app.packageName, "freeform", false),
                        task(2, 2, 0, app.packageName, "fullscreen", false)),
                        Collections.singletonList(app), PREVIOUS_HOME, 0));
    }

    @Test
    public void keepsDistinctBuiltInPhoneAppsButNotDesktopShellSurfaces() {
        final AppItem files = app(BuiltInDesktopAppCatalog.filesTarget());
        final AppItem settings = app(BuiltInDesktopAppCatalog.settingsTarget());
        final List<AppReference> selected = selectReferences(Arrays.asList(
                task(1, files.launchTarget), task(2, settings.launchTarget),
                task(3, 3, 0, BuildConfig.APPLICATION_ID, "fullscreen", true),
                task(4, 4, 0, BuildConfig.APPLICATION_ID, "multi-window", false)),
                Arrays.asList(files, settings), PREVIOUS_HOME, 0);
        assertEquals(Arrays.asList(
                files.reference,
                settings.reference), selected);
    }

    @Test
    public void emptyPhoneSnapshotDoesNotFallBackToApplicationCatalog() {
        assertTrue(selectReferences(Collections.emptyList(),
                Collections.singletonList(app("com.example.app")), PREVIOUS_HOME, 0).isEmpty());
    }

    @Test public void unassignedSecondaryHomeUsesOnlyItsLocalTasks() {
        final AppItem app = app("com.example.shared");
        assertEquals(List.of(app.reference), selectReferences(List.of(
                task(1, 1, 7, app.packageName, "fullscreen", false),
                task(2, 2, 0, "com.example.phone", "fullscreen", false)),
                List.of(app, app("com.example.phone")), PREVIOUS_HOME, 7));
    }

    @Test public void runningConsoleDoesNotRequireAnApplicationCatalogEntry() {
        final var console = task(20, BuiltInDesktopAppCatalog.consoleTarget());
        final var settings = task(21, BuiltInDesktopAppCatalog.settingsTarget());
        final var selected = HomeRecentApps.select(List.of(console, settings), List.of(),
                PREVIOUS_HOME, 0, new AppProfile(0, 0));
        assertEquals(List.of(console, settings), selected.stream().map(HomeRecentApps.Entry::task).toList());
        assertEquals(BuiltInDesktopAppCatalog.consoleTarget(), selected.get(0).reference().launchTarget());
    }

    @Test public void runningSelectionRetainsTheMostRecentExactTask() {
        final var console = task(20, BuiltInDesktopAppCatalog.consoleTarget());
        final var older = task(19, BuiltInDesktopAppCatalog.consoleTarget());
        final var selected = HomeRecentApps.select(List.of(console, older), List.of(),
                PREVIOUS_HOME, 0, new AppProfile(0, 0));
        assertEquals(1, selected.size());
        assertEquals(console, selected.get(0).task());
    }

    @Test public void missingCatalogNeverAdmitsAnotherProfilesToolsOrShellInfrastructure() {
        final var console = task(20, BuiltInDesktopAppCatalog.consoleTarget());
        final var shell = task(21, 21, 0, BuildConfig.APPLICATION_ID, "fullscreen", false);
        assertTrue(HomeRecentApps.select(List.of(console, shell), List.of(),
                PREVIOUS_HOME, 0, new AppProfile(10, 10)).isEmpty());
        assertTrue(HomeRecentApps.select(List.of(shell), List.of(),
                PREVIOUS_HOME, 0, new AppProfile(0, 0)).isEmpty());
    }

    private static List<AppReference> selectReferences(List<TaskRepository.TaskEntry> tasks,
            List<AppItem> apps, String previousHome, int display) {
        return HomeRecentApps.select(tasks, apps, previousHome, display, new AppProfile(0, 0))
                .stream().map(HomeRecentApps.Entry::reference).toList();
    }

    private static AppItem app(final String packageName) {
        return app(AppLaunchTarget.packageDefault(packageName));
    }

    private static AppItem app(final AppLaunchTarget target) {
        return new AppItem(new AppProfile(0, 0), target.packageName, target.packageName, false,
                AppItem.FULLSCREEN_REASON_NONE, null, target);
    }

    private static TaskRepository.TaskEntry task(final int id, final AppLaunchTarget target) {
        final String component = target.packageName + "/" + target.activityClassName;
        return new TaskRepository.TaskEntry(id, id, 0, target.packageName,
                component, component, "fullscreen", null, -1, -1, false, true, false, 0);
    }

    private static TaskRepository.TaskEntry task(final int root, final int id,
            final int display, final String packageName, final String mode, final boolean home) {
        return new TaskRepository.TaskEntry(root, id, display, packageName,
                packageName + "/.MainActivity", packageName + "/.MainActivity",
                mode, null, -1, -1, home, true, false, 0);
    }
}
