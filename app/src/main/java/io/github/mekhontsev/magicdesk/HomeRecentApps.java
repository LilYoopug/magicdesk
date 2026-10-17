package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

/** Ordinary HOME recents come from local tasks, not desktop launch history. */
final class HomeRecentApps {
    record Entry(AppReference reference, TaskRepository.TaskEntry task) { }

    private HomeRecentApps() {
    }

    static List<Entry> select(
            final List<TaskRepository.TaskEntry> tasks,
            final List<AppItem> apps,
            final String previousHomePackage, final int displayId, final AppProfile profile) {
        final var entries = new LinkedHashMap<AppReference, Entry>();
        final Set<Integer> roots = new HashSet<>();
        for (final TaskRepository.TaskEntry task : tasks) {
            if (task == null
                    || task.displayId != displayId
                    || task.taskId < 0
                    || task.rootTaskId < 0
                    || !profile.owns(task.userId)
                    || task.home
                    || !PackageNameValidator.isSafe(task.packageName)
                    || task.packageName.equals(previousHomePackage)
                    || !roots.add(task.rootTaskId)) {
                continue;
            }
            // Running tools need not have a launcher entry. Keep their exact task
            // so activating a retained console cannot launch another PTY.
            final var builtIn = BuiltInDesktopAppCatalog.find(task);
            if (builtIn != null) {
                final var reference = AppReference.forTarget(profile.application(task), builtIn.launchTarget);
                entries.putIfAbsent(reference, new Entry(reference, task));
                continue;
            }
            for (final AppItem app : apps) {
                if (app.matchesTask(task) && app.reference != null) {
                    entries.putIfAbsent(app.reference, new Entry(app.reference, task));
                    break;
                }
            }
        }
        return new ArrayList<>(entries.values());
    }
}
