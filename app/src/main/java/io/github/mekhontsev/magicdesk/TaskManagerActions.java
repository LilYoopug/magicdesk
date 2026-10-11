package io.github.mekhontsev.magicdesk;

import android.app.Activity;
import android.view.View;
import android.widget.PopupMenu;
import android.widget.Toast;
import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

/** UI actions use each resource owner's existing lifecycle, never package-wide substitutes. */
final class TaskManagerActions {
    private enum WindowAction { OPEN, CLOSE, FORCE_STOP }
    private final Activity activity;
    private final Runnable refresh;
    private final Consumer<TaskManagerApplications.Entry> processes;
    TaskManagerActions(Activity activity, Runnable refresh, Consumer<TaskManagerApplications.Entry> processes) {
        this.activity = activity; this.refresh = refresh; this.processes = processes;
    }

    void open(TaskManagerApplications.Entry entry) {
        if (!entry.windows().isEmpty()) { chooseWindow(entry, WindowAction.OPEN); return; }
        try {
            final var target = ToolLaunchTarget.resolve("auto", activity.getDisplay().getDisplayId(),
                    DesktopRuntimeBridge.workspaceDisplayIds());
            if (entry.target() instanceof TaskManagerApplications.Terminal terminal) {
                final var live = ConsoleTerminalRegistry.status(terminal.session().id);
                if (live == null) throw new IOException("Terminal session has ended");
                TerminalSessions.open(activity, CommandConsoleActivity.attachIntent(activity, live), target, null, this::result);
            } else if (entry.target() instanceof TaskManagerApplications.Tmux tmux) {
                TmuxSessionProvider.list(activity, (snapshot, error) -> activity.runOnUiThread(() -> {
                    if (activity.isDestroyed() || activity.isFinishing()) return;
                    final var live = snapshot == null ? null : snapshot.find(tmux.session().id);
                    if (error != null || live == null || live.createdSeconds != tmux.session().createdSeconds) {
                        result(error != null ? error : new IOException("tmux session has ended")); return;
                    }
                    TerminalSessions.open(activity, TerminalSessions.tmuxIntent(activity, live, snapshot), target, null, this::result);
                }));
            } else if (entry.target() instanceof TaskManagerApplications.Graphics graphics) openGraphics(graphics.sessionId());
        } catch (IOException | RuntimeException error) { result(error); }
    }

    void menu(View anchor, TaskManagerApplications.Entry entry) {
        final PopupMenu menu = new PopupMenu(activity, anchor);
        add(menu, R.string.task_manager_focus, () -> open(entry));
        if (!entry.windows().isEmpty()) add(menu, R.string.task_manager_close, () -> chooseWindow(entry, WindowAction.CLOSE));
        if (entry.target() instanceof TaskManagerApplications.Graphics
                && !windows(entry, WindowAction.FORCE_STOP).isEmpty())
            add(menu, R.string.task_manager_force_stop, () -> chooseWindow(entry, WindowAction.FORCE_STOP));
        if (!entry.processes().isEmpty()) add(menu, R.string.task_manager_processes, () -> processes.accept(entry));
        if (entry.target() instanceof TaskManagerApplications.AndroidApp app) {
            add(menu, R.string.task_manager_logs, () -> BuiltInWindowLauncher.launch(activity,
                    AppLogViewerActivity.createIntent(activity, app.task().packageName, entry.title()),
                    AppLogViewerActivity.launchTarget(), this::result));
            if (!activity.getPackageName().equals(app.task().packageName))
                add(menu, R.string.task_manager_force_stop, () -> confirm(R.string.task_manager_force_stop,
                        activity.getString(R.string.task_manager_force_stop_message, entry.title()),
                        () -> MagicDeskRuntime.forceStopApplication(AppProfile.current(activity).application(app.task()),
                                this::taskResult)));
        } else if (entry.target() instanceof TaskManagerApplications.Terminal terminal
                && !terminal.session().tmuxSessionId.isEmpty()) {
            add(menu, R.string.terminal_detach, () -> confirm(R.string.terminal_detach,
                    activity.getString(R.string.terminal_detach_tmux_confirm), () -> end(entry)));
        } else {
            add(menu, R.string.terminal_end_session, () -> confirm(R.string.terminal_end_session,
                    activity.getString(R.string.task_manager_end_session_confirm, entry.title()), () -> end(entry)));
        }
        menu.show();
    }

    private void end(TaskManagerApplications.Entry entry) {
        try {
            if (entry.target() instanceof TaskManagerApplications.Terminal terminal)
                ConsoleTerminalRegistry.close(terminal.session().id);
            else if (entry.target() instanceof TaskManagerApplications.Tmux tmux) {
                TmuxSessionProvider.end(activity, tmux.session(), this::result); return;
            } else if (entry.target() instanceof TaskManagerApplications.Graphics graphics) {
                final var session = GraphicalSessions.find(graphics.sessionId());
                if (session != null && !session.stopped()) session.close();
            }
            refresh.run();
        } catch (RuntimeException error) { result(error); }
    }

    static GraphicalSessions.Session requireGraphics(String id) {
        final var session = GraphicalSessions.find(id);
        if (session == null || session.stopped()) throw new IllegalStateException("Graphical session has ended");
        if (!session.ready()) throw new IllegalStateException("Graphical session is not ready");
        return session;
    }

    static List<GraphicalSessions.Window> applicationWindows(GraphicalSessions.Session session) {
        return session.windows().stream().filter(GraphicalSessions.Window::mapped).toList();
    }

    private void openGraphics(String id) {
        final var session = requireGraphics(id);
        if (!session.application() && session.desktop()) { openGraphicsWindow(id, 0); return; }
        final var windows = applicationWindows(session);
        if (windows.isEmpty()) throw new IllegalStateException("Graphical session has no mapped application windows");
        if (windows.size() == 1) { openGraphicsWindow(id, windows.get(0).id()); return; }
        final String[] labels = windows.stream().map(window -> window.title().isBlank()
                ? session.protocol() + " " + Long.toUnsignedString(window.id()) : window.title()).toArray(String[]::new);
        UiDialogs.builder(activity).setTitle(R.string.graphics_windows)
                .setItems(labels, (dialog, which) -> openGraphicsWindow(id, windows.get(which).id()))
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    private void openGraphicsWindow(String id, long window) {
        try {
            final var session = requireGraphics(id);
            if (window != 0 && applicationWindows(session).stream().noneMatch(item -> item.id() == window))
                throw new IllegalStateException("Graphical window has closed");
            ToolApplications.openSibling(activity, session.windowIntent(activity, window), this::result);
        } catch (RuntimeException error) { result(error); }
    }

    private void chooseWindow(TaskManagerApplications.Entry entry, WindowAction action) {
        final var windows = windows(entry, action);
        if (windows.isEmpty()) { result(new IOException("No available windows")); return; }
        if (windows.size() == 1) { window(windows.get(0), action); return; }
        final String[] names = windows.stream().map(t -> TaskTitle.resolve(activity, null, t)
                + " [" + t.displayId + "] #" + t.taskId).toArray(String[]::new);
        UiDialogs.builder(activity).setTitle(switch (action) {
                    case OPEN -> R.string.task_manager_focus;
                    case CLOSE -> R.string.task_manager_close;
                    case FORCE_STOP -> R.string.task_manager_force_stop;
                })
                .setItems(names, (d, i) -> window(windows.get(i), action))
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    private static List<TaskRepository.TaskEntry> windows(TaskManagerApplications.Entry entry, WindowAction action) {
        return action == WindowAction.FORCE_STOP ? entry.windows().stream()
                .filter(task -> BuiltInWindowRegistry.forceCloseAction(task) != null).toList() : entry.windows();
    }

    private void window(TaskRepository.TaskEntry task, WindowAction action) {
        if (action == WindowAction.CLOSE) { MagicDeskRuntime.closeTask(task, this::taskResult); return; }
        if (action == WindowAction.FORCE_STOP) {
            final var hosted = BuiltInWindowRegistry.forceCloseAction(task);
            if (hosted == null) { result(new IOException("Hosted window has closed")); return; }
            confirm(hosted.label(), hosted.warning(),
                    () -> MagicDeskRuntime.forceStopTaskApplication(task, this::taskResult));
            return;
        }
        TaskCommandQueue.execute(() -> {
            try {
                final var live = ApplicationTaskPlacement.requireLive(task);
                if (ApplicationTaskPlacement.isManaged(live))
                    MagicDeskRuntime.focusDesktopTask(live.displayId, live.taskId, this::taskResult);
                else ApplicationTaskPlacement.controlIndependent(live, null, false, this::taskResult);
            } catch (IOException | RuntimeException error) { result(error); }
        });
    }

    void processMenu(View anchor, SystemProcessSnapshot process) {
        final PopupMenu menu = new PopupMenu(activity, anchor);
        add(menu, R.string.task_manager_process_details, () -> UiDialogs.builder(activity)
                .setTitle(process.name).setMessage("PID: " + process.pid + "\nPPID: " + process.parentPid
                        + "\nUID: " + process.uid + "\nState: " + process.state + "\nStart ticks: " + process.startTicks)
                .setPositiveButton(android.R.string.ok, null).show());
        if (ProcessControl.allowed(activity, process)) {
            add(menu, R.string.task_manager_end_process, () -> signal(process, false));
            add(menu, R.string.task_manager_kill_process, () -> signal(process, true));
        }
        menu.show();
    }

    private void signal(SystemProcessSnapshot process, boolean force) {
        confirm(force ? R.string.task_manager_kill_process : R.string.task_manager_end_process,
                activity.getString(R.string.task_manager_signal_confirm, process.name, process.pid),
                () -> ProcessControl.signal(activity, process, force, this::result));
    }
    private void confirm(int title, String message, Runnable action) {
        UiDialogs.builder(activity).setTitle(title).setMessage(message)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(title, (d, which) -> action.run()).show();
    }
    private void add(PopupMenu menu, int title, Runnable action) {
        menu.getMenu().add(title).setOnMenuItemClickListener(item -> { action.run(); return true; });
    }
    private void taskResult(TaskRepository.ActionResult result) {
        result(result.success ? null : new IOException(result.message));
    }
    private void result(Throwable error) {
        activity.runOnUiThread(() -> {
            if (activity.isDestroyed() || activity.isFinishing()) return;
            if (error != null) Toast.makeText(activity, ShellAccess.usefulMessage(error), Toast.LENGTH_LONG).show();
            refresh.run();
        });
    }
}
