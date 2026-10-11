package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class ApplicationEntryLauncherTest {
    @Test public void independentCallerSurvivesUntilWindowHandoffAndReceivesAsyncFailure() throws Exception {
        RuntimeSourceFixture.verify("""
                interface BooleanSupplier extends java.util.function.BooleanSupplier { }
                interface Consumer<T> extends java.util.function.Consumer<T> { }
                static class Context { }
                static class DesktopLaunchRequest { }
                static class ToolLaunchTarget {
                    int displayId = 7; boolean desktop;
                    void requireCurrent(Set<Integer> s) { }
                }
                static class DesktopRuntimeBridge {
                    static Set<Integer> workspaceDisplayIds() { return Set.of(); }
                    static boolean launchAutomationRequest(DesktopLaunchRequest r, int d) { return true; }
                }
                static class InteractiveActivityLaunch {
                    static void requireDestination(Context c, int d, String u) throws IOException { }
                }
                static class Queue { void post(Runnable r) { r.run(); } }
                static final Queue MAIN = new Queue();
                static class TaskCommandQueue { static void execute(Runnable r) { r.run(); } }
                static class StandaloneDesktopLaunchContext {
                    StandaloneDesktopLaunchContext(Context c, int d, String id) { }
                }
                static class Result {
                    String error;
                    Result(String error) { this.error = error; }
                    boolean succeeded() { return error == null; }
                }
                static class DesktopLaunchCoordinator {
                    static java.util.function.Consumer<Result> completion;
                    DesktopLaunchCoordinator(StandaloneDesktopLaunchContext c) { }
                    boolean launch(DesktopLaunchRequest r, java.util.function.Consumer<Result> done) {
                        completion = done; return true;
                    }
                }
                public static void verify() {
                    var events = new ArrayList<Throwable>();
                    boolean[] alive = {true};
                    launch(new Context(), new DesktopLaunchRequest(), new ToolLaunchTarget(), "display-7",
                            () -> alive[0], events::add);
                    check(events.isEmpty(), "acceptance closed the caller before asynchronous handoff");
                    DesktopLaunchCoordinator.completion.accept(new Result(null));
                    check(events.size() == 1 && events.get(0) == null, "window completion lost");
                    events.clear();
                    launch(new Context(), new DesktopLaunchRequest(), new ToolLaunchTarget(), "display-7",
                            () -> alive[0], events::add);
                    DesktopLaunchCoordinator.completion.accept(new Result("client exited"));
                    check(events.size() == 1 && events.get(0).getMessage().equals("client exited"), "failure lost");
                    events.clear();
                    launch(new Context(), new DesktopLaunchRequest(), new ToolLaunchTarget(), "display-7",
                            () -> alive[0], events::add);
                    alive[0] = false;
                    DesktopLaunchCoordinator.completion.accept(new Result(null));
                    check(events.isEmpty(), "closed caller received a late completion");
                }
                """ + RuntimeSourceFixture.methods("ApplicationEntryLauncher", "launch"));
    }
}
