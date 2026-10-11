package io.github.mekhontsev.magicdesk;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;
import static org.junit.Assert.*;

public final class TaskManagerGraphicsTest {
    @Test public void bothProtocolsJoinHostsAndOnlyTheirServerProcesses() throws Exception {
        verify("""
                var x = session("x11-one", "X11", false);
                var w = session("wayland-one", "Wayland", true);
                x.hosts.add(new Host(10)); x.hosts.add(new Host(11)); w.hosts.add(new Host(20));
                var a = new TaskRepository.TaskEntry(10); var b = new TaskRepository.TaskEntry(11);
                var c = new TaskRepository.TaskEntry(20); var unrelated = new TaskRepository.TaskEntry(30);
                var xs = new SystemProcessSnapshot(1, 10001, x.id);
                var ws = new SystemProcessSnapshot(2, 10001, w.id);
                var processes = new ProcessCatalog(List.of(xs, ws,
                        new SystemProcessSnapshot(3, 2000, w.id),
                        new SystemProcessSnapshot(4, 10001, "linux-client")));
                var rows = graphics(List.of(x,w), List.of(a,b,c,unrelated), processes, "server only");
                check(rows.size()==2, "missing protocol");
                check(rows.get(0).windows().equals(List.of(a,b)), "X11 hosts");
                check(rows.get(1).windows().equals(List.of(c)), "Wayland hosts");
                check(rows.get(0).processes().equals(Set.of(xs.identity())), "X11 process ownership");
                check(rows.get(1).processes().equals(Set.of(ws.identity())), "Wayland process ownership");
                check(rows.get(1).detail().equals("Wayland | ready | server only"), "resource scope label");
                check(((Graphics)rows.get(1).target()).sessionId().equals(w.id), "target is not stable session ID");
                """);
    }

    @Test public void windowlessAndStartingSessionsRemainButStoppedSessionsDoNot() throws Exception {
        verify("""
                var live=session("live", "Wayland", true);
                var starting=session("starting", "X11", false); starting.ready=false;
                var stopped=session("stopped", "Wayland", true); stopped.stopped=true;
                var rows=graphics(List.of(live,starting,stopped), List.of(), new ProcessCatalog(List.of()), "server");
                check(rows.size()==2 && rows.get(0).windows().isEmpty(), "lost retained session");
                check(rows.get(1).detail().contains("starting"), "startup state lost");
                check(rows.get(0).processes().isEmpty(), "invented resource ownership");
                """);
    }

    @Test public void openingUsesDesktopModeOrMappedClientsAndRevalidatesSelection() throws Exception {
        verify("""
                Fixture f=new Fixture();
                var desktop=session("desktop", "X11", false);
                f.openGraphics(desktop.id);
                check(ToolApplications.opened.equals(List.of("desktop:0")), "whole desktop not reopened");
                var app=session("app", "Wayland", true);
                app.windows.add(new GraphicalSessions.Window(1,"hidden",false));
                app.windows.add(new GraphicalSessions.Window(2,"client",true));
                f.openGraphics(app.id);
                check(ToolApplications.opened.get(1).equals("app:2"), "mapped client not reopened");
                app.windows.add(new GraphicalSessions.Window(3,"second",true));
                f.openGraphics(app.id);
                check(UiDialogs.labels.equals(List.of("client","second")), "wrong client selection");
                app.windows.remove(2); UiDialogs.choice.accept(null,1);
                check(f.error!=null && ToolApplications.opened.size()==2, "closed client was opened");
                f.error=null; app.stopped=true; UiDialogs.choice.accept(null,0);
                check(f.error!=null && ToolApplications.opened.size()==2, "stopped session was opened");
                app.stopped=false; app.ready=false;
                try { f.openGraphics(app.id); throw new AssertionError("opened starting session"); }
                catch(IllegalStateException expected) {}
                GraphicalSessions.sessions.remove(app.id);
                try { f.openGraphics(app.id); throw new AssertionError("opened removed session"); }
                catch(IllegalStateException expected) {}
                """);
    }

    @Test public void taskManagerUsesSharedCatalogAndClaimsGraphicalHosts() throws Exception {
        var applications=Files.readString(Path.of(RuntimeSourceFixture.MAIN+"TaskManagerApplications.java"));
        assertTrue(applications.contains("graphics(GraphicalSessions.list()"));
        assertTrue(applications.contains("for (var entry : graphics) for (var window : entry.windows()) claimed.add(window.taskId)"));
        assertTrue(applications.contains("if (claimed.contains(task.taskId)) continue"));
        for (var file: new String[]{"TaskManagerApplications", "TaskManagerActions"}) {
            var source=Files.readString(Path.of(RuntimeSourceFixture.MAIN+file+".java"));
            assertFalse(source.contains("X11Sessions"));
            assertFalse(source.contains("WaylandSessions"));
        }
    }

    @Test public void x11DesktopCapabilityDoesNotOverrideApplicationMode() throws Exception {
        verify("""
                Fixture f=new Fixture();
                var app=session("x11-app", "X11", true);
                check(app.desktop(), "fixture must expose whole-desktop capability");
                app.windows.add(new GraphicalSessions.Window(42,"application",true));
                f.openGraphics(app.id);
                check(ToolApplications.opened.equals(List.of("x11-app:42")), "application replaced with root viewer");
                """);
    }

    @Test public void forceCloseSelectionUsesOnlyHostsWithThatContract() throws Exception {
        RuntimeSourceFixture.verify("""
                static class TaskRepository { record TaskEntry(boolean force) {} }
                static class TaskManagerApplications { record Entry(List<TaskRepository.TaskEntry> windows) {} }
                static class BuiltInWindowRegistry {
                    static Object forceCloseAction(TaskRepository.TaskEntry task){return task.force()?task:null;}
                }
                public static void verify() {
                    var plain=new TaskRepository.TaskEntry(false); var force=new TaskRepository.TaskEntry(true);
                    var entry=new TaskManagerApplications.Entry(List.of(plain,force));
                    check(windows(entry,WindowAction.OPEN).equals(entry.windows()), "open filtered hosts");
                    check(windows(entry,WindowAction.CLOSE).equals(entry.windows()), "close filtered hosts");
                    check(windows(entry,WindowAction.FORCE_STOP).equals(List.of(force)), "unsupported force-close offered");
                }
                """+RuntimeSourceFixture.nestedClass("TaskManagerActions", "WindowAction")
                +RuntimeSourceFixture.methods("TaskManagerActions", "windows"));
    }

    private static void verify(String scenario) throws Exception {
        RuntimeSourceFixture.verify("""
                interface Target {}
                record Graphics(String sessionId) implements Target {}
                record Entry(String id,String title,String detail,Target target,
                    List<TaskRepository.TaskEntry> windows,Set<SystemProcessSnapshot.Identity> processes) {}
                static class TaskRepository {
                    static class TaskEntry { final int taskId; TaskEntry(int id){taskId=id;} }
                }
                record Host(int taskId) {}
                record Identity(int serverUid) {}
                static class SystemProcessSnapshot {
                    record Identity(int pid) {}
                    final int pid,uid; final String name;
                    SystemProcessSnapshot(int pid,int uid,String name){this.pid=pid;this.uid=uid;this.name=name;}
                    Identity identity(){return new Identity(pid);}
                }
                record ProcessCatalog(List<SystemProcessSnapshot> samples) {
                    Set<SystemProcessSnapshot.Identity> matching(java.util.function.Predicate<SystemProcessSnapshot> filter) {
                        return samples.stream().filter(filter).map(SystemProcessSnapshot::identity)
                            .collect(java.util.stream.Collectors.toSet());
                    }
                }
                static class GraphicalSessions {
                    static final Map<String,Session> sessions=new HashMap<>();
                    static Session find(String id){return sessions.get(id);}
                    record Window(long id,String title,boolean mapped) {}
                    static class Session {
                        String id,protocol; boolean application,stopped,ready=true;
                        final List<Host> hosts=new ArrayList<>(); final List<Window> windows=new ArrayList<>();
                        String id(){return id;} String name(){return id;} String protocol(){return protocol;}
                        String state(){return ready?"READY":"STARTING";}
                        Identity identity(){return new Identity(10001);}
                        boolean stopped(){return stopped;} boolean ready(){return ready;}
                        boolean desktop(){return protocol.equals("X11") || !application;}
                        boolean application(){return application;}
                        List<Host> hosts(){return hosts;} List<Window> windows(){return windows;}
                        String windowIntent(Object context,long window){return id+":"+window;}
                    }
                }
                static GraphicalSessions.Session session(String id,String protocol,boolean application) {
                    var s=new GraphicalSessions.Session(); s.id=id;s.protocol=protocol;s.application=application;
                    GraphicalSessions.sessions.put(id,s);return s;
                }
                final Object activity=new Object(); Throwable error;
                void result(Throwable error){this.error=error;}
                static class ToolApplications {
                    static final List<String> opened=new ArrayList<>();
                    static void openSibling(Object activity,String intent,java.util.function.Consumer<Throwable> result) {
                        opened.add(intent); result.accept(null);
                    }
                }
                static class R { static class string { static int graphics_windows; } }
                static class android { static class R { static class string { static int cancel; } } }
                static class UiDialogs {
                    static List<String> labels; static java.util.function.BiConsumer<Object,Integer> choice;
                    static UiDialogs builder(Object activity){return new UiDialogs();}
                    UiDialogs setTitle(int title){return this;}
                    UiDialogs setItems(String[] items,java.util.function.BiConsumer<Object,Integer> listener) {
                        labels=List.of(items);choice=listener;return this;
                    }
                    UiDialogs setNegativeButton(int label,Object action){return this;} void show(){}
                }
                public static void verify(){
                """+scenario+"\n}\n"+RuntimeSourceFixture.methods("TaskManagerApplications", "graphics")
                +RuntimeSourceFixture.methods("TaskManagerActions", "requireGraphics", "applicationWindows",
                        "openGraphics", "openGraphicsWindow"));
    }
}
