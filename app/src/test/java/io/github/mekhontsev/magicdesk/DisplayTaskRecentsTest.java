package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class DisplayTaskRecentsTest {
    @Test public void onlyPresentedVirtualHostsAreExcludedAndTaskFlagsSurviveRecreation() throws Exception {
        RuntimeSourceFixture.verify("""
            static class Looper { static Looper getMainLooper() { return new Looper(); } }
            static class Handler { Handler(Looper looper) {} void post(Runnable r) {} }
            static class Display {
                static final int DEFAULT_DISPLAY=0;
                int id; boolean valid=true;
                Display(int id) { this.id=id; }
                int getDisplayId() { return id; } boolean isValid() { return valid; }
            }
            static class DisplayManager {
                interface DisplayListener { void onDisplayAdded(int id); void onDisplayChanged(int id); void onDisplayRemoved(int id); }
                void registerDisplayListener(DisplayListener listener,Handler handler) {}
            }
            static class Context {
                DisplayManager displays=new DisplayManager(); ActivityManager manager=new ActivityManager();
                <T> T getSystemService(Class<T> type) { return type.cast(type==DisplayManager.class?displays:manager); }
            }
            static class MagicDeskApplication {
                static Context context=new Context(); static Context applicationContext() { return context; }
            }
            static class Activity extends Context {
                int taskId=1; Display display=new Display(4); boolean finishing;
                int getTaskId() { return taskId; } Display getDisplay() { return display; }
                boolean isFinishing() { return finishing; }
            }
            static class HostedWindowPresentation { interface ContentHost {} }
            static class Host extends Activity implements HostedWindowPresentation.ContentHost {}
            static class Intent { static int FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS=1; int flags; int getFlags() { return flags; } }
            static class ActivityManager {
                List<AppTask> tasks=new ArrayList<>(); int reads;
                List<AppTask> getAppTasks() { reads++; return tasks; }
                static class RecentTaskInfo { int taskId=1,displayId=4; Intent baseIntent=new Intent(); }
                static class AppTask {
                    RecentTaskInfo info=new RecentTaskInfo(); List<Boolean> changes=new ArrayList<>(); boolean fail;
                    RecentTaskInfo getTaskInfo() { return info; }
                    void setExcludeFromRecents(boolean value) {
                        if(fail) throw new IllegalStateException("denied");
                        changes.add(value); info.baseIntent.flags=value?1:0;
                    }
                }
            }
            static class DisplayPresentations {
                static class Source { int id=4; boolean direct=true; }
                static class Session { Source source=new Source(); boolean closed,ready,outputAttachment; int taskId=99; }
            }
            enum DisplayPresentationMode {
                DIRECT,MIRROR;
                static DisplayPresentationMode forSource(DisplayPresentations.Source source) { return source.direct?DIRECT:MIRROR; }
            }
            static class DesktopTaskDescription { static void refresh() {} }
            static class ShellAccess { static String usefulMessage(Exception e) { return e.getMessage(); } }
            static class CompatibilityDiagnostics { static int errors; static void record(String a,String b,String c) { errors++; } }
            """ + "static " + RuntimeSourceFixture.nestedClass("DisplayTaskRecents", "DisplayTaskRecents") + """
            public static void verify() {
                Host host=new Host(); ActivityManager.AppTask task=new ActivityManager.AppTask(); host.manager.tasks.add(task);
                var session=new DisplayPresentations.Session();
                DisplayTaskRecents.presentationChanged(session); DisplayTaskRecents.update(host);
                check(task.changes.isEmpty(),"unattached presentation hid task");
                session.ready=true; session.outputAttachment=true;
                session.source.direct=false;
                DisplayTaskRecents.presentationChanged(session); DisplayTaskRecents.update(host);
                check(task.changes.isEmpty(),"mirrored physical host hidden");
                session.source.direct=true;
                task.fail=true;
                DisplayTaskRecents.presentationChanged(session); DisplayTaskRecents.update(host);
                check(CompatibilityDiagnostics.errors==1 && DisplayTaskRecents.ORIGINAL_FLAGS.isEmpty(),"failed update committed ownership");
                task.fail=false; DisplayTaskRecents.update(host);
                check(task.changes.equals(List.of(true)),"source not hidden");
                int reads=host.manager.reads; DisplayTaskRecents.update(host);
                check(host.manager.reads==reads,"unchanged layout queried task metadata");
                session.closed=true; DisplayTaskRecents.presentationChanged(session); DisplayTaskRecents.update(host);
                check(task.changes.equals(List.of(true)),"viewer close exposed internal task");
                Host replacement=new Host(); replacement.manager=host.manager;
                DisplayTaskRecents.forget(host); DisplayTaskRecents.update(replacement);
                check(task.changes.equals(List.of(true)),"recreation lost original flag");
                replacement.display.id=0; task.info.displayId=0; DisplayTaskRecents.update(replacement);
                check(task.changes.equals(List.of(true,false)),"phone move did not restore task");
                replacement.display.id=4; task.info.displayId=4; task.info.baseIntent.flags=1;
                DisplayTaskRecents.update(replacement);
                DisplayTaskRecents.observer.onDisplayRemoved(4); DisplayTaskRecents.update(replacement);
                check(task.changes.equals(List.of(true,false)),"original exclusion overwritten");
                task.info.baseIntent.flags=0; session.closed=false;
                DisplayTaskRecents.presentationChanged(session); DisplayTaskRecents.update(replacement);
                DisplayTaskRecents.observer.onDisplayAdded(4); DisplayTaskRecents.update(replacement);
                check(task.changes.equals(List.of(true,false,true,false)),"display ID reuse retained hidden role");
                DisplayTaskRecents.presentationChanged(session);
                Activity ordinary=new Activity(); ordinary.taskId=2; ordinary.manager=host.manager;
                check(!DisplayTaskRecents.represented(ordinary),"ordinary tool hidden");
                DisplayTaskRecents.update(replacement); replacement.finishing=true; DisplayTaskRecents.forget(replacement);
                check(DisplayTaskRecents.ORIGINAL_FLAGS.isEmpty(),"finished task retained flag ownership");
            }
            """);
    }
}
