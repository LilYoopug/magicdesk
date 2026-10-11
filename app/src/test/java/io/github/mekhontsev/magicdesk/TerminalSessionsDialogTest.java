package io.github.mekhontsev.magicdesk;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public final class TerminalSessionsDialogTest {
    @Test public void dropdownUsesTheHostDisplayAndAutomaticPlacement() throws Exception {
        final String dropdown = RuntimeSourceFixture.methods("TerminalSessionsDialog", "showDropdown");
        assertTrue(dropdown.contains("showDropdown(activity, anchor, null)"));
        assertTrue(dropdown.contains("currentTarget(activity), null,"));
        assertTrue(dropdown.contains("DesktopLaunchPresentation.automatic(), anchor, selection"));
        RuntimeSourceFixture.verify("""
                static class Display { int id; int getDisplayId(){return id;} }
                static class Activity { Display display; Display getDisplay(){return display;} }
                static class DesktopRuntimeBridge {
                    static Set<Integer> workspaces=Set.of();
                    static Set<Integer> workspaceDisplayIds(){return workspaces;}
                }
                record ToolLaunchTarget(int displayId, boolean desktop) {
                    static ToolLaunchTarget resolve(String placement, int display, Set<Integer> workspaces) {
                        check(placement.equals("auto"),"forced Desktop placement");
                        return new ToolLaunchTarget(display,workspaces.contains(display));
                    }
                }
                public static void verify() {
                    var activity=new Activity();
                    check(currentTarget(activity).displayId()==0,"missing display did not fall back to phone");
                    check(!currentTarget(activity).desktop(),"started Desktop");
                    activity.display=new Display();activity.display.id=8;
                    DesktopRuntimeBridge.workspaces=Set.of(9);
                    check(currentTarget(activity).displayId()==8,"used another display");
                    check(!currentTarget(activity).desktop(),"borrowed another workspace");
                    DesktopRuntimeBridge.workspaces=Set.of(8);
                    check(currentTarget(activity).desktop(),"ignored existing host workspace");
                }
                """ + RuntimeSourceFixture.methods("TerminalSessionsDialog", "currentTarget"));
    }

    @Test public void selectionEitherSwitchesTheHostOrOpensThroughTheSharedLauncher() throws Exception {
        RuntimeSourceFixture.verify("""
                static class Intent { }
                static class Activity {
                    boolean finishing,destroyed;
                    boolean isFinishing(){return finishing;} boolean isDestroyed(){return destroyed;}
                }
                static class TerminalSessions {
                    static int opens;
                    static Intent opened;
                    static Object destination,presentation;
                    static void open(Activity activity,Intent intent,Object target,String uniqueId,
                            Object mode,java.util.function.Consumer<Throwable> callback) {
                        check(dismissed,"window launched before closing picker");
                        opens++;opened=intent;destination=target;presentation=mode;
                    }
                }
                final Activity activity=new Activity();
                final Object target=new Object(),presentation=new Object();
                final String uniqueId=null;
                java.util.function.Consumer<Intent> selection;
                static boolean dismissed;
                void dismiss(){dismissed=true;}
                void result(Throwable error){throw new AssertionError(error);}
                public static void verify() {
                    var picker=new Fixture();var request=new Intent();
                    picker.openIntent(request);
                    check(TerminalSessions.opens==1 && TerminalSessions.opened==request,"did not reuse launch intent");
                    check(TerminalSessions.destination==picker.target && TerminalSessions.presentation==picker.presentation,
                            "lost placement");
                    final Intent[] selected={null};
                    picker.selection=intent->{check(dismissed,"switch before dismiss");selected[0]=intent;};
                    dismissed=false;picker.openIntent(request);
                    check(selected[0]==request && TerminalSessions.opens==1,"console switch opened a window");
                    for(int state=0;state<2;state++) {
                        picker.activity.finishing=state==0;picker.activity.destroyed=state==1;
                        dismissed=false;selected[0]=null;picker.openIntent(request);
                        check(!dismissed && selected[0]==null && TerminalSessions.opens==1,"used expired host");
                    }
                }
                """ + RuntimeSourceFixture.methods("TerminalSessionsDialog", "openIntent"));
    }
}
