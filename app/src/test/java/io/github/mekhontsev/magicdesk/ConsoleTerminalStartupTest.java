package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class ConsoleTerminalStartupTest {
    @Test public void firstLayoutStartsPtyBeforeAndroidPublishesIsLaidOut() throws Exception {
        RuntimeSourceFixture.verify("""
                enum DesktopExecBackend { SHELL, TERMUX }
                static class R { static class string {
                    static final int console_termux_permission_required=1,console_terminal_starting=2;
                } }
                static class TermuxIntegration {
                    static class Endpoint {
                        String packageName="termux",error="";
                        boolean available(){return true;} boolean canRequestPermission(){return false;}
                    }
                    static Endpoint inspect(Object c){return new Endpoint();}
                    static void ensureRunCommandPermission(Object c){}
                }
                static class View {
                    int width,height;
                    int getWidth(){return width;} int getHeight(){return height;}
                    boolean isLaidOut(){return false;}
                }
                static class Session { boolean ready; int starts;
                    boolean isReady(){return ready;} void start(){starts++;ready=true;}
                }
                static class Snapshot { boolean ready=true; boolean isReady(){return ready;} }
                Session mSession=new Session(); View mTerminalView=new View(); Snapshot mSnapshot=new Snapshot();
                DesktopExecBackend mBackend=DesktopExecBackend.SHELL;
                boolean mTerminalFailed,mPermissionRequested; String mTerminalStatus="";
                void failTerminal(String message){throw new AssertionError(message);}
                String getString(int r){return "starting";} void updateShellStatus(){}
                """ + RuntimeSourceFixture.methods("CommandConsoleActivity", "maybeStartSession") + """
                public static void verify() {
                    Fixture window=new Fixture();window.maybeStartSession();
                    check(window.mSession.starts==0, "PTY started before geometry");
                    window.mTerminalView.width=800;window.mTerminalView.height=600;window.maybeStartSession();
                    check(window.mSession.starts==1, "first layout callback did not start PTY");
                    window.maybeStartSession();check(window.mSession.starts==1,"ready PTY restarted");
                    window.mSession=new Session();window.mSnapshot.ready=false;window.maybeStartSession();
                    check(window.mSession.starts==0,"shell prerequisite ignored");
                    window.mBackend=DesktopExecBackend.TERMUX;window.maybeStartSession();
                    check(window.mSession.starts==1,"Termux acquired a shell prerequisite");
                }
                """);
    }
}
