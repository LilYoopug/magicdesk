package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public class GraphicalLaunchConfigurationTest {
    @Test public void applicationLifetimeIsIndependentOfHistory() throws Exception {
        RuntimeSourceFixture.verify("""
            static class Context { }
            static class WaylandExecution { Commands commands = new Commands(); }
            static class Commands { String scope="shell:2000"; }
            static class RecentApplicationStore { record Entry(String sourcePath) { } }
            static class GraphicalPresentationPreferences {
                static String key(String scope, String path) { return scope + path; }
                static int load(Context c, String key) { return 100; }
            }
            static class HostedWindowPresentation { HostedWindowPresentation(Context c, Session s) { } }
            static class Session {
                Context context; String name, presentationKey; WaylandExecution execution;
                RecentApplicationStore.Entry recipe; boolean desktop, application; int scalePercent;
                HostedWindowPresentation presentation;
            """ + RuntimeSourceFixture.methods("WaylandSessions", "<init>").replace("private WaylandSessions() { }", "") + """
            }
            public static void verify() {
                var c = new Context(); var execution = new WaylandExecution();
                check(new Session(c,"external",execution,null,false,true).application,
                        "external application acquired a retained server lifetime");
                check(!new Session(c,"desktop",execution,null,true,true).application,
                        "whole desktop acquired an individual application lifetime");
                check(!new Session(c,"server",execution,null,false,false).application,
                        "retained server acquired an individual application lifetime");
                var recipe = new RecentApplicationStore.Entry("/launcher.desktop");
                check(new Session(c,"shortcut",execution,recipe,false,true).application,
                        "shortcut lost application lifetime");
            }
            """);
    }

    @Test public void graphicsConfigurationDoesNotRequireRecentHistory() throws Exception {
        RuntimeSourceFixture.verify("""
            static class Context { }
            enum Protocol { X11, WAYLAND }
            record Graphics(Protocol protocol, String fileEnvironment) { }
            static class Exec { Graphics graphics; String command="command", workingDirectory="/tmp"; Object backend=new Object(); }
            static class DesktopLaunchRequest { Exec exec=new Exec(); String name="external", desktopFilePath=""; }
            static class RecentApplicationStore { static class Entry { } }
            interface Session { }
            static class X11 implements Session { X11(Object value) { } }
            static class Wayland implements Session { Wayland(Object value) { } }
            static Graphics received;
            static class X11Sessions {
                static Object startCommand(Context c, String name, String command, String cwd, String file,
                        RecentApplicationStore.Entry recipe, Object backend, Graphics graphics) {
                    check(recipe == null, "external request must not create history"); received = graphics; return new Object();
                }
            }
            static class WaylandSessions {
                static Object startApplication(Context c, String name, String command, String cwd, Object backend,
                        Graphics graphics, RecentApplicationStore.Entry recipe) {
                    check(recipe == null, "external request must not create history"); received = graphics; return new Object();
                }
            }
            public static void verify() {
                var request = new DesktopLaunchRequest();
                for (Protocol protocol : Protocol.values()) {
                    request.exec.graphics = new Graphics(protocol, "guest store identity");
                    startApplication(new Context(), request, null);
                    check(received == request.exec.graphics, "lost explicit graphics options without history: " + protocol);
                }
            }
            """ + RuntimeSourceFixture.methods("GraphicalSessions", "startApplication"));
    }
}
