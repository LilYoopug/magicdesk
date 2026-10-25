package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class HostedKeyboardShortcutsTest {
    @Test public void chordsKeepTheirTargetAndReleaseWithoutNativeDuplicates() throws Exception {
        RuntimeSourceFixture.verify("""
            static class KeyEvent {
                static final int ACTION_DOWN = 0, ACTION_UP = 1;
                static final int KEYCODE_HOME = 20, KEYCODE_APP_SWITCH = 21, KEYCODE_SEARCH = 22;
                static final int KEYCODE_POWER = 23, KEYCODE_SLEEP = 24, KEYCODE_WAKEUP = 25;
                static final int KEYCODE_VOLUME_UP = 26, KEYCODE_VOLUME_DOWN = 27, KEYCODE_VOLUME_MUTE = 28;
                final int code, action, repeats;
                KeyEvent(int code, boolean down, int repeats) { this.code=code; action=down?0:1; this.repeats=repeats; }
                int getKeyCode() { return code; }
                int getAction() { return action; }
                int getRepeatCount() { return repeats; }
                boolean isSystem() { return code>=20; }
                static boolean isModifierKey(int key) { return key>=1 && key<=4; }
            }
            """ + "static " + RuntimeSourceFixture.nestedClass("HostedKeyboardShortcuts", "HostedKeyboardShortcuts") + """
            static class Target implements HostedKeyboardShortcuts.Target {
                List<String> events = new ArrayList<>(); Set<Integer> held = new LinkedHashSet<>();
                boolean valid = true; int releases;
                public boolean key(KeyEvent event) {
                    if (!valid) return false;
                    int key = event.getKeyCode(); boolean down = event.getAction()==0;
                    if (down) held.add(key); else held.remove(key);
                    events.add(key+(down?"+":"-")); return true;
                }
                public void release() { releases++; for (int key:held) events.add(key+"-"); held.clear(); }
            }
            static class Keyboard {
                HostedKeyboardShortcuts router = new HostedKeyboardShortcuts();
                Target target = new Target(); int queries; boolean reserved;
                boolean key(int code, boolean down) { return repeat(code,down,0); }
                boolean repeat(int code, boolean down, int repeats) {
                    return router.accept(new KeyEvent(code,down,repeats),reserved,()->{queries++; return target;});
                }
            }
            public static void verify() {
                Keyboard k = new Keyboard();
                for(int i=0;i<100;i++) { check(!k.key(10,true),"typing captured"); check(!k.key(10,false),"typing up captured"); }
                check(k.queries==0,"typing queried tasks");
                // Alt, Tab, repeat, reverse Tab, Alt release, late Tab release.
                check(k.key(1,true),"Alt not captured");
                check(k.key(10,true) && k.repeat(10,true,1) && k.key(10,false),"Tab stream not owned");
                check(k.key(3,true) && k.key(10,true) && k.key(3,false) && k.key(1,false) && k.key(10,false),"reverse/up order lost");
                check(k.target.events.equals(List.of("1+","10+","10+","10-","3+","10+","3-","1-","10-")),"chord changed");
                check(k.target.held.isEmpty() && k.queries==1,"stuck key or query per key");
                check(k.key(4,true) && k.key(4,false),"standalone Super leaked to Android");
                check(k.key(20,true) && k.key(20,false),"system key leaked to Android");
                // Ctrl+Alt+T stays one chord; the shared display switch has priority.
                k.target.events.clear();
                check(k.key(2,true) && k.key(1,true) && k.key(11,true) && k.key(11,false),"Ctrl+Alt+T lost");
                k.reserved=true; check(k.key(10,true),"display-switch down not drained");
                check(k.target.held.isEmpty(),"display switch retained guest modifiers");
                int delivered=k.target.events.size();
                check(k.key(10,false) && k.key(1,false) && k.key(2,false),"display-switch release leaked");
                check(k.target.events.size()==delivered,"cancelled chord kept delivering");
                k.reserved=false;
                check(k.key(1,true),"new chord missing"); k.router.cancel();
                check(k.key(10,true) && k.key(10,false) && k.key(1,false),"route loss leaked partial chord");
                check(k.target.held.isEmpty(),"route loss stuck modifier");
                // A game movement key already down stays on its original path.
                check(!k.key(12,true),"plain movement captured");
                check(k.key(1,true) && k.key(10,true) && k.key(10,false),"held movement prevented Alt+Tab");
                check(!k.key(12,false) && k.key(1,false),"movement release stolen");
                k.target.valid=false;
                check(k.key(1,true) && k.key(10,true) && k.key(1,false) && k.key(10,false),"dead output leaked keys");
                k.target=new Target();
                check(k.key(2,true) && k.key(2,false),"replacement output unavailable");
                for(int key=23;key<=28;key++) check(!k.key(key,true) && !k.key(key,false),"hardware key captured");
                Keyboard nativeOnly=new Keyboard(); nativeOnly.target=null;
                check(!nativeOnly.key(1,true),"unknown destination consumed Alt");
                nativeOnly.target=new Target();
                check(!nativeOnly.key(2,true) && !nativeOnly.key(10,true),"half-native chord captured");
                check(!nativeOnly.key(10,false) && !nativeOnly.key(2,false) && !nativeOnly.key(1,false),"native ups captured");
                Keyboard desktop=new Keyboard(); desktop.reserved=true;
                check(!desktop.key(1,true) && !desktop.key(10,true),"Desktop shortcuts stolen");
                check(desktop.queries==0,"Desktop queried hosted tasks");
                check(k.target.held.isEmpty(),"other keyboard affected held state");
            }
            """);
    }
}
