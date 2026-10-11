package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class ConsoleTerminalAppearanceTest {
    @Test public void liveThemeFollowsTheHostAndInvalidatesOnlyStaleAnimation() throws Exception {
        RuntimeSourceFixture.verify("""
                static class TextStyle { static final int COLOR_INDEX_FOREGROUND=0,COLOR_INDEX_BACKGROUND=1,COLOR_INDEX_CURSOR=2; }
                static class AppearanceStore {
                    static AppearanceStore resolved(Object context) { return (AppearanceStore)context; }
                    boolean night;
                    AppearanceStore theme(){return this;} AppearanceStore palette(){return this;}
                    boolean night(){return night;}
                }
                static class Colors {
                    int[] values=new int[3];
                    boolean setDefaultColor(int i,int value){boolean changed=values[i]!=value;values[i]=value;return changed;}
                }
                static class Session {
                    final Colors mColors=new Colors(); boolean dark;
                    Session emulator(){return this;}
                    void setColorScheme(boolean value){
                        check(mColors.values[1]==(value?0xff000000:0xffffffff),"notification precedes palette update");
                        dark=value;
                    }
                }
                static class Animation { int resets; void reset(){resets++;} }
                static class View {
                    final AppearanceStore context=new AppearanceStore();
                    Object getContext(){return context;}
                    int mBackgroundColor, invalidations;
                    Session mSession;
                    final Animation mRegionScroll=new Animation();
                    void invalidate(){invalidations++;}
                """ + RuntimeSourceFixture.methods("ConsoleTerminalView", "refreshAppearance") + """
                }
                public static void verify() {
                    var view=new View();view.refreshAppearance();
                    check(view.mBackgroundColor==0xffffffff,"empty light terminal is not white");
                    var first=new Session();view.mSession=first;view.refreshAppearance();
                    check(Arrays.equals(first.mColors.values,new int[]{0xff000000,0xffffffff,0xff000000}),"light text/cursor mismatch");
                    int resets=view.mRegionScroll.resets;view.refreshAppearance();
                    check(view.mRegionScroll.resets==resets,"unchanged palette interrupts scrolling");
                    view.context.night=true;view.refreshAppearance();
                    check(view.mBackgroundColor==0xff000000 && first.mColors.values[0]==0xffffffff,"live dark theme ignored");
                    check(first.dark,"host scheme not published to terminal programs");
                    check(view.mRegionScroll.resets==resets+1,"old animation kept obsolete colors");
                    var second=new Session();view.mSession=second;view.context.night=false;view.refreshAppearance();
                    check(first.mColors.values[1]==0xff000000 && second.mColors.values[1]==0xffffffff,"another session was repainted");
                    check(first.dark && !second.dark,"scheme leaked between sessions");
                }
                """);
    }
}
