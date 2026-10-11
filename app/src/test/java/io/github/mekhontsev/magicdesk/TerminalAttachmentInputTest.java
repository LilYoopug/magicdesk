package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class TerminalAttachmentInputTest {
    @Test public void transferEndsOldMousePressAndCancelsGesturesAndComposition() throws Exception {
        RuntimeSourceFixture.verify("io.github.mekhontsev.magicdesk", """
                static class android { static class os { static class SystemClock {
                    static long uptimeMillis() {return 1;}
                } } }
                static class MotionEvent {
                    static final int ACTION_CANCEL=3; int action; boolean recycled;
                    static MotionEvent obtain(long a,long b,int c,int d,int e,int f) {
                        var event=new MotionEvent();event.action=c;return event;
                    }
                    void recycle(){recycled=true;}
                }
                static class Gesture {
                    MotionEvent last; void onTouchEvent(MotionEvent event){last=event;}
                }
                static class Input { boolean reset; void reset(){reset=true;} }
                static class Session {
                    boolean pressed=true; int releases;
                    Session emulator(){return this;}
                    void sendMouseEvent(int button,int x,int y,boolean down){pressed=down;releases++;}
                }
                final TerminalViewport mViewport=new TerminalViewport();
                Session mSession=new Session();
                Gesture mGestures=new Gesture(),mScaleGestures=new Gesture(); Input mInput=new Input();
                boolean mTerminalMousePress=true,mTouchScrolling=true,mFontScaleGesture=true,mImageGesture=true;
                int mTerminalMouseButton=0; float mDownX,mDownY;
                float mTouchScrollRemainder=1,mWheelScrollRemainder=1,mFontWheelRemainder=1;
                """ + RuntimeSourceFixture.methods("ConsoleTerminalView", "resetAttachmentInput") + """
                public static void verify() {
                    Fixture view=new Fixture(); view.resetAttachmentInput();
                    check(!view.mSession.pressed && view.mSession.releases==1, "old PTY kept mouse pressed");
                    check(!view.mTerminalMousePress && !view.mTouchScrolling && !view.mFontScaleGesture
                            && !view.mImageGesture && view.mInput.reset, "gesture/composition crossed sessions");
                    check(view.mTouchScrollRemainder==0 && view.mWheelScrollRemainder==0
                            && view.mFontWheelRemainder==0, "fractional gestures crossed sessions");
                    check(view.mGestures.last.action==MotionEvent.ACTION_CANCEL
                            && view.mScaleGestures.last==view.mGestures.last && view.mGestures.last.recycled,
                            "pending gesture callbacks not cancelled");
                    view.mSession=null;view.resetAttachmentInput();
                }
                """, "TerminalViewport");
    }
}
