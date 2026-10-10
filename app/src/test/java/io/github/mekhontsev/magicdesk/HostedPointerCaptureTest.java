package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class HostedPointerCaptureTest {
    @Test public void captureNeedsConfirmationAndReleasesOnFocusLoss() throws Exception {
        verify("""
            var host=new Host(); var c=new HostedPointerCapture(host); var out=new HostedSurfaceOutput();
            c.bind(out); c.eligible(true); out.listener.accept(12);
            check(host.requests==1 && c.serial()==0 && out.events.isEmpty(),"request is not capture");
            c.changed(true); c.changed(true);
            check(c.serial()==12 && out.events.equals(List.of("12:true")),"exactly one acknowledgement");
            c.eligible(false); c.changed(false); c.changed(true);
            check(c.serial()==0 && out.events.equals(List.of("12:true","12:false")),"focus loss and late confirmation");
            int requested=host.requests; c.eligible(true);
            check(host.requests==requested,"focus return cannot resurrect a revoked request");
            out.listener.accept(13); c.changed(true); out.listener.accept(0);
            check(c.serial()==0 && host.releases>=2,"client release frees Android capture");
            """);
    }

    @Test public void replacementCannotBeCapturedByOldOutputCallbacks() throws Exception {
        verify("""
            var host=new Host(); var c=new HostedPointerCapture(host); var old=new HostedSurfaceOutput();
            c.bind(old); c.eligible(true); var callback=old.listener; callback.accept(1); c.changed(true);
            var next=new HostedSurfaceOutput(); c.bind(next); callback.accept(2);
            check(c.serial()==0 && host.requests==1 && old.listener==null,"old callback is detached and guarded");
            next.listener.accept(3); c.changed(true); c.bind(null);
            check(next.events.equals(List.of("3:true","3:false")) && c.serial()==0,"replacement owns its cleanup");
            """);
    }

    @Test public void unavailableHostDeclinesWithoutRequestingAndroid() throws Exception {
        verify("""
            var host=new Host(); var c=new HostedPointerCapture(host); var out=new HostedSurfaceOutput();
            c.bind(out); out.listener.accept(1);
            check(host.requests==0 && out.events.equals(List.of("1:false")),"hidden host rejects request");
            c.eligible(true); out.listener.accept(2); c.changed(false);
            check(out.events.equals(List.of("1:false","2:false")),"platform refusal propagates");
            """);
    }

    private static void verify(String body) throws Exception {
        String source = java.nio.file.Files.readString(java.nio.file.Path.of(RuntimeSourceFixture.MAIN + "HostedPointerCapture.java"));
        RuntimeSourceFixture.verify("io.github.mekhontsev.magicdesk",
            "static " + source.substring(source.indexOf("final class HostedPointerCapture")) + """
            static class HostedSurfaceOutput {
                java.util.function.LongConsumer listener;
                List<String> events=new ArrayList<>();
                void captureListener(java.util.function.LongConsumer value){listener=value;}
                void pointerCapture(long serial,boolean active){events.add(serial+":"+active);}
            }
            static class Host implements HostedPointerCapture.Host {
                int requests,releases;
                public void request(){requests++;} public void release(){releases++;}
            }
            """ + "public static void verify() {" + body + "}");
    }
}
