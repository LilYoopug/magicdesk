package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class HostedApplicationIconTest {
    @Test public void subscriptionRetainsOneDemandUntilIdentityChangesOrHostCloses() throws Exception {
        String subscription = RuntimeSourceFixture.nestedClass("ApplicationIconSubscription", "ApplicationIconSubscription");
        RuntimeSourceFixture.verify("""
            static class Context { }
            record ApplicationIconKey(String value) { }
            static class RecentApplicationStore { record Entry(String shortcut, String termuxPackage) { } }
            static class ApplicationIcons {
                static final ApplicationIcons instance = new ApplicationIcons();
                int requests, releases;
                static ApplicationIcons get(Context ignored) { return instance; }
                static ApplicationIconKey key(String shortcut, String owner) { return new ApplicationIconKey(owner + shortcut); }
                Runnable subscribe(ApplicationIconKey key, Runnable changed) { requests++; return () -> releases++; }
            }
            """ + "static " + subscription + """
            public static void verify() {
                var binding = new ApplicationIconSubscription(new Context(), () -> { });
                var service = ApplicationIcons.instance;
                var recipe = new RecentApplicationStore.Entry("editor", "termux");
                binding.set(recipe); binding.set(recipe);
                check(service.requests == 1 && service.releases == 0, "identical presentation resubscribed");
                binding.set(new RecentApplicationStore.Entry("editor", "other"));
                check(service.requests == 2 && service.releases == 1, "source identity was not replaced");
                binding.close(); binding.close();
                check(service.releases == 2, "host lifetime did not release exactly once");
                binding.set((RecentApplicationStore.Entry)null);
                check(service.requests == 2, "missing recipe requested artwork");
            }
            """);
    }

    @Test public void clientIconWinsAndMissingIconsUseOnlyTheSelectedRecipesCache() throws Exception {
        RuntimeSourceFixture.verify("""
            static class Bitmap { }
            enum DesktopExecBackend { TERMUX, SHELL }
            record DesktopApplicationShortcut(String icon, DesktopExecBackend execBackend) {
                boolean hasExecLaunch(){return true;}
            }
            static class RecentApplicationStore { record Entry(DesktopApplicationShortcut shortcut, String termuxPackage) { } }
            static class ApplicationIcons {
                static Bitmap termux, guest; static int reads;
                static String key(DesktopApplicationShortcut shortcut, String owner) {
                    return shortcut == null ? null : shortcut.icon.startsWith("guest:") ? shortcut.icon : owner + ":" + shortcut.icon;
                }
                static Bitmap cached(String key){
                    if(key==null)return null;
                    reads++;
                    return key.startsWith("guest:") ? guest : key.startsWith("selected:") ? termux : null;
                }
            }
            """ + RuntimeSourceFixture.methods("DesktopApplicationIconResolver", "hostedIcon")
                    .replace("android.graphics.Bitmap", "Bitmap") + """
            public static void verify() {
                var recipe=new RecentApplicationStore.Entry(new DesktopApplicationShortcut("code",DesktopExecBackend.TERMUX),"selected");
                Bitmap nativeIcon=new Bitmap();
                check(hostedIcon(nativeIcon,recipe)==nativeIcon && ApplicationIcons.reads==0, "client icon consulted cache");
                check(hostedIcon(null,recipe)==null, "cache miss invented an icon");
                ApplicationIcons.termux=new Bitmap();
                check(hostedIcon(null,recipe)==ApplicationIcons.termux, "Termux cache ignored");
                var other=new RecentApplicationStore.Entry(recipe.shortcut(),"other");
                check(hostedIcon(null,other)==null, "wrong Termux owner borrowed icon");
                var guest=new RecentApplicationStore.Entry(new DesktopApplicationShortcut("guest:ubuntu/code",DesktopExecBackend.SHELL),"");
                ApplicationIcons.guest=new Bitmap();
                check(hostedIcon(null,guest)==ApplicationIcons.guest, "guest cache ignored");
                int reads=ApplicationIcons.reads;
                check(hostedIcon(null,null)==null && ApplicationIcons.reads==reads, "missing recipe accessed catalog");
            }
            """);
    }
}
