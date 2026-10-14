package io.github.mekhontsev.magicdesk;

import org.junit.Test;

public final class DesktopUiSnapshotTest {
    @Test public void automationExportsEveryLivePanelAndKeepsGeometryDetachedFromTheHost() throws Exception {
        RuntimeSourceFixture.verify("""
                static class Rect {
                    int left,top,right,bottom;
                    Rect(){}
                    Rect(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;}
                    Rect(Rect r){this(r.left,r.top,r.right,r.bottom);}
                }
                static class ShellPanel { enum Edge { TOP,BOTTOM,LEFT,RIGHT } }
                static class DesktopShellLayout {
                    record Observation() {}
                    final Observation state = new Observation();
                    Observation observe(){return state;}
                }
                static class DesktopLayoutController {
                    final DesktopShellLayout layout = new DesktopShellLayout();
                    DesktopShellLayout shellLayout(){return layout;}
                }
                DesktopLayoutController mDesktopLayout = new DesktopLayoutController();
                static class DesktopTaskbarHost {
                    record Panel(String id,ShellPanel.Edge edge,Rect content,Rect paint,Rect output){}
                    List<Panel> values;
                    List<Panel> panels(){return values;}
                }
                static class DesktopPanelWindowController {
                    boolean hasVisiblePanel(){return false;} Rect visibleBounds(){return new Rect();}
                    String visibleTitle(){return "";}
                }
                static class StartMenuController { boolean isVisible(){return false;} }
                DesktopPanelWindowController mDesktopPanelWindowController;
                StartMenuController mStartMenuController;
                DesktopTaskbarHost mTaskbarHost = new DesktopTaskbarHost();
                boolean isActivityUnavailable(){return false;} boolean isDesktopShell(){return true;}
                int getCurrentDisplayId(){return 9;} boolean isTaskbarVisible(){return false;}
                Rect getTaskbarBounds(){return new Rect(100,200,1100,240);}
                boolean isDesktopWallpaperRendered(){return true;} boolean isUsingFallbackDesktopWallpaper(){return false;}
                static class JSONException extends Exception {}
                static class JSONObject {
                    Map<String,Object> values = new LinkedHashMap<>();
                    JSONObject put(String name,Object value){values.put(name,value);return this;}
                    Object get(String name){return values.get(name);}
                }
                static class JSONArray {
                    List<Object> values = new ArrayList<>();
                    JSONArray put(Object value){values.add(value);return this;}
                }
                """ + "static " + RuntimeSourceFixture.nestedClass("DesktopUiSnapshot", "DesktopUiSnapshot")
                + RuntimeSourceFixture.methods("DesktopShellActivity", "getAutomationUiSnapshot")
                + RuntimeSourceFixture.methods("DesktopAutomationStateReader", "uiJson", "rectJson") + """
                public static void verify() throws Exception {
                    Fixture f=new Fixture();
                    List<DesktopTaskbarHost.Panel> panels=new ArrayList<>();
                    for (var edge:ShellPanel.Edge.values()) {
                        int n=panels.size();
                        panels.add(new DesktopTaskbarHost.Panel("panel-"+n,edge,
                            new Rect(100+n,200+n,300+n,400+n),
                            new Rect(90+n,190+n,310+n,410+n),new Rect(0,0,1000,800)));
                    }
                    f.mTaskbarHost.values=panels;
                    var snapshot=f.getAutomationUiSnapshot();
                    check(snapshot.shellLayout==f.mDesktopLayout.shellLayout().observe(),"layout observation lost");
                    check(snapshot.panels.size()==4,"panel list was flattened");
                    panels.get(0).content().left=999;
                    panels.get(0).paint().left=999;
                    panels.get(0).output().left=999;
                    panels.clear();
                    snapshot.panels.get(0).bounds().left=888;
                    snapshot.panels.get(0).paintBounds().left=888;
                    snapshot.panels.get(0).outputBounds().left=888;
                    check(snapshot.panels.get(0).bounds().left==100,"host or reader mutated content snapshot");
                    check(snapshot.panels.get(0).paintBounds().left==90,"host or reader mutated paint snapshot");
                    check(snapshot.panels.get(0).outputBounds().left==0,"host or reader mutated output snapshot");
                    try { snapshot.panels.clear(); throw new AssertionError("mutable panel list"); }
                    catch (UnsupportedOperationException expected) {}
                    JSONObject ui=uiJson(snapshot);
                    JSONArray exported=(JSONArray)ui.get("panels");
                    check(exported.values.size()==4,"MCP omitted panels");
                    String[] edges={"top","bottom","left","right"};
                    for (int i=0;i<4;i++) {
                        JSONObject panel=(JSONObject)exported.values.get(i);
                        check(panel.get("id").equals("panel-"+i),"MCP changed stable identity");
                        check(panel.get("edge").equals(edges[i]),"MCP lost edge");
                        check(((JSONObject)panel.get("bounds")).get("left").equals(100+i),"content geometry lost");
                        check(((JSONObject)panel.get("paintBounds")).get("left").equals(90+i),"paint geometry lost");
                        check(((JSONObject)panel.get("outputBounds")).get("right").equals(1000),"output geometry lost");
                    }
                    JSONObject taskbar=(JSONObject)ui.get("taskbar");
                    check(taskbar.get("visible").equals(false),"snapshot changed reveal policy");
                    check(((JSONObject)taskbar.get("bounds")).get("top").equals(200),"primary bounds lost");
                    check(((JSONArray)uiJson(DesktopUiSnapshot.UNAVAILABLE).get("panels")).values.isEmpty(),
                        "unavailable snapshot invented panel geometry");
                    f.mTaskbarHost=null;
                    check(f.getAutomationUiSnapshot().panels.isEmpty(),"missing host retained panels");
                }
                """);
    }
}
