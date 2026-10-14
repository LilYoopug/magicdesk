package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;

import android.graphics.Rect;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.util.Collections;

public final class DesktopAutomationTaskEventTrackerTest {
    @Before
    public void setUp() {
        DesktopWindowTransitionProvenance.resetForTests(() -> 1_000L);
    }

    @After
    public void tearDown() {
        DesktopWindowTransitionProvenance.resetForTests();
    }

    @Test
    public void modeChangeIncludesBothConfigurationsAndDoesNotInventRequest() throws Exception {
        final DesktopAutomationTaskEventTracker tracker = new DesktopAutomationTaskEventTracker();
        tracker.observe(snapshot("com.example/.MainActivity"));
        final long afterId = DesktopAutomationEventJournal.latestId();
        tracker.observe(new TaskRepository.Snapshot(Collections.singletonList(
                new TaskRepository.TaskEntry(40, 42, 20, "com.example",
                        "com.example/.MainActivity", "com.example/.Dialog", "fullscreen",
                        new Rect(0, 0, 3840, 2160), 1, 228, false, true, true, 0)), true, ""));
        final JSONObject data = DesktopAutomationEventJournal.snapshot(afterId, 10)
                .getJSONObject(0).getJSONObject("data");
        assertEquals("unattributed", data.getString("transitionSource"));
        assertEquals("source-not-established", data.getString("transitionEvidence"));
        assertEquals("com.example/.MainActivity", data.getString("previousTopActivity"));
        org.junit.Assert.assertTrue(data.getJSONObject("previousBounds").has("left"));
        org.junit.Assert.assertTrue(data.getJSONObject("bounds").has("right"));
        assertEquals(228, data.getInt("densityDpi"));
        org.junit.Assert.assertTrue(data.isNull("lastImmersive"));
    }

    @Test
    public void capturesImmutableGeometryWithoutAndroidStubConstructors() throws Exception {
        RuntimeSourceFixture.verify("""
                static class Rect {
                    int left, top, right, bottom;
                    Rect(int l, int t, int r, int b) { left=l; top=t; right=r; bottom=b; }
                    Rect(Rect source) { this(source.left, source.top, source.right, source.bottom); }
                }
                static class JSONException extends Exception {}
                static class JSONObject extends HashMap<String, Object> {
                    public JSONObject put(String key, Object value) { super.put(key, value); return this; }
                }
                static class TaskRepository {
                    static class TaskEntry {
                        int displayId=4, densityDpi=228, userId=10;
                        String windowingMode="freeform", packageName="example", topActivityName="example/.Main";
                        Rect bounds=new Rect(100, 200, 900, 700);
                        boolean visible=true, active=true;
                    }
                }
                public static void verify() throws Exception {
                    TaskRepository.TaskEntry task = new TaskRepository.TaskEntry();
                    State state = new State(task);
                    task.bounds.left = 500;
                    JSONObject result = state.toJson();
                    JSONObject bounds = (JSONObject) result.get("bounds");
                    check(bounds.get("left").equals(100) && bounds.get("right").equals(900), "geometry changed");
                    check(result.get("densityDpi").equals(228) && result.get("userId").equals(10), "configuration lost");
                }
                """ + RuntimeSourceFixture.nestedClass("DesktopAutomationTaskEventTracker", "State")
                + RuntimeSourceFixture.methods("DesktopAutomationTaskEventTracker", "rectJson"));
    }

    @Test
    public void reportsTopActivityChangesFromExistingSnapshots()
            throws Exception {
        final DesktopAutomationTaskEventTracker tracker =
                new DesktopAutomationTaskEventTracker();
        tracker.observe(snapshot("com.example/.MainActivity"));
        final long afterId = DesktopAutomationEventJournal.latestId();

        tracker.observe(snapshot(
                "com.android.permissioncontroller/.GrantPermissionsActivity"));

        final JSONArray events = DesktopAutomationEventJournal.snapshot(
                afterId, 10);
        assertEquals(1, events.length());
        final JSONObject event = events.getJSONObject(0);
        assertEquals("top_activity_changed", event.getString("operation"));
        assertEquals(
                "com.android.permissioncontroller/.GrantPermissionsActivity",
                event.getJSONObject("data").getString("topActivity"));
    }

    private static TaskRepository.Snapshot snapshot(
            final String topActivity) {
        return new TaskRepository.Snapshot(
                Collections.singletonList(new TaskRepository.TaskEntry(
                        40,
                        42,
                        20,
                        "com.example",
                        "com.example/.MainActivity",
                        topActivity,
                        "freeform",
                        new Rect(100, 100, 900, 700),
                        false,
                        true,
                        true)),
                true,
                "");
    }
}
