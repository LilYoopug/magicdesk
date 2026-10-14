package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.graphics.Rect;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class DesktopWindowTransitionProvenanceTest {
    private long now = 1_000L;

    @Before
    public void setUp() {
        DesktopWindowTransitionProvenance.resetForTests(() -> now);
    }

    @After
    public void tearDown() {
        DesktopWindowTransitionProvenance.resetForTests();
    }

    @Test
    public void magicDeskCommandCarriesSemanticCallerPath() {
        DesktopWindowTransitionProvenance.noteMagicDeskCommand(
                DesktopWindowTransitionRequest.restoreFreeform(
                        3,
                        42,
                        new Rect(1, 2, 300, 400),
                        DesktopTaskDensity.INHERIT,
                        "native-window-restore-shortcut"));

        final DesktopWindowTransitionProvenance.Observation observation =
                DesktopWindowTransitionProvenance.classify(
                        42, "fullscreen", "freeform");

        assertEquals(
                DesktopWindowTransitionProvenance.Source.MAGICDESK_COMMAND,
                observation.source);
        assertEquals(
                "restore-freeform/native-window-restore-shortcut",
                observation.detail);
    }

    @Test
    public void handoffCorrectionOverridesEarlierApplicationRequest() {
        DesktopWindowTransitionProvenance.noteApplicationRequest(7, true);
        DesktopWindowTransitionProvenance.noteActivityHandoff(
                7, "fullscreen", "example.Activity");

        assertEquals(
                DesktopWindowTransitionProvenance.Source.ACTIVITY_HANDOFF_GUARD,
                DesktopWindowTransitionProvenance.classify(
                        7, "freeform", "fullscreen").source);
    }

    @Test
    public void uncorrelatedKnownModeChangeDoesNotBlameFramework() {
        assertEquals(
                DesktopWindowTransitionProvenance.Source.UNATTRIBUTED,
                DesktopWindowTransitionProvenance.classify(
                        9, "freeform", "fullscreen").source);
    }

    @Test
    public void expiredCauseCannotAttributeLaterTransition() {
        DesktopWindowTransitionProvenance.noteApplicationRequest(7, true);
        now += 15_001;
        var observation = DesktopWindowTransitionProvenance.classify(7, "freeform", "fullscreen");
        assertEquals(DesktopWindowTransitionProvenance.Source.UNATTRIBUTED, observation.source);
        assertEquals(15_001, observation.ageMillis);
    }

    @Test
    public void mismatchedAndRejectedCausesAreNotAttributed() {
        DesktopWindowTransitionProvenance.noteApplicationRequest(7, false);
        var mismatch = DesktopWindowTransitionProvenance.classify(7, "freeform", "fullscreen");
        assertEquals("source-not-established", mismatch.evidence());
        assertTrue(mismatch.detail.contains("unmatched-cause"));
        DesktopWindowTransitionProvenance.noteActivityHandoff(7, "freeform", "example.Activity");
        DesktopWindowTransitionProvenance.rejectCommand(7);
        assertEquals("source-not-established",
                DesktopWindowTransitionProvenance.classify(7, "fullscreen", "freeform").evidence());
    }

    @Test
    public void immersiveObservationRetainsUnknownEffectiveStateAndIsTaskScoped() throws Exception {
        var state = new DesktopTaskRuntimeState(7);
        DesktopWindowTransitionProvenance.noteImmersiveObservation(7, false, false,
                false, "ignored-background-exit", state);
        var evidence = DesktopWindowTransitionProvenance.lastImmersive(7);
        assertTrue(evidence.isNull("effectiveRequest"));
        assertEquals("ignored-background-exit", evidence.getString("decision"));
        assertNull(DesktopWindowTransitionProvenance.lastImmersive(8));
        evidence.put("decision", "modified");
        assertEquals("ignored-background-exit",
                DesktopWindowTransitionProvenance.lastImmersive(7).getString("decision"));
        DesktopWindowTransitionProvenance.forgetTask(7);
        assertNull(DesktopWindowTransitionProvenance.lastImmersive(7));
    }
}
