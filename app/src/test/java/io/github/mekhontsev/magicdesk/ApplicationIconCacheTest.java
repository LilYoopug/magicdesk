package io.github.mekhontsev.magicdesk;

import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.Test;

public final class ApplicationIconCacheTest {
    private final List<List<String>> requests = new ArrayList<>();
    private final List<Consumer<Map<String, String>>> pending = new ArrayList<>();
    private final ArrayDeque<Runnable> dispatched = new ArrayDeque<>();
    private int changes;
    private final ApplicationIconCache<String, String> cache = new ApplicationIconCache<>(2, 2, (keys, complete) -> {
        requests.add(keys);
        pending.add(complete);
    }, dispatched::add);

    private Runnable watch(String key) { return cache.subscribe(key, () -> changes++); }
    private void drain() { while (!dispatched.isEmpty()) dispatched.remove().run(); }

    @Test public void independentConsumersCoalesceWithoutCatalogAndCacheMisses() {
        watch("gimp"); watch("firefox"); watch("missing"); watch("gimp");
        assertTrue(requests.isEmpty());
        drain();
        assertEquals(List.of(List.of("gimp", "firefox")), requests);
        pending.get(0).accept(Map.of("gimp", "pixels", "firefox", "browser"));
        assertEquals(3, changes);
        drain();
        assertEquals(List.of("missing"), requests.get(1));
        pending.get(1).accept(Map.of()); drain();
        var snapshot = cache.snapshot();
        watch("missing"); drain();
        assertEquals(2, requests.size());
        assertSame(snapshot, cache.snapshot());
        assertEquals("pixels", snapshot.get("gimp"));
        assertTrue(snapshot.containsKey("missing"));
        assertNull(snapshot.get("missing"));
        assertThrows(UnsupportedOperationException.class, snapshot::clear);
    }

    @Test public void resetRetainsDemandButDiscardsOldEndpointCompletion() {
        watch("gimp"); drain();
        cache.reset(); drain();
        int notifications = changes;
        pending.get(0).accept(Map.of("gimp", "wrong endpoint"));
        assertTrue(cache.snapshot().isEmpty());
        assertEquals(notifications, changes);
        pending.get(1).accept(Map.of("gimp", "current endpoint")); drain();
        assertEquals("current endpoint", cache.snapshot().get("gimp"));
        assertEquals(notifications + 1, changes);
    }

    @Test public void detachDoesNotCancelOtherConsumerOrDeliverToRecycledView() {
        Runnable detached = watch("gimp");
        watch("gimp"); drain();
        detached.run(); detached.run();
        pending.get(0).accept(Map.of("gimp", "pixels")); drain();
        assertEquals(1, changes);
        assertEquals("pixels", cache.snapshot().get("gimp"));
    }

    @Test public void detachBeforeDispatchDoesNotLoadAnything() {
        watch("gone").run(); drain();
        assertTrue(requests.isEmpty());
    }

    @Test public void refreshRetriesFailuresWithoutBusyLoop() {
        watch("temporary failure"); drain();
        pending.get(0).accept(Map.of()); drain();
        assertEquals(1, requests.size());
        cache.reset(); drain();
        pending.get(1).accept(Map.of("temporary failure", "pixels")); drain();
        assertEquals("pixels", cache.snapshot().get("temporary failure"));
    }

    @Test public void unusedCacheIsBoundedAndActiveArtworkRemainsPinned() {
        var active = watch("active"); drain();
        pending.get(0).accept(Map.of("active", "pixels")); drain();
        for (int i = 1; i <= 5; i++) {
            String key = "idle" + i;
            var release = watch(key); drain();
            pending.get(i).accept(Map.of(key, "pixels")); drain(); release.run();
        }
        assertEquals(3, cache.snapshot().size());
        assertTrue(cache.snapshot().containsKey("active"));
        assertTrue(cache.snapshot().containsKey("idle5"));
        assertFalse(cache.snapshot().containsKey("idle1"));
        active.run();
        assertEquals(2, cache.snapshot().size());
    }

    @Test public void duplicateCompletionCannotOverwritePixelsOrStartConcurrentBatch() {
        watch("first"); drain();
        pending.get(0).accept(Map.of("first", "correct")); drain();
        watch("second"); drain();
        pending.get(0).accept(Map.of("first", "stale")); drain();
        assertEquals("correct", cache.snapshot().get("first"));
        assertEquals(2, requests.size());
        pending.get(1).accept(Map.of("second", "correct")); drain();
        assertEquals("correct", cache.snapshot().get("second"));
    }

    @Test public void loaderFailureIsCachedUntilExplicitRefresh() {
        int[] attempts = {0};
        var failed = new ApplicationIconCache<String, String>(4, 2, (keys, complete) -> {
            attempts[0]++;
            throw new IllegalStateException("source lost");
        }, dispatched::add);
        failed.subscribe("one", () -> { }); drain();
        assertEquals(1, attempts[0]);
        assertTrue(failed.snapshot().containsKey("one"));
        failed.reset(); drain();
        assertEquals(2, attempts[0]);
    }
}
