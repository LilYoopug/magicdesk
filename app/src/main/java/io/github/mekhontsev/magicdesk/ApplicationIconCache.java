package io.github.mekhontsev.magicdesk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/** Single-threaded demand registry. Detached artwork is bounded; active consumers stay pinned. */
final class ApplicationIconCache<K, T> {
    interface Loader<K, T> { void load(List<K> keys, Consumer<Map<K, T>> complete); }

    private final int batchSize, retained;
    private final Loader<K, T> loader;
    private final Consumer<Runnable> dispatch;
    private final Map<K, List<Runnable>> consumers = new LinkedHashMap<>();
    private final LinkedHashMap<K, T> values = new LinkedHashMap<>(16, .75f, true);
    private volatile Map<K, T> snapshot = Map.of();
    private long generation, sequence, inFlight;
    private boolean loading, queued;

    ApplicationIconCache(int batchSize, int retained, Loader<K, T> loader, Consumer<Runnable> dispatch) {
        if (batchSize < 1 || retained < 0) throw new IllegalArgumentException("Invalid icon cache limits");
        this.batchSize = batchSize;
        this.retained = retained;
        this.loader = loader;
        this.dispatch = dispatch;
    }

    Map<K, T> snapshot() { return snapshot; }

    Runnable subscribe(K key, Runnable changed) {
        consumers.computeIfAbsent(key, ignored -> new ArrayList<>()).add(changed);
        values.get(key); // Touch the retained entry, without I/O in a view binding.
        enqueue();
        return new Runnable() {
            private boolean closed;
            @Override public void run() {
                if (closed) return;
                closed = true;
                var listeners = consumers.get(key);
                listeners.remove(changed);
                if (listeners.isEmpty()) consumers.remove(key);
                trim();
            }
        };
    }

    void reset() {
        generation++;
        inFlight = 0;
        loading = false;
        values.clear();
        snapshot = Map.of();
        var listeners = consumers.values().stream().flatMap(List::stream).toList();
        listeners.forEach(Runnable::run);
        enqueue();
    }

    private void enqueue() {
        if (queued) return;
        queued = true;
        dispatch.accept(() -> { queued = false; loadNext(); });
    }

    private void loadNext() {
        if (loading) return;
        var batch = consumers.keySet().stream().filter(key -> !values.containsKey(key)).limit(batchSize).toList();
        if (batch.isEmpty()) return;
        loading = true;
        long epoch = generation, request = ++sequence;
        inFlight = request;
        Consumer<Map<K, T>> complete = result -> {
            if (epoch != generation || request != inFlight) return;
            inFlight = 0;
            // Misses and read failures are bounded to this source epoch; refresh/reconnect retries them.
            for (K key : batch) values.put(key, result.get(key));
            loading = false;
            trim();
            snapshot = Collections.unmodifiableMap(new LinkedHashMap<>(values));
            for (K key : batch) for (Runnable listener : List.copyOf(consumers.getOrDefault(key, List.of())))
                listener.run();
            enqueue();
        };
        try { loader.load(batch, complete); }
        catch (RuntimeException error) { complete.accept(Map.of()); }
    }

    private void trim() {
        int idle = 0;
        for (K key : values.keySet()) if (!consumers.containsKey(key)) idle++;
        boolean changed = false;
        for (var iterator = values.keySet().iterator(); idle > retained && iterator.hasNext();) {
            if (!consumers.containsKey(iterator.next())) { iterator.remove(); idle--; changed = true; }
        }
        if (changed) snapshot = Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }
}
