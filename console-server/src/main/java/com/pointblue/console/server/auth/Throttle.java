package com.pointblue.console.server.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * At most {@code limit} events per key in a sliding {@code window}: failed sign-ins per client address
 * and per typed name, setup-token attempts, probes. Keys idle for a window are forgotten.
 */
public final class Throttle {

    private final int limit;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Deque<Instant>> events = new ConcurrentHashMap<>();

    public Throttle(int limit, Duration window) {
        this(limit, window, Clock.systemUTC());
    }

    Throttle(int limit, Duration window, Clock clock) {
        this.limit = limit;
        this.window = window;
        this.clock = clock;
    }

    /** Whether another event for {@code key} is allowed now (does not record one). */
    public boolean allowed(String key) {
        Deque<Instant> d = events.get(key);
        if (d == null) {
            return true;
        }
        synchronized (d) {
            prune(d);
            return d.size() < limit;
        }
    }

    /** Record an event for {@code key}. */
    public void record(String key) {
        Deque<Instant> d = events.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (d) {
            prune(d);
            d.addLast(clock.instant());
        }
        if (events.size() > 10_000) {
            events.entrySet().removeIf(e -> {
                synchronized (e.getValue()) {
                    prune(e.getValue());
                    return e.getValue().isEmpty();
                }
            });
        }
    }

    /** Forget {@code key} (a successful sign-in clears its failures). */
    public void clear(String key) {
        events.remove(key);
    }

    private void prune(Deque<Instant> d) {
        Instant cutoff = clock.instant().minus(window);
        while (!d.isEmpty() && d.peekFirst().isBefore(cutoff)) {
            d.removeFirst();
        }
    }
}
