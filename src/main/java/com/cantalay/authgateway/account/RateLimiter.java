package com.cantalay.authgateway.account;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory sliding-window limits for the account email actions. Per pod: the gateway runs one replica; with more
 * replicas the limits apply per replica (a shared store would be needed). Keys are hashed so no email address is kept.
 */
@Component
public class RateLimiter {

    /** One limit: at most {@code max} accepted events per {@code window}. */
    public record Limit(int max, Duration window) {
    }

    private static final int SWEEP_EVERY = 1024;
    private static final Duration LONGEST_WINDOW = Duration.ofHours(1);

    private final Clock clock;
    private final Map<String, Deque<Long>> events = new ConcurrentHashMap<>();
    private final AtomicInteger calls = new AtomicInteger();

    public RateLimiter(Clock clock) {
        this.clock = clock;
    }

    /**
     * Records an event for {@code key} when every limit still has room; otherwise records nothing.
     *
     * @return whether the event is allowed
     */
    public boolean tryAcquire(String key, Limit... limits) {
        long now = clock.millis();
        if (calls.incrementAndGet() % SWEEP_EVERY == 0) {
            sweep(now);
        }
        Deque<Long> log = events.computeIfAbsent(hash(key), k -> new ArrayDeque<>());
        synchronized (log) {
            long longest = 0;
            for (Limit limit : limits) {
                longest = Math.max(longest, limit.window().toMillis());
            }
            while (!log.isEmpty() && log.peekFirst() <= now - longest) {
                log.pollFirst();
            }
            for (Limit limit : limits) {
                long from = now - limit.window().toMillis();
                int inWindow = 0;
                for (var it = log.descendingIterator(); it.hasNext(); ) {
                    if (it.next() > from) {
                        inWindow++;
                    } else {
                        break;
                    }
                }
                if (inWindow >= limit.max()) {
                    return false;
                }
            }
            log.addLast(now);
            return true;
        }
    }

    private void sweep(long now) {
        long horizon = now - LONGEST_WINDOW.toMillis();
        events.entrySet().removeIf(entry -> {
            synchronized (entry.getValue()) {
                Long last = entry.getValue().peekLast();
                return last == null || last <= horizon;
            }
        });
    }

    int size() {
        return events.size();
    }

    private static String hash(String key) {
        try {
            return Base64.getEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
