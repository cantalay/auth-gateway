package com.cantalay.authgateway.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory sliding-window limits for the account endpoints. Per pod: the gateway runs one replica; with more replicas
 * the limits apply per replica (a shared store would be needed). Keys are hashed so no email address is kept.
 * <p>
 * Bounded: at most {@code maxKeys} keys in access order (LRU). Each call evicts at most two idle keys from the cold end,
 * so cleanup never walks the whole map on the request path; when the map is full the least recently used key goes.
 */
@Component
public class RateLimiter {

    /** One limit: at most {@code max} accepted events per {@code window}. */
    public record Limit(int max, Duration window) {
    }

    public static final int DEFAULT_MAX_KEYS = 50_000;
    private static final Duration LONGEST_WINDOW = Duration.ofHours(1);
    private static final int EVICT_PER_CALL = 2;

    private final Clock clock;
    private final int maxKeys;
    private final LinkedHashMap<String, Deque<Long>> events;

    public RateLimiter(Clock clock) {
        this(clock, DEFAULT_MAX_KEYS);
    }

    @Autowired
    public RateLimiter(Clock clock, @Value("${gateway.rate-limit.max-keys:" + DEFAULT_MAX_KEYS + "}") int maxKeys) {
        this.clock = clock;
        this.maxKeys = maxKeys;
        this.events = new LinkedHashMap<>(1024, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Deque<Long>> eldest) {
                return size() > RateLimiter.this.maxKeys;
            }
        };
    }

    /**
     * Records an event for {@code key} when every limit still has room; otherwise records nothing.
     *
     * @return whether the event is allowed
     */
    public synchronized boolean tryAcquire(String key, Limit... limits) {
        long now = clock.millis();
        evictIdle(now);
        Deque<Long> log = events.computeIfAbsent(hash(key), k -> new ArrayDeque<>());
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
            for (Iterator<Long> it = log.descendingIterator(); it.hasNext(); ) {
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

    /** Removes up to {@value #EVICT_PER_CALL} least recently used keys whose events all left the longest window. */
    private void evictIdle(long now) {
        long horizon = now - LONGEST_WINDOW.toMillis();
        Iterator<Map.Entry<String, Deque<Long>>> it = events.entrySet().iterator();
        for (int i = 0; i < EVICT_PER_CALL && it.hasNext(); i++) {
            Long last = it.next().getValue().peekLast();
            if (last == null || last <= horizon) {
                it.remove();
            } else {
                return;
            }
        }
    }

    synchronized int size() {
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
