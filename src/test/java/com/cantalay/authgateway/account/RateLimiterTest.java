package com.cantalay.authgateway.account;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterTest {

    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-22T10:00:00Z");

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    @Test
    void slidingWindowPerKey() {
        MutableClock clock = new MutableClock();
        RateLimiter limiter = new RateLimiter(clock);
        RateLimiter.Limit threePerHour = new RateLimiter.Limit(3, Duration.ofHours(1));

        assertThat(limiter.tryAcquire("a", threePerHour)).isTrue();
        assertThat(limiter.tryAcquire("a", threePerHour)).isTrue();
        clock.now = clock.now.plus(Duration.ofMinutes(30));
        assertThat(limiter.tryAcquire("a", threePerHour)).isTrue();
        assertThat(limiter.tryAcquire("a", threePerHour)).isFalse();
        assertThat(limiter.tryAcquire("b", threePerHour)).isTrue();

        clock.now = clock.now.plus(Duration.ofMinutes(31)); // first two left the window
        assertThat(limiter.tryAcquire("a", threePerHour)).isTrue();
        assertThat(limiter.tryAcquire("a", threePerHour)).isTrue();
        assertThat(limiter.tryAcquire("a", threePerHour)).isFalse();
    }

    @Test
    void everyLimitMustHaveRoomAndRejectionsAreNotCounted() {
        MutableClock clock = new MutableClock();
        RateLimiter limiter = new RateLimiter(clock);
        RateLimiter.Limit perMinute = new RateLimiter.Limit(1, Duration.ofMinutes(1));
        RateLimiter.Limit perHour = new RateLimiter.Limit(5, Duration.ofHours(1));

        assertThat(limiter.tryAcquire("r", perMinute, perHour)).isTrue();
        assertThat(limiter.tryAcquire("r", perMinute, perHour)).isFalse();
        for (int i = 0; i < 4; i++) {
            clock.now = clock.now.plus(Duration.ofSeconds(61));
            assertThat(limiter.tryAcquire("r", perMinute, perHour)).isTrue();
        }
        clock.now = clock.now.plus(Duration.ofSeconds(61));
        assertThat(limiter.tryAcquire("r", perMinute, perHour)).isFalse(); // sixth in the hour
    }

    @Test
    void forgetsIdleKeys() {
        MutableClock clock = new MutableClock();
        RateLimiter limiter = new RateLimiter(clock);
        RateLimiter.Limit limit = new RateLimiter.Limit(1, Duration.ofMinutes(1));
        for (int i = 0; i < 1000; i++) {
            limiter.tryAcquire("k" + i, limit);
        }
        clock.now = clock.now.plus(Duration.ofHours(2));
        for (int i = 0; i < 100; i++) {
            limiter.tryAcquire("fresh" + i, limit);
        }
        assertThat(limiter.size()).isLessThan(1000);
    }
}
