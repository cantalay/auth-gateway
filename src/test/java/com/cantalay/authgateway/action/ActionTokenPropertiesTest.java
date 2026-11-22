package com.cantalay.authgateway.action;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.RepetitionInfo;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Property-style tests: each repetition draws inputs from a {@link Random} seeded with the repetition number, so a
 * failure names a reproducible case.
 */
class ActionTokenPropertiesTest {

    private static final String SECRETS = "k2:" + Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII))
            + ",k1:" + Base64.getEncoder().encodeToString(new byte[40]);
    private static final Instant NOW = Instant.parse("2026-11-22T10:00:00Z");
    private static final String TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";

    private static ActionTokenService service(Instant now) {
        return new ActionTokenService(SECRETS, Duration.ofMinutes(60), Duration.ofHours(24), Clock.fixed(now, ZoneOffset.UTC));
    }

    private static String randomString(Random random, String alphabet, int min, int max) {
        int length = min + random.nextInt(max - min + 1);
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return out.toString();
    }

    @RepeatedTest(300)
    void roundTripsRandomPayloads(RepetitionInfo info) {
        Random random = new Random(info.getCurrentRepetition());
        String realm = randomString(random, "abcdefghijklmnopqrstuvwxyz0123456789", 1, 24);
        String subject = random.nextBoolean() ? UUID.randomUUID().toString()
                : randomString(random, "abcdefghijklmnopqrstuvwxyz0123456789-", 1, 64);
        String fingerprint = ActionTokenService.fingerprint(randomString(random, TOKEN_ALPHABET, 0, 80));
        ActionPurpose purpose = random.nextBoolean() ? ActionPurpose.RESET : ActionPurpose.VERIFY;
        ActionTokenService tokens = service(NOW);

        String token = tokens.issue(realm, purpose, subject, fingerprint);

        assertThat(token.length()).isLessThanOrEqualTo(ActionTokenService.MAX_LENGTH);
        ActionToken verified = tokens.verify(token, realm, purpose);
        assertThat(verified.subject()).isEqualTo(subject);
        assertThat(verified.fingerprint()).isEqualTo(fingerprint);
        assertThat(verified.realm()).isEqualTo(realm);
        assertThat(verified.purpose()).isEqualTo(purpose);
    }

    @RepeatedTest(1000)
    void anyChangedCharacterIsRejected(RepetitionInfo info) {
        Random random = new Random(info.getCurrentRepetition());
        ActionTokenService tokens = service(NOW);
        String token = tokens.issue("todogi", ActionPurpose.RESET, UUID.nameUUIDFromBytes(new byte[]{1}).toString(),
                ActionTokenService.fingerprint("password", "id", "1"));
        int i = random.nextInt(token.length());
        char replacement = TOKEN_ALPHABET.charAt(random.nextInt(TOKEN_ALPHABET.length()));
        if (token.charAt(i) == replacement) {
            return;
        }
        String tampered = token.substring(0, i) + replacement + token.substring(i + 1);

        assertThatThrownBy(() -> tokens.verify(tampered, "todogi", ActionPurpose.RESET))
                .isInstanceOf(InvalidActionTokenException.class);
    }

    @RepeatedTest(500)
    void anyChangedByteOfTheSignedPayloadIsRejected(RepetitionInfo info) {
        Random random = new Random(info.getCurrentRepetition());
        ActionTokenService tokens = service(NOW);
        String token = tokens.issue("todogi", ActionPurpose.VERIFY, "user", ActionTokenService.emailFingerprint("a@b.co"));
        String[] parts = token.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[0]);
        payload[random.nextInt(payload.length)] ^= (byte) (1 + random.nextInt(255));
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." + parts[1];

        assertThatThrownBy(() -> tokens.verify(tampered, "todogi", ActionPurpose.VERIFY))
                .isInstanceOf(InvalidActionTokenException.class);
    }

    @RepeatedTest(300)
    void expiryIsExactAtTheBoundary(RepetitionInfo info) {
        Random random = new Random(info.getCurrentRepetition());
        int offsetSeconds = random.nextInt(7201) - 3600;
        String token = service(NOW).issue("todogi", ActionPurpose.RESET, "user", "fp");
        ActionTokenService later = service(NOW.plus(Duration.ofMinutes(60)).plusSeconds(offsetSeconds));

        if (offsetSeconds < 0) {
            assertThat(later.verify(token, "todogi", ActionPurpose.RESET).subject()).isEqualTo("user");
        } else {
            assertThatThrownBy(() -> later.verify(token, "todogi", ActionPurpose.RESET))
                    .isInstanceOf(InvalidActionTokenException.class)
                    .satisfies(e -> assertThat(((InvalidActionTokenException) e).reason())
                            .isEqualTo(InvalidActionTokenException.Reason.EXPIRED));
        }
    }

    @RepeatedTest(500)
    void garbageIsRejectedNeverThrownOtherwise(RepetitionInfo info) {
        Random random = new Random(info.getCurrentRepetition());
        String garbage = random.nextInt(4) == 0
                ? randomString(random, TOKEN_ALPHABET, 0, 600)
                : randomString(random, TOKEN_ALPHABET.replace(".", ""), 1, 200) + "." + randomString(random, TOKEN_ALPHABET.replace(".", ""), 1, 60);

        assertThatThrownBy(() -> service(NOW).verify(garbage, "todogi", ActionPurpose.RESET))
                .isInstanceOf(InvalidActionTokenException.class);
    }
}
