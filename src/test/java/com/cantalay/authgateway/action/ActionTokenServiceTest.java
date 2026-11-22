package com.cantalay.authgateway.action;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ActionTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-22T10:00:00Z");
    private static final String K1 = "k1:" + b64("k1-secret-k1-secret-k1-secret-k1");
    private static final String K2 = "k2:" + b64("k2-secret-k2-secret-k2-secret-k2");

    private static String b64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static ActionTokenService service(String secrets, Instant now) {
        return new ActionTokenService(secrets, Duration.ofMinutes(60), Duration.ofHours(24), Clock.fixed(now, ZoneOffset.UTC));
    }

    private static InvalidActionTokenException.Reason reason(Runnable call) {
        try {
            call.run();
        } catch (InvalidActionTokenException e) {
            return e.reason();
        }
        throw new AssertionError("token accepted");
    }

    @Test
    void issuesAndVerifiesATokenBoundToRealmAndPurpose() {
        ActionTokenService tokens = service(K1, NOW);
        String token = tokens.issue("todogi", ActionPurpose.RESET, "user-1", "fp");

        ActionToken verified = tokens.verify(token, "todogi", ActionPurpose.RESET);
        assertThat(verified.subject()).isEqualTo("user-1");
        assertThat(verified.fingerprint()).isEqualTo("fp");
        assertThat(verified.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(60)).getEpochSecond());

        assertThat(reason(() -> tokens.verify(token, "vitafinder", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
        assertThat(reason(() -> tokens.verify(token, "todogi", ActionPurpose.VERIFY))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
    }

    @Test
    void payloadIsVersionedJsonWithKeyId() {
        String token = service(K1, NOW).issue("todogi", ActionPurpose.VERIFY, "user-1", "fp");
        String payload = new String(Base64.getUrlDecoder().decode(token.substring(0, token.indexOf('.'))), StandardCharsets.UTF_8);

        assertThat(payload).isEqualTo("{\"v\":1,\"kid\":\"k1\",\"realm\":\"todogi\",\"purpose\":\"verify\",\"sub\":\"user-1\",\"exp\":"
                + NOW.plus(Duration.ofHours(24)).getEpochSecond() + ",\"fp\":\"fp\"}");
    }

    @Test
    void verifyTokensLiveADayResetTokensAnHour() {
        ActionTokenService tokens = service(K1, NOW);
        String reset = tokens.issue("todogi", ActionPurpose.RESET, "u", "fp");
        String verify = tokens.issue("todogi", ActionPurpose.VERIFY, "u", "fp");

        ActionTokenService after61Minutes = service(K1, NOW.plus(Duration.ofMinutes(61)));
        assertThat(reason(() -> after61Minutes.verify(reset, "todogi", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.EXPIRED);
        assertThat(after61Minutes.verify(verify, "todogi", ActionPurpose.VERIFY).subject()).isEqualTo("u");
        assertThat(reason(() -> service(K1, NOW.plus(Duration.ofHours(24))).verify(verify, "todogi", ActionPurpose.VERIFY)))
                .isEqualTo(InvalidActionTokenException.Reason.EXPIRED);
    }

    @Test
    void rotationKeepsOldLinksWorkingAndUnknownKeysFail() {
        String oldToken = service(K1, NOW).issue("todogi", ActionPurpose.RESET, "u", "fp");

        ActionTokenService rotated = service(K2 + "," + K1, NOW);
        assertThat(rotated.verify(oldToken, "todogi", ActionPurpose.RESET).subject()).isEqualTo("u");
        String newToken = rotated.issue("todogi", ActionPurpose.RESET, "u", "fp");
        assertThat(new String(Base64.getUrlDecoder().decode(newToken.substring(0, newToken.indexOf('.'))), StandardCharsets.UTF_8))
                .contains("\"kid\":\"k2\"");

        ActionTokenService oldKeyDropped = service(K2, NOW);
        assertThat(reason(() -> oldKeyDropped.verify(oldToken, "todogi", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
        // Same secret under another key id: the payload's kid must match the key that verified it.
        ActionTokenService renamed = service("k9:" + K1.substring(3), NOW);
        assertThat(reason(() -> renamed.verify(oldToken, "todogi", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
    }

    @Test
    void rejectsOverlongAndMalformedTokens() {
        ActionTokenService tokens = service(K1, NOW);
        String token = tokens.issue("todogi", ActionPurpose.RESET, "u", "fp");

        assertThat(reason(() -> tokens.verify(token + "a".repeat(ActionTokenService.MAX_LENGTH), "todogi", ActionPurpose.RESET)))
                .isEqualTo(InvalidActionTokenException.Reason.INVALID);
        for (String bad : new String[]{null, "", ".", "a.", ".a", "a.b.c", "!!!.???", token + ".x", token.replace('.', '-')}) {
            assertThat(reason(() -> tokens.verify(bad, "todogi", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
        }
    }

    @Test
    void invalidKeyConfigurationDisablesTokensWithoutLeakingSecrets() {
        assertThat(service("", NOW).isConfigured()).isFalse();
        assertThat(service("k1:" + b64("short"), NOW).isConfigured()).isFalse();
        assertThat(service("k1:" + b64("k1-secret-k1-secret-k1-secret-k1") + ",k1:" + b64("k2-secret-k2-secret-k2-secret-k2"), NOW).isConfigured()).isFalse();
        assertThat(service("no-colon", NOW).isConfigured()).isFalse();
        assertThat(service("bad kid:" + b64("k1-secret-k1-secret-k1-secret-k1"), NOW).isConfigured()).isFalse();
        assertThat(service(K1, NOW).isConfigured()).isTrue();
        assertThat(ActionTokenService.parseKeys(K1).toString()).doesNotContain("secret");

        assertThatThrownBy(() -> service("", NOW).issue("todogi", ActionPurpose.RESET, "u", "fp")).isInstanceOf(IllegalStateException.class);
    }

    /** Golden vector minted by scripts/smoke-gateway.sh's Python code: the formats must stay identical. */
    @Test
    void acceptsTokensMintedByTheSmokeScript() {
        String minted = "eyJ2IjoxLCJraWQiOiJrMSIsInJlYWxtIjoidG9kb2dpIiwicHVycG9zZSI6InJlc2V0Iiwic3ViIjoidXNlci0xIiwiZXhwIjo0MTAyNDQ0ODAwLCJmcCI6IkJQa1llWTMtUWlUcVhkaVZJWERsYUxJQV9pcVktMFBpX2VOTjVnTVQ5dHcifQ.6rEWHLdkiN1gTK8LpL9FYKbNddFazc_ShdiPjwL5zEw";
        ActionToken verified = service(K1, NOW).verify(minted, "todogi", ActionPurpose.RESET);

        assertThat(verified.subject()).isEqualTo("user-1");
        assertThat(verified.fingerprint()).isEqualTo(ActionTokenService.fingerprint("password", "cred-1", "1700000000000"));
    }

    @Test
    void nonCanonicalBase64IsRejected() {
        ActionTokenService tokens = service(K1, NOW);
        String token = tokens.issue("todogi", ActionPurpose.RESET, "u", "fp");
        // 'A' and 'B' differ only in the unused low bits of a 32-byte signature's last character
        char last = token.charAt(token.length() - 1);
        String alias = token.substring(0, token.length() - 1) + (char) (last ^ 1);

        assertThat(reason(() -> tokens.verify(alias, "todogi", ActionPurpose.RESET))).isEqualTo(InvalidActionTokenException.Reason.INVALID);
    }

    @Test
    void emailFingerprintIgnoresCaseAndSpaces() {
        assertThat(ActionTokenService.emailFingerprint(" Can@Ornek.com ")).isEqualTo(ActionTokenService.emailFingerprint("can@ornek.com"));
        assertThat(ActionTokenService.emailFingerprint("can@ornek.com")).isNotEqualTo(ActionTokenService.emailFingerprint("can2@ornek.com"));
    }
}
