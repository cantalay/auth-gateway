package com.cantalay.authgateway.action;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Stateless, signed single-purpose tokens for links in emails (password reset, email confirmation).
 * <p>
 * Format: {@code base64url(JSON payload) + "." + base64url(HMAC-SHA256(key[kid], payload))}, at most
 * {@value #MAX_LENGTH} characters. Payload: {@code {v:1, kid, realm, purpose, sub, exp, fp}}.
 * <p>
 * Keys come from {@code GATEWAY_ACTION_TOKEN_SECRETS="k2:<base64 32+ bytes>,k1:<...>"}: the first key signs, every key
 * verifies, so keys rotate without breaking links in flight (add the new key first, drop the old one after the longest
 * token lifetime). Without keys the gateway issues no tokens and the realm features that need them stay off.
 * <p>
 * Single use comes from the fingerprint ({@code fp}) the caller derives from account state that the action changes
 * (password credential, email address). Tokens never appear in logs.
 */
@Service
public class ActionTokenService {

    public static final int MAX_LENGTH = 512;
    private static final int VERSION = 1;
    private static final int MIN_KEY_BYTES = 32;
    private static final Pattern KID = Pattern.compile("[A-Za-z0-9]{1,16}");
    private static final Logger log = LoggerFactory.getLogger(ActionTokenService.class);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final List<Key> keys;
    private final Clock clock;
    private final Duration resetTtl;
    private final Duration verifyTtl;
    private final JsonMapper json = JsonMapper.builder().build();

    @Autowired
    public ActionTokenService(@Value("${gateway.action-token.secrets:}") String secrets,
                              @Value("${gateway.action-token.reset-ttl:60m}") Duration resetTtl,
                              @Value("${gateway.action-token.verify-ttl:24h}") Duration verifyTtl,
                              Clock clock) {
        this.keys = parseKeys(secrets);
        this.resetTtl = resetTtl;
        this.verifyTtl = verifyTtl;
        this.clock = clock;
    }

    /** Whether tokens can be issued (at least one valid key). */
    public boolean isConfigured() {
        return !keys.isEmpty();
    }

    public Duration ttl(ActionPurpose purpose) {
        return purpose == ActionPurpose.RESET ? resetTtl : verifyTtl;
    }

    public String issue(String realm, ActionPurpose purpose, String subject, String fingerprint) {
        if (keys.isEmpty()) {
            throw new IllegalStateException("No action token key configured");
        }
        Key key = keys.get(0);
        long exp = clock.instant().plus(ttl(purpose)).getEpochSecond();
        byte[] payload = json.writeValueAsBytes(new Payload(VERSION, key.id, realm, purpose.value(), subject, exp, fingerprint));
        String body = B64.encodeToString(payload);
        String token = body + "." + B64.encodeToString(key.sign(body));
        if (token.length() > MAX_LENGTH) {
            throw new IllegalStateException("Action token longer than " + MAX_LENGTH);
        }
        return token;
    }

    /**
     * Checks signature, realm, purpose and expiry; the fingerprint is left to the caller.
     *
     * @throws InvalidActionTokenException for anything that is not a live token of this realm and purpose
     */
    public ActionToken verify(String token, String realm, ActionPurpose purpose) {
        if (token == null || token.isEmpty() || token.length() > MAX_LENGTH) {
            throw invalid();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.') || dot == token.length() - 1) {
            throw invalid();
        }
        String body = token.substring(0, dot);
        String encodedSignature = token.substring(dot + 1);
        byte[] signature;
        byte[] payloadBytes;
        try {
            signature = B64D.decode(encodedSignature);
            payloadBytes = B64D.decode(body);
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
        // The decoder ignores the unused low bits of the last character; only the canonical encoding is accepted, so
        // every changed character invalidates the token.
        if (!B64.encodeToString(signature).equals(encodedSignature) || !B64.encodeToString(payloadBytes).equals(body)) {
            throw invalid();
        }
        // Every key is tried (there are only a few) so unauthenticated input is never parsed.
        Key signer = null;
        for (Key key : keys) {
            if (MessageDigest.isEqual(key.sign(body), signature)) {
                signer = key;
            }
        }
        if (signer == null) {
            throw invalid();
        }
        Payload payload;
        try {
            payload = json.readValue(payloadBytes, Payload.class);
        } catch (RuntimeException e) {
            throw invalid();
        }
        if (payload.v() != VERSION || !signer.id.equals(payload.kid())
                || !realm.equals(payload.realm()) || !purpose.value().equals(payload.purpose())
                || payload.sub() == null || payload.sub().isEmpty() || payload.fp() == null) {
            throw invalid();
        }
        if (clock.instant().getEpochSecond() >= payload.exp()) {
            throw new InvalidActionTokenException(InvalidActionTokenException.Reason.EXPIRED);
        }
        return new ActionToken(payload.realm(), purpose, payload.sub(), payload.exp(), payload.fp());
    }

    /** {@code base64url(sha256(parts joined by '\n'))}: compact fingerprint of account state. */
    public static String fingerprint(String... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return B64.encodeToString(digest.digest(String.join("\n", parts).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String emailFingerprint(String email) {
        return fingerprint("email", email == null ? "" : email.trim().toLowerCase(Locale.ROOT));
    }

    private static InvalidActionTokenException invalid() {
        return new InvalidActionTokenException(InvalidActionTokenException.Reason.INVALID);
    }

    static List<Key> parseKeys(String secrets) {
        if (secrets == null || secrets.isBlank()) {
            return List.of();
        }
        List<Key> parsed = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        for (String entry : secrets.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            String id = colon > 0 ? trimmed.substring(0, colon) : "";
            byte[] secret = colon > 0 ? decodeSecret(trimmed.substring(colon + 1)) : null;
            if (!KID.matcher(id).matches() || secret == null || secret.length < MIN_KEY_BYTES || !ids.add(id)) {
                // Never print the value; a broken key list disables the token features instead of the whole gateway.
                log.error("GATEWAY_ACTION_TOKEN_SECRETS is invalid (expected kid:<base64 of 32+ bytes>, unique kids); "
                        + "password reset and email confirmation links are disabled");
                return List.of();
            }
            parsed.add(new Key(id, secret));
        }
        return Collections.unmodifiableList(parsed);
    }

    private static byte[] decodeSecret(String value) {
        String v = value.trim();
        try {
            return Base64.getDecoder().decode(v);
        } catch (IllegalArgumentException e) {
            try {
                return Base64.getUrlDecoder().decode(v);
            } catch (IllegalArgumentException e2) {
                return null;
            }
        }
    }

    @JsonPropertyOrder({"v", "kid", "realm", "purpose", "sub", "exp", "fp"})
    record Payload(int v, String kid, String realm, String purpose, String sub, long exp, String fp) {
    }

    static final class Key {
        final String id;
        private final SecretKeySpec spec;

        Key(String id, byte[] secret) {
            this.id = id;
            this.spec = new SecretKeySpec(secret, "HmacSHA256");
        }

        byte[] sign(String body) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(spec);
                return mac.doFinal(body.getBytes(StandardCharsets.US_ASCII));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String toString() {
            return "Key[" + id + "]";
        }
    }
}
