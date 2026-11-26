package com.cantalay.authgateway.identity;

import com.cantalay.authgateway.account.RateLimiter;
import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.domain.IdentitiesResponse;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.KeycloakUserSessionDto;
import com.cantalay.authgateway.domain.LogoutRequest;
import com.cantalay.authgateway.domain.SocialLoginRequest;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import feign.FeignException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

/**
 * Sign-in methods of an account (ToDoGi İP-06 §2.9): which methods the signed-in user has, removing a provider, adding
 * one from a signed-in session ({@code /social} with {@code mode=link}), and refusing social sign-in into an account
 * whose email address nobody has confirmed.
 * <p>
 * Opt-in per realm ({@link RealmConfig#identityMethods()}). Off, {@code identities} and {@code mode=link} answer 404
 * {@code realm_feature_disabled} and {@code /social} behaves exactly as before (any other {@code mode} is ignored).
 * <p>
 * Keycloak decides the linking (talay-identity {@code social-first-login} with talay-keycloak-providers
 * {@code idp-auto-link-verified-only}, and {@code social-post-login} with {@code idp-unverified-account-guard}): a
 * provider is linked automatically only to an account whose email is confirmed, otherwise the app's redirect gets
 * {@code error_description=account_exists_unverified} and no code ({@code /social} with {@code error} translates it,
 * for every realm). What the gateway still checks when it gets a code is a second line, for realms whose Keycloak flow
 * is older or links by itself ({@code idp-auto-link}):
 * <ul>
 *     <li>sign-in that resolves to an account with a password and an unconfirmed email, whatever its links: the
 *     session is ended (admin API by {@code sid}, online and offline, so neither the tokens nor the browser's SSO cookie
 *     can be used) and the answer is 409 {@code account_exists_unverified}. Links are not touched;</li>
 *     <li>{@code mode=link} needs proof: the code's session must come from a sign-in with the requested
 *     {@code provider} ({@code identity_provider} claim, talay-identity user session note mapper) made at most
 *     {@link #FRESH_SIGN_IN} ago ({@code auth_time}); otherwise 409 {@code identity_unproven}. A code of the signed-in
 *     user that passes is the link (no admin call after it, so no 503 after Keycloak linked). A code of another user:
 *     the new session is ended and the signed-in user is left alone. A user Keycloak created for exactly this sign-in
 *     (its only session is the code's {@code sid}, created within {@link #CREATED_WITH_SIGN_IN} of {@code auth_time},
 *     no password, the one provider) is deleted: 409 {@code identity_mismatch} (503 when the deletion fails); any
 *     other user: 409 {@code identity_in_use}.</li>
 * </ul>
 * Nothing here marks an email confirmed: a provider link is no proof that whoever set the account's password owns the
 * address.
 * <p>
 * Metric: {@code auth_gateway_identity_requests_total{realm, action=list|unlink|link|login, result}}.
 */
@Service
public class IdentityMethodsService {

    /** A {@code mode=link} code must come from a provider sign-in at most this old ({@code auth_time}). */
    static final Duration FRESH_SIGN_IN = Duration.ofMinutes(2);
    /** A user counts as created by the sign-in when its creation is this close to the sign-in's {@code auth_time}. */
    static final Duration CREATED_WITH_SIGN_IN = Duration.ofSeconds(5);
    static final RateLimiter.Limit LIST_PER_USER = new RateLimiter.Limit(30, Duration.ofMinutes(1));
    static final RateLimiter.Limit UNLINK_PER_USER = new RateLimiter.Limit(10, Duration.ofMinutes(10));
    static final int LOCK_STRIPES = 64;
    static final String MODE_LOGIN = "login";
    static final String MODE_LINK = "link";

    private static final Logger log = LoggerFactory.getLogger(IdentityMethodsService.class);
    /** {@link #justCreated}: how recent the account must be to count as created by this sign-in. */
    static final Duration NEW_ACCOUNT_WINDOW = Duration.ofMinutes(10);

    private final AuthAdminService adminService;
    private final AuthService authService;
    private final KeycloakAdminClient admin;
    private final MeterRegistry meters;
    private final Clock clock;
    private final RateLimiter limiter;
    /** Called once a social sign-in has just created the account (welcome email); optional. */
    private SocialSignupHook signupHook;
    /** One removal at a time per user, so two parallel removals cannot take away the last two methods. */
    private final ReentrantLock[] userLocks = new ReentrantLock[LOCK_STRIPES];

    @Autowired
    public IdentityMethodsService(AuthAdminService adminService, AuthService authService, KeycloakAdminClient admin,
                                  MeterRegistry meters, Clock clock, RateLimiter limiter) {
        this.adminService = adminService;
        this.authService = authService;
        this.admin = admin;
        this.meters = meters;
        this.clock = clock;
        this.limiter = limiter;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            userLocks[i] = new ReentrantLock();
        }
    }

    public IdentityMethodsService(AuthAdminService adminService, AuthService authService, KeycloakAdminClient admin,
                                  MeterRegistry meters, Clock clock) {
        this(adminService, authService, admin, meters, clock, new RateLimiter(clock));
    }

    @Autowired(required = false)
    public void setSignupHook(SocialSignupHook signupHook) {
        this.signupHook = signupHook;
    }

    /**
     * Keycloak created the account during this sign-in (first broker login): created moments ago. The window covers the
     * provider round trip (Apple / Google consent) and clock skew; a later sign-in finds an older account.
     */
    boolean justCreated(KeycloakUserDto user) {
        Long created = user == null ? null : user.createdTimestamp();
        return created != null && clock.millis() - created <= NEW_ACCOUNT_WINDOW.toMillis();
    }

    /* ======================= identities ======================= */

    public IdentitiesResponse list(RealmConfig realm, String userId) {
        require(realm, "list");
        limit(realm, "list", userId, LIST_PER_USER);
        String token = adminToken(realm, "list");
        try {
            boolean password = hasPassword(realm, token, userId);
            List<IdentitiesResponse.Provider> providers = identities(realm, token, userId).stream()
                    .map(identity -> new IdentitiesResponse.Provider(identity.identityProvider(), emailOf(identity)))
                    .toList();
            count(realm, "list", "ok");
            return new IdentitiesResponse(password, providers);
        } catch (FeignException e) {
            throw adminError(realm, "list", e);
        }
    }

    /** Idempotent: a provider that is not linked is not an error. */
    public void unlink(RealmConfig realm, String userId, String alias) {
        require(realm, "unlink");
        limit(realm, "unlink", userId, UNLINK_PER_USER);
        String token = adminToken(realm, "unlink");
        ReentrantLock lock = userLocks[Math.floorMod((realm.name() + "|" + userId).hashCode(), LOCK_STRIPES)];
        lock.lock();
        try {
            List<KeycloakFederatedIdentityDto> linked = identities(realm, token, userId);
            if (linked.stream().noneMatch(identity -> alias.equals(identity.identityProvider()))) {
                count(realm, "unlink", "not_linked");
                return;
            }
            if (linked.size() == 1 && !hasPassword(realm, token, userId)) {
                count(realm, "unlink", "last_method");
                throw new BaseAuthException(AuthError.LAST_METHOD);
            }
            try {
                admin.removeFederatedIdentity(realm.name(), userId, alias, bearer(token));
            } catch (FeignException.NotFound e) {
                // already gone
            }
            count(realm, "unlink", "ok");
            log.info("Identity provider {} unlinked in realm {} for user {}", alias, realm.name(), userId);
        } catch (FeignException e) {
            throw adminError(realm, "unlink", e);
        } finally {
            lock.unlock();
        }
    }

    /* ======================= social sign-in ======================= */

    /**
     * {@code POST /social}: sign-in ({@code mode} absent or {@code login}) or linking ({@code mode=link}, with the
     * account's Bearer token). A request with {@code error} (Keycloak refused the sign-in) is translated before.
     *
     * @param bearer the request's access token; {@code null} without one
     */
    public TokenResponseDto social(RealmConfig realm, Jwt bearer, SocialLoginRequest request) {
        String mode = StringUtils.hasText(request.mode()) ? request.mode() : null;
        if (!realm.identityMethods()) {
            if (MODE_LINK.equals(mode)) {
                count(realm, "link", "disabled");
                throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
            }
            return authService.socialLogin(realm, request);
        }
        if (mode == null || MODE_LOGIN.equals(mode)) {
            return login(realm, request);
        }
        if (MODE_LINK.equals(mode)) {
            return link(realm, bearer, request);
        }
        throw new BaseAuthException(AuthError.SOCIAL_MODE_INVALID, Map.of("mode", "login|link"));
    }

    /**
     * The app's redirect carried {@code error} instead of a code: Keycloak refused the sign-in (talay-keycloak-providers
     * {@code error_description}) or the user cancelled. Served for every realm, with or without identity methods.
     */
    public BaseAuthException callbackError(RealmConfig realm, SocialLoginRequest request) {
        BaseAuthException error = translateCallbackError(request);
        String action = MODE_LINK.equals(request.mode()) ? "link" : "login";
        count(realm, action, "refused_" + (error.getCode() == null ? "other" : error.getCode()));
        log.info("Social {} in realm {} ended at the provider: error={}, description={}", action, realm.name(),
                printable(request.error()), printable(request.errorDescription()));
        return error;
    }

    /** {@code account_exists_unverified} / {@code account_exists} → 409; {@code access_denied} → cancelled; else failed. */
    public static BaseAuthException translateCallbackError(SocialLoginRequest request) {
        String description = request.errorDescription() == null ? "" : request.errorDescription().strip();
        if (AuthError.ACCOUNT_EXISTS_UNVERIFIED.code().equals(description)) {
            return new BaseAuthException(AuthError.ACCOUNT_EXISTS_UNVERIFIED);
        }
        if (AuthError.ACCOUNT_EXISTS.code().equals(description)) {
            return new BaseAuthException(AuthError.ACCOUNT_EXISTS);
        }
        if ("access_denied".equals(request.error())) {
            return new BaseAuthException(AuthError.SOCIAL_CANCELLED);
        }
        return new BaseAuthException(AuthError.SOCIAL_FAILED);
    }

    /** Client-supplied text in logs: short, no line breaks. */
    private static String printable(String value) {
        if (value == null) {
            return "-";
        }
        String flat = value.replaceAll("[\\r\\n\\t]", " ");
        return flat.length() > 64 ? flat.substring(0, 64) + "…" : flat;
    }

    private TokenResponseDto login(RealmConfig realm, SocialLoginRequest request) {
        TokenResponseDto tokens = exchange(realm, request, "login");
        SignIn signIn = signIn(realm, tokens, "login");
        String token = null;
        try {
            token = adminService.getAdminAccessToken(realm);
            KeycloakUserDto user = admin.getUser(realm.name(), signIn.subject(), bearer(token));
            if (unconfirmedPasswordAccount(realm, token, user)) {
                endSession(realm, "login", token, signIn, tokens);
                count(realm, "login", "unverified");
                log.info("Social sign-in in realm {} refused: account {} ({}) has a password and an unconfirmed email",
                        realm.name(), signIn.subject(), maskEmail(user.email()));
                throw new BaseAuthException(AuthError.ACCOUNT_EXISTS_UNVERIFIED, null, user.email());
            }
            if (signupHook != null && justCreated(user)) {
                signupHook.accountCreated(realm, user);
            }
        } catch (FeignException e) {
            // the account could not be checked: no tokens for it
            endSession(realm, "login", token, signIn, tokens);
            throw adminError(realm, "login", e);
        } catch (BaseAuthException e) {
            throw e;
        } catch (RuntimeException e) {
            endSession(realm, "login", token, signIn, tokens);
            throw e;
        }
        count(realm, "login", "ok");
        return tokens;
    }

    private TokenResponseDto link(RealmConfig realm, Jwt bearer, SocialLoginRequest request) {
        if (bearer == null) {
            count(realm, "link", "unauthenticated");
            throw new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        }
        if (!realm.issuerUri().equals(bearer.getClaimAsString("iss"))) {
            throw new BaseAuthException(AuthError.REALM_MISMATCH);
        }
        String provider = request.provider();
        if (!StringUtils.hasText(provider)) {
            count(realm, "link", "invalid");
            throw new BaseAuthException(AuthError.PROVIDER_REQUIRED, Map.of("provider", "google|apple"));
        }
        String current = bearer.getSubject();
        TokenResponseDto tokens = exchange(realm, request, "link");
        SignIn signIn = signIn(realm, tokens, "link");

        if (!signIn.provenFor(provider, clock)) {
            endSession(realm, "link", null, signIn, tokens);
            count(realm, "link", "unproven");
            log.info("Link in realm {} for user {} refused: the code is not a fresh {} sign-in (provider {}, auth_time {})",
                    realm.name(), current, provider, signIn.identityProvider(), signIn.authTime());
            throw new BaseAuthException(AuthError.IDENTITY_UNPROVEN);
        }
        if (current.equals(signIn.subject())) {
            // Keycloak signed the user in with the provider just now: the provider is linked to this account.
            count(realm, "link", "ok");
            log.info("Identity provider {} linked in realm {} for user {}", provider, realm.name(), current);
            return tokens;
        }

        // Another user: its tokens never leave the gateway, the signed-in user is not touched.
        String resolved = signIn.subject();
        String token = null;
        boolean sessionOpen = true;
        try {
            token = adminService.getAdminAccessToken(realm);
            boolean createdNow = createdForThisSignIn(realm, token, signIn, provider);
            endSession(realm, "link", token, signIn, tokens);
            sessionOpen = false;
            if (createdNow) {
                deleteNewUser(realm, token, resolved);
                count(realm, "link", "mismatch");
                log.info("Link in realm {} for user {} resolved to user {} created for it; deleted", realm.name(),
                        current, resolved);
                throw new BaseAuthException(AuthError.IDENTITY_MISMATCH);
            }
            count(realm, "link", "in_use");
            log.info("Link in realm {} for user {} refused: the provider account belongs to user {}", realm.name(),
                    current, resolved);
            throw new BaseAuthException(AuthError.IDENTITY_IN_USE);
        } catch (FeignException e) {
            if (sessionOpen) {
                endSession(realm, "link", token, signIn, tokens);
            }
            throw adminError(realm, "link", e);
        } catch (BaseAuthException e) {
            throw e;
        } catch (RuntimeException e) {
            if (sessionOpen) {
                endSession(realm, "link", token, signIn, tokens);
            }
            throw e;
        }
    }

    /* ======================= checks ======================= */

    /** Password and an email nobody has confirmed: whoever typed the address knows the password. Links do not matter. */
    private boolean unconfirmedPasswordAccount(RealmConfig realm, String token, KeycloakUserDto user) {
        if (!StringUtils.hasText(user.email()) || Boolean.TRUE.equals(user.emailVerified())) {
            return false;
        }
        return hasPassword(realm, token, user.id());
    }

    /**
     * Keycloak created this user for exactly the sign-in just made: its only session is the code's, it was created
     * with the sign-in, has no password and only the provider. Deleting it is final, so every part must hold.
     */
    private boolean createdForThisSignIn(RealmConfig realm, String token, SignIn signIn, String provider) {
        if (signIn.sessionId() == null || signIn.authTime() == null) {
            return false;
        }
        KeycloakUserDto user = admin.getUser(realm.name(), signIn.subject(), bearer(token));
        Long created = user.createdTimestamp();
        if (created == null
                || Math.abs(created - signIn.authTime() * 1000) > CREATED_WITH_SIGN_IN.toMillis()) {
            return false;
        }
        List<KeycloakUserSessionDto> sessions = admin.getUserSessions(realm.name(), signIn.subject(), bearer(token));
        if (sessions == null || sessions.size() != 1 || !signIn.sessionId().equals(sessions.get(0).id())) {
            return false;
        }
        List<KeycloakFederatedIdentityDto> linked = identities(realm, token, signIn.subject());
        return linked.size() == 1 && provider.equals(linked.get(0).identityProvider())
                && !hasPassword(realm, token, signIn.subject());
    }

    /** Tried twice; when the user is still there the client is told (503), so the mismatch is not silently kept. */
    private void deleteNewUser(RealmConfig realm, String token, String userId) {
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                admin.deleteUser(realm.name(), userId, bearer(token));
                return;
            } catch (FeignException.NotFound e) {
                return; // already gone
            } catch (FeignException e) {
                log.error("Could not delete user {} created by a failed link in realm {} (attempt {}): HTTP {}", userId,
                        realm.name(), attempt, e.status());
            }
        }
        count(realm, "link", "delete_failed");
        throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
    }

    /* ======================= helpers ======================= */

    private TokenResponseDto exchange(RealmConfig realm, SocialLoginRequest request, String action) {
        try {
            return authService.socialLogin(realm, request);
        } catch (BaseAuthException e) {
            count(realm, action, e.getStatus() == HttpStatus.SERVICE_UNAVAILABLE ? "error" : "invalid");
            throw e;
        }
    }

    /**
     * What the access token the gateway has just received from Keycloak's token endpoint says about the sign-in (no
     * signature check: it did not come from the client). Without a subject the session is ended: 503.
     *
     * @param identityProvider alias of the provider the session was signed in with ({@code null} for password)
     * @param authTime         when the user authenticated, epoch seconds
     * @param sessionId        Keycloak user session ({@code sid})
     */
    record SignIn(String subject, String identityProvider, Long authTime, String sessionId) {

        boolean provenFor(String provider, Clock clock) {
            return provider.equals(identityProvider) && authTime != null
                    && clock.millis() - authTime * 1000 <= FRESH_SIGN_IN.toMillis()
                    && authTime * 1000 - clock.millis() <= CREATED_WITH_SIGN_IN.toMillis();
        }
    }

    private SignIn signIn(RealmConfig realm, TokenResponseDto tokens, String action) {
        SignIn signIn = null;
        try {
            JWTClaimsSet claims = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet();
            Object authTime = claims.getClaim("auth_time");
            Long seconds = authTime instanceof Number number ? Long.valueOf(number.longValue())
                    : authTime instanceof Date date ? Long.valueOf(date.getTime() / 1000) : null;
            signIn = new SignIn(claims.getSubject(), claims.getStringClaim("identity_provider"), seconds,
                    claims.getStringClaim("sid"));
        } catch (ParseException | RuntimeException e) {
            // handled below
        }
        if (signIn != null && StringUtils.hasText(signIn.subject())) {
            return signIn;
        }
        endSession(realm, action, null, signIn == null ? new SignIn(null, null, null, null) : signIn, tokens);
        count(realm, action, "error");
        log.error("Social sign-in in realm {}: Keycloak returned an access token without a subject", realm.name());
        throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
    }

    /**
     * Ends the session the refused code opened, so neither its tokens nor the browser's SSO cookie for it work: admin
     * API by {@code sid}, the online session and the offline one with the same id ({@code offline_access} sign-ins),
     * each tried twice. Without an admin token or {@code sid}, or when that fails, the refresh token is logged out
     * (an {@code offline_access} code leaves only the offline session once exchanged, which that logout ends; Keycloak
     * 26.7.3, IdentityMethodsIT). The tokens never reached the client either way; a session left open is logged and
     * counted ({@code result=session_left}).
     */
    private void endSession(RealmConfig realm, String action, String adminToken, SignIn signIn, TokenResponseDto tokens) {
        boolean ended = false;
        if (StringUtils.hasText(signIn.sessionId())) {
            String token = adminToken;
            if (token == null) {
                try {
                    token = adminService.getAdminAccessToken(realm);
                } catch (RuntimeException e) {
                    log.warn("Could not get an admin token to end a refused social session in realm {}", realm.name());
                }
            }
            if (token != null) {
                ended = deleteSession(realm, token, signIn.sessionId(), false)
                        & deleteSession(realm, token, signIn.sessionId(), true);
            }
        }
        if (!ended && StringUtils.hasText(tokens.refreshToken())) {
            try {
                authService.logout(realm, new LogoutRequest(tokens.refreshToken()));
                ended = true;
            } catch (BaseAuthException e) {
                // logged below
            }
        }
        if (!ended) {
            count(realm, action, "session_left");
            log.error("Could not end a refused social session in realm {} for user {}", realm.name(), signIn.subject());
        }
    }

    private boolean deleteSession(RealmConfig realm, String token, String sessionId, boolean offline) {
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                admin.deleteSession(realm.name(), sessionId, offline, bearer(token));
                return true;
            } catch (FeignException.NotFound e) {
                return true; // no such session (no offline_access, or already ended)
            } catch (FeignException e) {
                log.warn("Ending {} session in realm {} failed (attempt {}): HTTP {}", offline ? "offline" : "online",
                        realm.name(), attempt, e.status());
            } catch (RuntimeException e) {
                log.warn("Ending {} session in realm {} failed (attempt {}): {}", offline ? "offline" : "online",
                        realm.name(), attempt, e.getClass().getSimpleName());
            }
        }
        return false;
    }

    private boolean hasPassword(RealmConfig realm, String token, String userId) {
        return admin.getCredentials(realm.name(), userId, bearer(token)).stream()
                .anyMatch(credential -> "password".equals(credential.type()));
    }

    private List<KeycloakFederatedIdentityDto> identities(RealmConfig realm, String token, String userId) {
        List<KeycloakFederatedIdentityDto> linked = admin.getFederatedIdentities(realm.name(), userId, bearer(token));
        return linked == null ? List.of() : linked;
    }

    /** Providers keep the account's address as the link's user name (Google always, Apple when it shared one). */
    static String emailOf(KeycloakFederatedIdentityDto identity) {
        String name = identity.userName();
        return name != null && name.indexOf('@') > 0 ? name : null;
    }

    private void require(RealmConfig realm, String action) {
        if (!realm.identityMethods()) {
            count(realm, action, "disabled");
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
    }

    /** Each call costs the admin API two or three requests: limited per user. */
    private void limit(RealmConfig realm, String action, String userId, RateLimiter.Limit limit) {
        if (!limiter.tryAcquire("identities-" + action + "|" + realm.name() + "|" + userId, limit)) {
            count(realm, action, "rate_limited");
            throw new BaseAuthException(AuthError.RATE_LIMITED);
        }
    }

    private String adminToken(RealmConfig realm, String action) {
        try {
            return adminService.getAdminAccessToken(realm);
        } catch (FeignException e) {
            throw adminError(realm, action, e);
        }
    }

    private BaseAuthException adminError(RealmConfig realm, String action, FeignException e) {
        count(realm, action, "error");
        if (e.status() == 404) {
            // the token's user is gone
            return new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        }
        if (e.status() == 403) {
            log.error("Admin client {} of realm {} may not manage users ({})", realm.adminClientId(), realm.name(), action);
            return new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        }
        log.error("Keycloak admin API failed in realm {} ({}): HTTP {}", realm.name(), action, e.status());
        return new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private void count(RealmConfig realm, String action, String result) {
        Counter.builder("auth.gateway.identity.requests")
                .description("Sign-in method requests (list, unlink, link, social sign-in check) by result")
                .tag("realm", realm.name()).tag("action", action).tag("result", result)
                .register(meters).increment();
    }
}
