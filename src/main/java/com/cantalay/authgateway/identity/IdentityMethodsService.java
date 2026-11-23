package com.cantalay.authgateway.identity;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.domain.IdentitiesResponse;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.LogoutRequest;
import com.cantalay.authgateway.domain.SocialLoginRequest;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
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
 * Keycloak's first broker login (talay-identity {@code social-first-login}: create the user if the email is unique,
 * otherwise link the provider to the account with that email) has already run when the gateway gets the code, so the
 * gateway judges the account the code resolved to:
 * <ul>
 *     <li>an account with a password and an unconfirmed email that has a provider linked: Keycloak linked a provider to
 *     an account whose owner never proved the address (whoever registered it knows its password). The provider links
 *     are removed, the new session is ended and the answer is 409 {@code account_exists_unverified};</li>
 *     <li>{@code mode=link} resolving to another user: the new session is ended (its tokens are never returned) and the
 *     signed-in user is left alone. A user Keycloak has just created for this sign-in (at most 60 seconds old, one
 *     session, no password, one provider) is deleted: 409 {@code identity_mismatch}; any other user: 409
 *     {@code identity_in_use}.</li>
 * </ul>
 * Linking a provider whose address is the account's own confirms that address (the realm trusts the provider's
 * email), so later sign-ins with the provider pass the check above.
 * <p>
 * Metric: {@code auth_gateway_identity_requests_total{realm, action=list|unlink|link|login, result}}.
 */
@Service
public class IdentityMethodsService {

    static final Duration NEW_USER_WINDOW = Duration.ofSeconds(60);
    static final int LOCK_STRIPES = 64;
    static final String MODE_LOGIN = "login";
    static final String MODE_LINK = "link";

    private static final Logger log = LoggerFactory.getLogger(IdentityMethodsService.class);

    private final AuthAdminService adminService;
    private final AuthService authService;
    private final KeycloakAdminClient admin;
    private final MeterRegistry meters;
    private final Clock clock;
    /** One removal at a time per user, so two parallel removals cannot take away the last two methods. */
    private final ReentrantLock[] userLocks = new ReentrantLock[LOCK_STRIPES];

    @Autowired
    public IdentityMethodsService(AuthAdminService adminService, AuthService authService, KeycloakAdminClient admin,
                                  MeterRegistry meters, Clock clock) {
        this.adminService = adminService;
        this.authService = authService;
        this.admin = admin;
        this.meters = meters;
        this.clock = clock;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            userLocks[i] = new ReentrantLock();
        }
    }

    /* ======================= identities ======================= */

    public IdentitiesResponse list(RealmConfig realm, String userId) {
        require(realm, "list");
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
            removeIdentity(realm, token, userId, alias);
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
     * account's Bearer token).
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

    private TokenResponseDto login(RealmConfig realm, SocialLoginRequest request) {
        TokenResponseDto tokens = exchange(realm, request, "login");
        String userId = subject(realm, tokens, "login");
        try {
            String token = adminService.getAdminAccessToken(realm);
            KeycloakUserDto user = admin.getUser(realm.name(), userId, bearer(token));
            if (unlinkFromUnconfirmedAccount(realm, token, user)) {
                endSession(realm, tokens);
                count(realm, "login", "unverified");
                log.info("Social sign-in in realm {} refused: account {} ({}) has an unconfirmed email",
                        realm.name(), userId, maskEmail(user.email()));
                throw new BaseAuthException(AuthError.ACCOUNT_EXISTS_UNVERIFIED, null, user.email());
            }
        } catch (FeignException e) {
            // the account could not be checked: no tokens for it
            endSession(realm, tokens);
            throw adminError(realm, "login", e);
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
        String current = bearer.getSubject();
        TokenResponseDto tokens = exchange(realm, request, "link");
        String resolved = subject(realm, tokens, "link");
        boolean sessionOpen = true;
        try {
            String token = adminService.getAdminAccessToken(realm);
            if (current.equals(resolved)) {
                confirmEmailThroughProvider(realm, token, resolved);
                count(realm, "link", "ok");
                log.info("Identity provider linked in realm {} for user {}", realm.name(), current);
                return tokens;
            }
            // Another user: its tokens never leave the gateway, the signed-in user is not touched.
            boolean createdNow = createdForThisSignIn(realm, token, resolved);
            endSession(realm, tokens);
            sessionOpen = false;
            if (createdNow) {
                deleteNewUser(realm, token, resolved);
                count(realm, "link", "mismatch");
                log.info("Link in realm {} for user {} resolved to user {} created for it; deleted", realm.name(),
                        current, resolved);
                throw new BaseAuthException(AuthError.IDENTITY_MISMATCH);
            }
            unlinkFromUnconfirmedAccount(realm, token, admin.getUser(realm.name(), resolved, bearer(token)));
            count(realm, "link", "in_use");
            log.info("Link in realm {} for user {} refused: the provider account belongs to user {}", realm.name(),
                    current, resolved);
            throw new BaseAuthException(AuthError.IDENTITY_IN_USE);
        } catch (FeignException e) {
            if (sessionOpen) {
                endSession(realm, tokens);
            }
            throw adminError(realm, "link", e);
        }
    }

    /* ======================= checks ======================= */

    /**
     * Removes the provider links of an account that has a password and an unconfirmed email (Keycloak's automatic
     * linking by email put them there; nobody proved the address belongs to whoever set the password).
     *
     * @return whether the account was such an account with links
     */
    private boolean unlinkFromUnconfirmedAccount(RealmConfig realm, String token, KeycloakUserDto user) {
        if (!StringUtils.hasText(user.email()) || Boolean.TRUE.equals(user.emailVerified())) {
            return false;
        }
        List<KeycloakFederatedIdentityDto> linked = identities(realm, token, user.id());
        if (linked.isEmpty() || !hasPassword(realm, token, user.id())) {
            return false;
        }
        for (KeycloakFederatedIdentityDto identity : linked) {
            removeIdentity(realm, token, user.id(), identity.identityProvider());
            log.info("Identity provider {} unlinked in realm {} from user {}: email not confirmed",
                    identity.identityProvider(), realm.name(), user.id());
        }
        return true;
    }

    /** The provider vouched for the account's own address: the account's email counts as confirmed. */
    private void confirmEmailThroughProvider(RealmConfig realm, String token, String userId) {
        KeycloakUserDto user = admin.getUser(realm.name(), userId, bearer(token));
        if (!StringUtils.hasText(user.email()) || Boolean.TRUE.equals(user.emailVerified())) {
            return;
        }
        boolean sameAddress = identities(realm, token, userId).stream()
                .anyMatch(identity -> user.email().equalsIgnoreCase(emailOf(identity)));
        if (sameAddress) {
            admin.updateUser(realm.name(), userId, bearer(token), Map.of("emailVerified", true));
            log.info("Email of user {} in realm {} confirmed by a linked identity provider", userId, realm.name());
        }
    }

    /** Keycloak created this user for the sign-in just made: recent, one session, no password, one provider. */
    private boolean createdForThisSignIn(RealmConfig realm, String token, String userId) {
        KeycloakUserDto user = admin.getUser(realm.name(), userId, bearer(token));
        Long created = user.createdTimestamp();
        if (created == null || clock.millis() - created > NEW_USER_WINDOW.toMillis()) {
            return false;
        }
        return identities(realm, token, userId).size() == 1
                && !hasPassword(realm, token, userId)
                && admin.getUserSessions(realm.name(), userId, bearer(token)).size() <= 1;
    }

    private void deleteNewUser(RealmConfig realm, String token, String userId) {
        try {
            admin.deleteUser(realm.name(), userId, bearer(token));
        } catch (FeignException.NotFound e) {
            // already gone
        } catch (FeignException e) {
            log.error("Could not delete user {} created by a failed link in realm {}: HTTP {}", userId, realm.name(),
                    e.status());
        }
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
     * Subject of the access token the gateway has just received from Keycloak's token endpoint (no signature check:
     * it did not come from the client). Without one the session is ended: 503.
     */
    private String subject(RealmConfig realm, TokenResponseDto tokens, String action) {
        String subject = null;
        try {
            subject = JWTParser.parse(tokens.accessToken()).getJWTClaimsSet().getSubject();
        } catch (ParseException | RuntimeException e) {
            // handled below
        }
        if (StringUtils.hasText(subject)) {
            return subject;
        }
        endSession(realm, tokens);
        count(realm, action, "error");
        log.error("Social sign-in in realm {}: Keycloak returned an access token without a subject", realm.name());
        throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
    }

    /** Best effort: the session's tokens never reached the client, so a failure only leaves them to expire. */
    private void endSession(RealmConfig realm, TokenResponseDto tokens) {
        if (!StringUtils.hasText(tokens.refreshToken())) {
            return;
        }
        try {
            authService.logout(realm, new LogoutRequest(tokens.refreshToken()));
        } catch (BaseAuthException e) {
            log.warn("Could not end a refused social session in realm {}", realm.name());
        }
    }

    private boolean hasPassword(RealmConfig realm, String token, String userId) {
        return admin.getCredentials(realm.name(), userId, bearer(token)).stream()
                .anyMatch(credential -> "password".equals(credential.type()));
    }

    private List<KeycloakFederatedIdentityDto> identities(RealmConfig realm, String token, String userId) {
        List<KeycloakFederatedIdentityDto> linked = admin.getFederatedIdentities(realm.name(), userId, bearer(token));
        return linked == null ? List.of() : linked;
    }

    private void removeIdentity(RealmConfig realm, String token, String userId, String alias) {
        try {
            admin.removeFederatedIdentity(realm.name(), userId, alias, bearer(token));
        } catch (FeignException.NotFound e) {
            // already gone
        }
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
