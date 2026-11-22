package com.cantalay.authgateway.account;

import com.cantalay.authgateway.action.ActionPurpose;
import com.cantalay.authgateway.action.ActionToken;
import com.cantalay.authgateway.action.ActionTokenService;
import com.cantalay.authgateway.action.InvalidActionTokenException;
import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.KeycloakCredentialDto;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.RegisterRequest;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.mail.AccountMailService;
import com.cantalay.authgateway.mail.MailProperties;
import com.cantalay.authgateway.mail.MailTemplate;
import com.cantalay.authgateway.realm.KeycloakErrors;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
import com.cantalay.authgateway.service.RegistrationHook;
import feign.FeignException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

/**
 * Account email actions served by the gateway so users never see a Keycloak page: forgot/reset password and email
 * confirmation through signed links into the application ({@link ActionTokenService}), plus the verification and
 * welcome emails around registration.
 * <p>
 * Everything is opt-in per realm ({@link MailProperties}): {@code resetUrl} turns on forgot/reset password,
 * {@code verifyUrl} turns on gateway email confirmation. A realm with neither keeps the original behavior (Keycloak's
 * verification email on registration and resend; the new endpoints answer 404 {@code realm_feature_disabled}).
 * <p>
 * Endpoints that take an email address always answer 202 and do the lookup in the background, so neither the answer
 * nor its timing tells whether the address is registered. Limits (per pod) apply silently there and as 429
 * {@code rate_limited} on the token endpoints.
 * Metric: {@code auth_gateway_action_requests_total{realm, action, result}}.
 */
@Service
public class AccountActionService implements RegistrationHook {

    static final RateLimiter.Limit FORGOT_PER_EMAIL = new RateLimiter.Limit(3, Duration.ofHours(1));
    static final RateLimiter.Limit FORGOT_PER_IP = new RateLimiter.Limit(10, Duration.ofHours(1));
    static final RateLimiter.Limit RESEND_PER_EMAIL_MINUTE = new RateLimiter.Limit(1, Duration.ofMinutes(1));
    static final RateLimiter.Limit RESEND_PER_EMAIL_HOUR = new RateLimiter.Limit(5, Duration.ofHours(1));
    static final RateLimiter.Limit RESEND_PER_IP = new RateLimiter.Limit(20, Duration.ofHours(1));
    static final RateLimiter.Limit TOKEN_PER_IP = new RateLimiter.Limit(20, Duration.ofHours(1));
    static final int LOCK_STRIPES = 64;

    /** How a realm confirms email addresses. */
    public enum VerifyMode {
        /** Gateway link into the app ({@code verifyUrl}). */
        GATEWAY,
        /**
         * Keycloak's own verification email: realms without {@code verifyUrl} (unchanged behavior), and realms whose
         * {@code verifyUrl} cannot work because SMTP, the sender or the token keys are missing (degraded, see
         * {@code auth_gateway_feature_degraded}).
         */
        KEYCLOAK
    }

    private static final Logger log = LoggerFactory.getLogger(AccountActionService.class);

    private final AuthAdminService adminService;
    private final KeycloakClient keycloak;
    private final KeycloakAdminClient admin;
    private final ActionTokenService tokens;
    private final AccountMailService mail;
    private final MailProperties mailProperties;
    private final RateLimiter limiter;
    private final MeterRegistry meters;
    private final Executor tasks;
    private final RateLimiter.Limit registerPerIp;
    private final RateLimiter.Limit registerPerEmail;
    /** One password reset / confirmation at a time per user: the fingerprint is checked again under the lock. */
    private final ReentrantLock[] userLocks = new ReentrantLock[LOCK_STRIPES];
    private final Map<String, AtomicInteger> degraded = new ConcurrentHashMap<>();

    public AccountActionService(AuthAdminService adminService,
                                KeycloakClient keycloak,
                                KeycloakAdminClient admin,
                                ActionTokenService tokens,
                                AccountMailService mail,
                                MailProperties mailProperties,
                                RateLimiter limiter,
                                MeterRegistry meters,
                                Executor tasks) {
        this(adminService, keycloak, admin, tokens, mail, mailProperties, limiter, meters, tasks, 20, 5);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AccountActionService(AuthAdminService adminService,
                                KeycloakClient keycloak,
                                KeycloakAdminClient admin,
                                ActionTokenService tokens,
                                AccountMailService mail,
                                MailProperties mailProperties,
                                RateLimiter limiter,
                                MeterRegistry meters,
                                @Qualifier("accountTaskExecutor") Executor tasks,
                                @Value("${gateway.register-limit.per-ip:20}") int registerPerIp,
                                @Value("${gateway.register-limit.per-email:5}") int registerPerEmail) {
        this.registerPerIp = new RateLimiter.Limit(registerPerIp, Duration.ofHours(1));
        this.registerPerEmail = new RateLimiter.Limit(registerPerEmail, Duration.ofHours(1));
        for (int i = 0; i < LOCK_STRIPES; i++) {
            userLocks[i] = new ReentrantLock();
        }
        this.adminService = adminService;
        this.keycloak = keycloak;
        this.admin = admin;
        this.tokens = tokens;
        this.mail = mail;
        this.mailProperties = mailProperties;
        this.limiter = limiter;
        this.meters = meters;
        this.tasks = tasks;
    }

    /* ======================= feature switches ======================= */

    public boolean resetEnabled(RealmConfig realm) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        return config != null && StringUtils.hasText(config.getResetUrl()) && tokens.isConfigured()
                && mail.isEnabled(realm.name());
    }

    public VerifyMode verifyMode(RealmConfig realm) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        if (config == null || !StringUtils.hasText(config.getVerifyUrl())) {
            return VerifyMode.KEYCLOAK;
        }
        return verifyReady(realm) ? VerifyMode.GATEWAY : VerifyMode.KEYCLOAK;
    }

    private boolean verifyReady(RealmConfig realm) {
        return tokens.isConfigured() && mail.isEnabled(realm.name());
    }

    /**
     * {@code resend-verification} is opt-in: on with {@code verifyUrl}, or with {@code resendVerification=true} for
     * realms that keep Keycloak's verification email.
     */
    public boolean resendEnabled(RealmConfig realm) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        if (config == null) {
            return false;
        }
        if (config.getResendVerification() != null) {
            return config.getResendVerification();
        }
        return StringUtils.hasText(config.getVerifyUrl());
    }

    /** A half-configured realm must be visible in the logs, but it must not take the shared gateway down. */
    @EventListener(ApplicationReadyEvent.class)
    public void reportConfiguration(ApplicationReadyEvent event) {
        RealmRegistry realms = event.getApplicationContext().getBean(RealmRegistry.class);
        mailProperties.getRealms().forEach((name, config) -> {
            Optional<RealmConfig> realm = realms.all().stream().filter(r -> r.name().equals(name.toLowerCase(Locale.ROOT))).findFirst();
            if (realm.isEmpty()) {
                log.warn("Mail settings for unknown realm {} are ignored", name);
                return;
            }
            boolean wantsReset = StringUtils.hasText(config.getResetUrl());
            boolean wantsVerify = StringUtils.hasText(config.getVerifyUrl());
            boolean resetBroken = wantsReset && !resetEnabled(realm.get());
            boolean verifyBroken = wantsVerify && !verifyReady(realm.get());
            degradedGauge(realm.get().name(), "reset").set(resetBroken ? 1 : 0);
            degradedGauge(realm.get().name(), "verify").set(verifyBroken ? 1 : 0);
            if (resetBroken || verifyBroken) {
                log.error("Realm {} asks for gateway account emails but SMTP_HOST, its FROM address or "
                        + "GATEWAY_ACTION_TOKEN_SECRETS is missing; forgot-password stays off{}", name,
                        verifyBroken ? ", email confirmation falls back to Keycloak's email" : "");
            } else if (wantsReset || wantsVerify) {
                log.info("Realm {}: gateway password reset {}, email confirmation {}", name,
                        wantsReset ? "on" : "off", wantsVerify ? "on" : "keycloak");
            }
        });
    }

    /* ======================= forgot / reset password ======================= */

    /** Always returns normally (202); the lookup and email happen in the background. */
    public void forgotPassword(RealmConfig realm, String email, String locale, String clientIp) {
        if (!resetEnabled(realm)) {
            count(realm, "forgot", "disabled");
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
        String address = normalizeEmail(email);
        if (!limiter.tryAcquire("forgot-ip|" + realm.name() + "|" + ipKey(clientIp), FORGOT_PER_IP)
                || !limiter.tryAcquire("forgot-email|" + realm.name() + "|" + address, FORGOT_PER_EMAIL)) {
            count(realm, "forgot", "rate_limited");
            log.info("Forgot password in realm {} rate limited for {}", realm.name(), maskEmail(address));
            return;
        }
        count(realm, "forgot", "ok");
        tasks.execute(() -> sendForgotEmail(realm, address, locale));
    }

    void sendForgotEmail(RealmConfig realm, String email, String locale) {
        try {
            String token = adminService.getAdminAccessToken(realm);
            Optional<KeycloakUserDto> found = findUser(realm, token, email);
            if (found.isEmpty()) {
                log.info("Forgot password in realm {}: no usable account for {}", realm.name(), maskEmail(email));
                return;
            }
            KeycloakUserDto user = found.get();
            MailProperties.Realm config = mailProperties.realm(realm.name());
            String language = language(config, locale, user);
            Optional<KeycloakCredentialDto> password = passwordCredential(realm, token, user.id());
            if (password.isPresent()) {
                String link = link(config.getResetUrl(), tokens.issue(realm.name(), ActionPurpose.RESET, user.id(),
                        resetFingerprint(password.get())));
                mail.send(realm.name(), MailTemplate.RESET, user.email(), language, Map.of(
                        "name", greetingName(user),
                        "email", user.email(),
                        "duration", mail.templates().duration(language, tokens.ttl(ActionPurpose.RESET))
                ), link, List.of());
                return;
            }
            List<String> providers = admin.getFederatedIdentities(realm.name(), user.id(), "Bearer " + token).stream()
                    .map(KeycloakFederatedIdentityDto::identityProvider)
                    .filter(StringUtils::hasText)
                    .map(AccountActionService::providerName)
                    .distinct()
                    .toList();
            if (providers.isEmpty()) {
                log.info("Forgot password in realm {}: account {} has neither a password nor a linked provider",
                        realm.name(), user.id());
                return;
            }
            mail.send(realm.name(), MailTemplate.RESET_SOCIAL, user.email(), language, Map.of(
                    "name", greetingName(user),
                    "email", user.email(),
                    "providers", mail.templates().joinProviders(language, providers)
            ), emptyToNull(config.getAppUrl()), List.of());
        } catch (FeignException e) {
            log.error("Forgot password in realm {} failed: Keycloak HTTP {}", realm.name(), e.status());
        } catch (RuntimeException e) {
            log.error("Forgot password in realm {} failed: {}", realm.name(), e.getClass().getSimpleName());
        }
    }

    /** 204 when the link can still be used, 410 {@code reset_token_invalid} otherwise. */
    public void checkResetToken(RealmConfig realm, String token, String clientIp) {
        requireReset(realm, "reset_check");
        limitToken(realm, "reset_check", "reset-check-ip|" + realm.name() + "|" + ipKey(clientIp));
        resolveReset(realm, verifyToken(realm, token, ActionPurpose.RESET, "reset_check", AuthError.RESET_TOKEN_INVALID),
                "reset_check");
        count(realm, "reset_check", "ok");
    }

    /**
     * Sets the new password, ends every session of the user, clears a brute-force lockout, sends "your password changed"
     * and signs the user in on this device.
     *
     * @return tokens of the new session; empty when the password changed but the sign-in did not work (the client then
     * asks the user to sign in)
     */
    public Optional<TokenResponseDto> resetPassword(RealmConfig realm, String token, String newPassword, String clientIp) {
        requireReset(realm, "reset");
        limitToken(realm, "reset", "reset-ip|" + realm.name() + "|" + ipKey(clientIp));
        ActionToken verified = verifyToken(realm, token, ActionPurpose.RESET, "reset", AuthError.RESET_TOKEN_INVALID);
        ResetOutcome outcome = underUserLock(verified.subject(), () -> applyReset(realm, verified, newPassword));
        KeycloakUserDto user = outcome.user();

        MailProperties.Realm config = mailProperties.realm(realm.name());
        String language = language(config, null, user);
        if (StringUtils.hasText(user.email())) {
            tasks.execute(() -> mail.send(realm.name(), MailTemplate.PASSWORD_CHANGED, user.email(), language, Map.of(
                    "name", greetingName(user),
                    "email", user.email()
            ), config.getResetUrl(), List.of()));
        }
        if (!outcome.sessionsEnded()) {
            // The attacker's refresh/offline tokens may still live: no new session, the user must try again.
            count(realm, "reset", "sessions_failed");
            throw new BaseAuthException(AuthError.SESSIONS_REVOKE_FAILED);
        }
        count(realm, "reset", "ok");
        return signIn(realm, user.username() != null ? user.username() : user.email(), newPassword);
    }

    private record ResetOutcome(KeycloakUserDto user, boolean sessionsEnded) {
    }

    /** Runs under the user's lock, so a second request with the same link sees the new credential and gets 410. */
    private ResetOutcome applyReset(RealmConfig realm, ActionToken verified, String newPassword) {
        ResetTarget target = resolveReset(realm, verified, "reset");
        String bearer = "Bearer " + target.adminToken();
        String userId = target.user().id();

        try {
            admin.resetPassword(realm.name(), userId, bearer, Map.of(
                    "type", "password",
                    "value", newPassword,
                    "temporary", false
            ));
        } catch (FeignException.BadRequest e) {
            count(realm, "reset", "policy");
            String rule = KeycloakErrors.passwordPolicyRule(e);
            throw new BaseAuthException(AuthError.PASSWORD_POLICY_VIOLATION,
                    rule == null ? null : Map.of("newPassword", rule));
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }

        boolean sessionsEnded = endSessions(realm, userId, bearer);
        try {
            admin.clearBruteForce(realm.name(), userId, bearer);
        } catch (FeignException e) {
            log.warn("Password reset in realm {}: clearing lockout of user {} failed: HTTP {}", realm.name(), userId, e.status());
        }
        log.info("Password reset in realm {} for user {} (sessions ended: {})", realm.name(), userId, sessionsEnded);
        return new ResetOutcome(target.user(), sessionsEnded);
    }

    /**
     * Online sessions via logout; offline tokens (mobile apps) via the gateway clients' consents. Each call is tried
     * twice; {@code false} when one still failed (the caller must not open a new session then).
     */
    private boolean endSessions(RealmConfig realm, String userId, String bearer) {
        boolean ok = retryOnce(() -> admin.logoutUser(realm.name(), userId, bearer),
                "ending sessions", realm, userId);
        List<String> clients = new ArrayList<>(List.of(realm.clientId()));
        if (realm.platformClientId() != null) {
            clients.add(realm.platformClientId());
        }
        for (String clientId : clients) {
            ok &= retryOnce(() -> admin.revokeConsent(realm.name(), userId, clientId, bearer),
                    "revoking offline tokens", realm, userId);
        }
        return ok;
    }

    private boolean retryOnce(Runnable call, String what, RealmConfig realm, String userId) {
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                call.run();
                return true;
            } catch (FeignException.NotFound e) {
                return true; // nothing to end (no offline token for this client)
            } catch (FeignException e) {
                log.error("Password reset in realm {}: {} of user {} failed (attempt {}): HTTP {}", realm.name(), what,
                        userId, attempt, e.status());
            } catch (RuntimeException e) {
                log.error("Password reset in realm {}: {} of user {} failed (attempt {}): {}", realm.name(), what,
                        userId, attempt, e.getClass().getSimpleName());
            }
        }
        return false;
    }

    private <T> T underUserLock(String userId, Supplier<T> work) {
        ReentrantLock lock = userLocks[Math.floorMod(userId.hashCode(), LOCK_STRIPES)];
        lock.lock();
        try {
            return work.get();
        } finally {
            lock.unlock();
        }
    }

    private Optional<TokenResponseDto> signIn(RealmConfig realm, String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", realm.clientId());
        form.add("username", username);
        form.add("password", password);
        form.add("scope", AuthService.loginScope(realm));
        try {
            return Optional.ofNullable(keycloak.token(realm.name(), form));
        } catch (FeignException e) {
            log.warn("Password reset in realm {}: sign-in with the new password failed: HTTP {}", realm.name(), e.status());
            return Optional.empty();
        }
    }

    private ResetTarget resolveReset(RealmConfig realm, ActionToken verified, String action) {
        String adminToken = adminToken(realm);
        KeycloakUserDto user = userById(realm, adminToken, verified.subject(), action, AuthError.RESET_TOKEN_INVALID);
        Optional<KeycloakCredentialDto> password;
        try {
            password = passwordCredential(realm, adminToken, user.id());
        } catch (FeignException.NotFound e) {
            password = Optional.empty();
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
        if (password.isEmpty() || !sameFingerprint(resetFingerprint(password.get()), verified.fingerprint())) {
            count(realm, action, "invalid");
            throw new BaseAuthException(AuthError.RESET_TOKEN_INVALID);
        }
        return new ResetTarget(user, adminToken);
    }

    private record ResetTarget(KeycloakUserDto user, String adminToken) {
    }

    /* ======================= email confirmation ======================= */

    /** Always returns normally (202); the lookup and email happen in the background. */
    public void resendVerification(RealmConfig realm, String email, String locale, String clientIp) {
        if (!resendEnabled(realm)) {
            count(realm, "resend", "disabled");
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
        VerifyMode mode = verifyMode(realm);
        String address = normalizeEmail(email);
        if (!limiter.tryAcquire("resend-ip|" + realm.name() + "|" + ipKey(clientIp), RESEND_PER_IP)
                || !limiter.tryAcquire(resendKey(realm, address), RESEND_PER_EMAIL_MINUTE, RESEND_PER_EMAIL_HOUR)) {
            count(realm, "resend", "rate_limited");
            log.info("Verification email in realm {} rate limited for {}", realm.name(), maskEmail(address));
            return;
        }
        count(realm, "resend", "ok");
        tasks.execute(() -> sendResend(realm, mode, address, locale));
    }

    void sendResend(RealmConfig realm, VerifyMode mode, String email, String locale) {
        try {
            String token = adminService.getAdminAccessToken(realm);
            Optional<KeycloakUserDto> user = findUser(realm, token, email).filter(u -> !Boolean.TRUE.equals(u.emailVerified()));
            if (user.isEmpty()) {
                log.info("Verification email in realm {}: no unverified account for {}", realm.name(), maskEmail(email));
                return;
            }
            if (mode == VerifyMode.GATEWAY) {
                sendVerifyEmail(realm, user.get(), locale);
            } else {
                sendKeycloakVerification(realm, user.get().id(), token);
            }
        } catch (FeignException e) {
            log.error("Verification email in realm {} failed: Keycloak HTTP {}", realm.name(), e.status());
        } catch (RuntimeException e) {
            log.error("Verification email in realm {} failed: {}", realm.name(), e.getClass().getSimpleName());
        }
    }

    /** Marks the address confirmed; a link for an address the account no longer has is 410. */
    public void verifyEmail(RealmConfig realm, String token, String clientIp) {
        if (verifyMode(realm) != VerifyMode.GATEWAY) {
            count(realm, "verify", "disabled");
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
        limitToken(realm, "verify", "verify-ip|" + realm.name() + "|" + ipKey(clientIp));
        ActionToken verified = verifyToken(realm, token, ActionPurpose.VERIFY, "verify", AuthError.VERIFY_TOKEN_INVALID);
        underUserLock(verified.subject(), () -> {
            confirmEmail(realm, verified);
            return null;
        });
    }

    /** Under the user's lock: the address is compared with the account's current one right before the update. */
    private void confirmEmail(RealmConfig realm, ActionToken verified) {
        String adminToken = adminToken(realm);
        KeycloakUserDto user = userById(realm, adminToken, verified.subject(), "verify", AuthError.VERIFY_TOKEN_INVALID);
        if (!sameFingerprint(ActionTokenService.emailFingerprint(user.email()), verified.fingerprint())) {
            count(realm, "verify", "invalid");
            throw new BaseAuthException(AuthError.VERIFY_TOKEN_INVALID);
        }
        if (Boolean.TRUE.equals(user.emailVerified())) {
            count(realm, "verify", "ok");
            return;
        }
        try {
            admin.updateUser(realm.name(), user.id(), "Bearer " + adminToken, Map.of("emailVerified", true));
        } catch (FeignException.NotFound e) {
            count(realm, "verify", "invalid");
            throw new BaseAuthException(AuthError.VERIFY_TOKEN_INVALID);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
        count(realm, "verify", "ok");
        log.info("Email confirmed in realm {} for user {}", realm.name(), user.id());
    }

    private void sendVerifyEmail(RealmConfig realm, KeycloakUserDto user, String locale) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        String language = language(config, locale, user);
        String link = link(config.getVerifyUrl(), tokens.issue(realm.name(), ActionPurpose.VERIFY, user.id(),
                ActionTokenService.emailFingerprint(user.email())));
        mail.send(realm.name(), MailTemplate.VERIFY, user.email(), language, Map.of(
                "name", greetingName(user),
                "email", user.email(),
                "duration", mail.templates().duration(language, tokens.ttl(ActionPurpose.VERIFY))
        ), link, List.of());
    }

    /** Keycloak's verification email (PR #2): optional return to the app via the realm's verify client/redirect. */
    private boolean sendKeycloakVerification(RealmConfig realm, String userId, String adminToken) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        String clientId = config == null ? null : emptyToNull(config.getVerifyClientId());
        String redirectUri = config == null ? null : emptyToNull(config.getVerifyRedirectUri());
        if (clientId == null || redirectUri == null) {
            clientId = null;
            redirectUri = null;
        }
        try {
            admin.sendVerificationEmail(realm.name(), userId, "Bearer " + adminToken, clientId, redirectUri);
            log.info("Verification email sent in realm {} to user {}", realm.name(), userId);
            return true;
        } catch (FeignException e) {
            log.error("Failed to send verification email in realm {} to user {}: HTTP {}", realm.name(), userId, e.status());
            return false;
        }
    }

    /* ======================= registration ======================= */

    @Override
    public Map<String, List<String>> userAttributes(RealmConfig realm, RegisterRequest request) {
        MailProperties.Realm config = mailProperties.realm(realm.name());
        String locale = MailProperties.normalizeLocale(request.locale());
        if (config == null || locale == null || !config.supportedLocales().contains(locale)) {
            return Map.of();
        }
        return Map.of("locale", List.of(locale));
    }

    /** Registration limits (all realms): 429 {@code rate_limited} beyond them. */
    @Override
    public void beforeRegistration(RealmConfig realm, RegisterRequest request, String clientIp) {
        boolean allowed = (clientIp == null || limiter.tryAcquire("register-ip|" + realm.name() + "|" + ipKey(clientIp), registerPerIp))
                && limiter.tryAcquire("register-email|" + realm.name() + "|" + normalizeEmail(request.email()), registerPerEmail);
        if (!allowed) {
            count(realm, "register", "rate_limited");
            throw new BaseAuthException(AuthError.RATE_LIMITED);
        }
    }

    @Override
    public void registered(RealmConfig realm, KeycloakUserDto user, String adminToken, RegisterRequest request) {
        // Counts as the first send so "send again" waits a minute, as the app's countdown shows.
        limiter.tryAcquire(resendKey(realm, normalizeEmail(user.email())), RESEND_PER_EMAIL_MINUTE, RESEND_PER_EMAIL_HOUR);
        boolean verificationSent;
        if (verifyMode(realm) == VerifyMode.GATEWAY) {
            tasks.execute(() -> {
                try {
                    sendVerifyEmail(realm, user, request.locale());
                } catch (RuntimeException e) {
                    log.error("Verification email in realm {} failed: {}", realm.name(), e.getClass().getSimpleName());
                }
            });
            verificationSent = true;
        } else {
            verificationSent = sendKeycloakVerification(realm, user.id(), adminToken);
        }
        if (mail.isEnabled(realm.name())) {
            MailProperties.Realm config = mailProperties.realm(realm.name());
            String language = language(config, request.locale(), user);
            List<String> extra = verificationSent ? List.of("verify") : List.of();
            String to = user.email() != null ? user.email() : request.email();
            // No name: whoever registers chooses it, and the email goes to an address nobody has confirmed yet.
            tasks.execute(() -> mail.send(realm.name(), MailTemplate.WELCOME, to, language, Map.of(),
                    emptyToNull(config.getAppUrl()), extra));
        }
    }

    /* ======================= helpers ======================= */

    /**
     * Name for the greeting, only once the address owner confirmed the account: before that the name is whatever the
     * registering person typed, and the email may reach someone else.
     */
    static String greetingName(KeycloakUserDto user) {
        return Boolean.TRUE.equals(user.emailVerified()) ? nullToEmpty(user.firstName()) : "";
    }

    private static String ipKey(String clientIp) {
        return ClientIp.rateKey(clientIp);
    }

    private AtomicInteger degradedGauge(String realm, String feature) {
        return degraded.computeIfAbsent(realm + "|" + feature, k -> meters.gauge("auth.gateway.feature.degraded",
                io.micrometer.core.instrument.Tags.of("realm", realm, "feature", feature), new AtomicInteger()));
    }

    private void requireReset(RealmConfig realm, String action) {
        if (!resetEnabled(realm)) {
            count(realm, action, "disabled");
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
    }

    private void limitToken(RealmConfig realm, String action, String key) {
        if (!limiter.tryAcquire(key, TOKEN_PER_IP)) {
            count(realm, action, "rate_limited");
            throw new BaseAuthException(AuthError.RATE_LIMITED);
        }
    }

    private ActionToken verifyToken(RealmConfig realm, String token, ActionPurpose purpose, String action, AuthError.Error error) {
        try {
            return tokens.verify(token, realm.name(), purpose);
        } catch (InvalidActionTokenException e) {
            count(realm, action, e.reason() == InvalidActionTokenException.Reason.EXPIRED ? "expired" : "invalid");
            throw new BaseAuthException(error);
        }
    }

    private String adminToken(RealmConfig realm) {
        try {
            return adminService.getAdminAccessToken(realm);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    private KeycloakUserDto userById(RealmConfig realm, String adminToken, String id, String action, AuthError.Error error) {
        KeycloakUserDto user;
        try {
            user = admin.getUser(realm.name(), id, "Bearer " + adminToken);
        } catch (FeignException.NotFound e) {
            user = null;
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
        if (user == null || Boolean.FALSE.equals(user.enabled())) {
            count(realm, action, "invalid");
            throw new BaseAuthException(error);
        }
        return user;
    }

    private Optional<KeycloakUserDto> findUser(RealmConfig realm, String adminToken, String email) {
        return admin.getUsersByEmail(realm.name(), "Bearer " + adminToken, email, true).stream()
                .filter(u -> u.email() != null && u.email().equalsIgnoreCase(email))
                .filter(u -> !Boolean.FALSE.equals(u.enabled()))
                .findFirst();
    }

    private Optional<KeycloakCredentialDto> passwordCredential(RealmConfig realm, String adminToken, String userId) {
        return admin.getCredentials(realm.name(), userId, "Bearer " + adminToken).stream()
                .filter(c -> "password".equals(c.type()))
                .findFirst();
    }

    /** Changes whenever the password changes (Keycloak keeps the credential id and renews its creation time). */
    static String resetFingerprint(KeycloakCredentialDto password) {
        return ActionTokenService.fingerprint("password", nullToEmpty(password.id()), String.valueOf(password.createdDate()));
    }

    private static boolean sameFingerprint(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** Request language if the realm supports it, else the user's {@code locale} attribute, else the realm default. */
    String language(MailProperties.Realm config, String requested, KeycloakUserDto user) {
        if (config == null) {
            return "tr";
        }
        List<String> supported = new ArrayList<>(config.supportedLocales());
        supported.removeIf(l -> !mail.templates().supports(l));
        String fromRequest = MailProperties.normalizeLocale(requested);
        if (fromRequest != null && supported.contains(fromRequest)) {
            return fromRequest;
        }
        Map<String, List<String>> attributes = user == null ? null : user.attributes();
        if (attributes != null && attributes.get("locale") != null && !attributes.get("locale").isEmpty()) {
            String fromUser = MailProperties.normalizeLocale(attributes.get("locale").get(0));
            if (fromUser != null && supported.contains(fromUser)) {
                return fromUser;
            }
        }
        String fallback = config.effectiveDefaultLocale();
        return mail.templates().supports(fallback) ? fallback : "tr";
    }

    private static String link(String base, String token) {
        return base + "#t=" + token;
    }

    private static String resendKey(RealmConfig realm, String email) {
        return "resend-email|" + realm.name() + "|" + email;
    }

    static String providerName(String alias) {
        return switch (alias.toLowerCase(Locale.ROOT)) {
            case "google" -> "Google";
            case "apple" -> "Apple";
            case "facebook" -> "Facebook";
            case "microsoft" -> "Microsoft";
            default -> Character.toUpperCase(alias.charAt(0)) + alias.substring(1);
        };
    }

    private static String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private void count(RealmConfig realm, String action, String result) {
        Counter.builder("auth.gateway.action.requests")
                .description("Account email actions (forgot, reset, verify, resend) by result")
                .tag("realm", realm.name()).tag("action", action).tag("result", result)
                .register(meters).increment();
    }
}
