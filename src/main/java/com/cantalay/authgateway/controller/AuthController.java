package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.identity.IdentityMethodsService;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

/**
 * Authentication API. Every endpoint is served for an explicit realm at {@code /auth/{realm}/...};
 * the legacy {@code /auth/...} paths keep serving the default realm.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;
    private final RealmRegistry realms;
    /** {@code null} without identity methods: {@code /social} then behaves as in realms where they are off. */
    private final IdentityMethodsService identityMethods;

    public AuthController(AuthService authService, RealmRegistry realms) {
        this(authService, realms, null);
    }

    @Autowired
    public AuthController(AuthService authService, RealmRegistry realms, IdentityMethodsService identityMethods) {
        this.authService = authService;
        this.realms = realms;
        this.identityMethods = identityMethods;
    }

    @PostMapping({"/login", "/{realm}/login"})
    public TokenResponseDto login(@PathVariable(required = false) String realm,
                                  @Valid @RequestBody LoginRequest request) {
        RealmConfig config = realms.resolve(realm);
        log.info("Login attempt in realm {} for {}", config.name(), maskEmail(request.email()));
        TokenResponseDto response = authService.login(config, request);
        log.info("Login successful in realm {} for {}", config.name(), maskEmail(request.email()));
        return response;
    }

    @PostMapping({"/refresh", "/{realm}/refresh"})
    public TokenResponseDto refresh(@PathVariable(required = false) String realm,
                                    @RequestBody RefreshRequest request) {
        return authService.refresh(realms.resolve(realm), request);
    }

    @PostMapping({"/logout", "/{realm}/logout"})
    public void logout(@PathVariable(required = false) String realm,
                       @AuthenticationPrincipal Jwt jwt,
                       @RequestBody LogoutRequest request) {
        RealmConfig config = realmOf(realm, jwt);
        log.info("Logout request in realm {} for user {}", config.name(), jwt.getSubject());
        authService.logout(config, request);
    }

    @GetMapping({"/me", "/{realm}/me"})
    public UserMeResponse me(@PathVariable(required = false) String realm,
                             @AuthenticationPrincipal Jwt jwt) {
        RealmConfig config = realmOf(realm, jwt);
        return authService.getMe(config, jwt.getTokenValue());
    }

    @PostMapping({"/register", "/{realm}/register"})
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@PathVariable(required = false) String realm,
                         @Valid @RequestBody RegisterRequest request,
                         jakarta.servlet.http.HttpServletRequest http) {
        RealmConfig config = realms.resolve(realm);
        log.info("Registration attempt in realm {} for {}", config.name(), maskEmail(request.email()));
        authService.register(config, request, com.cantalay.authgateway.account.ClientIp.of(http));
        log.info("Registration successful in realm {} for {}", config.name(), maskEmail(request.email()));
    }

    @PatchMapping({"/me", "/{realm}/me"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateProfile(@PathVariable(required = false) String realm,
                              @AuthenticationPrincipal Jwt jwt,
                              @Valid @RequestBody UpdateProfileRequest request) {
        RealmConfig config = realmOf(realm, jwt);
        log.info("Profile update in realm {} for user {}", config.name(), jwt.getSubject());
        authService.updateProfile(config, jwt.getSubject(), request);
    }

    /** Account deletion (App Store 5.1.1(v), Google Play account deletion policy): removes the user from the realm. */
    @DeleteMapping({"/me", "/{realm}/me"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteAccount(@PathVariable(required = false) String realm,
                              @AuthenticationPrincipal Jwt jwt) {
        RealmConfig config = realmOf(realm, jwt);
        log.info("Account deletion in realm {} for user {}", config.name(), jwt.getSubject());
        authService.deleteAccount(config, jwt.getSubject());
        log.info("Account deleted in realm {} for user {}", config.name(), jwt.getSubject());
    }

    @PostMapping({"/change-password", "/{realm}/change-password"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@PathVariable(required = false) String realm,
                               @AuthenticationPrincipal Jwt jwt,
                               @Valid @RequestBody ChangePasswordRequest request) {
        RealmConfig config = realmOf(realm, jwt);
        log.info("Password change in realm {} for user {}", config.name(), jwt.getSubject());
        authService.changePassword(config, jwt.getClaimAsString("email"), jwt.getSubject(), request);
    }

    /*
    Social login: the client opens
    https://auth.cantalay.com/realms/<realm>/protocol/openid-connect/auth
    ?client_id=<realm client>&response_type=code&scope=openid%20profile%20email&
    redirect_uri=<app>://callback&kc_idp_hint=google
    and posts the returned code here (with provider=google). With identity methods on, mode=link (and the account's
    Bearer token) adds the provider to the signed-in account instead (IdentityMethodsService). When Keycloak refuses the
    sign-in the redirect has error/error_description instead of a code; posting those gives the translated error
    (409 account_exists_unverified when an account with the address exists but is not confirmed).
     */
    @PostMapping({"/social", "/{realm}/social"})
    public TokenResponseDto socialLogin(@PathVariable(required = false) String realm,
                                        @Valid @RequestBody SocialLoginRequest request) {
        RealmConfig config = realms.resolve(realm);
        if (request.isCallbackError()) {
            // Keycloak refused the sign-in (no code): e.g. error_description=account_exists_unverified → 409
            throw identityMethods != null ? identityMethods.callbackError(config, request)
                    : IdentityMethodsService.translateCallbackError(request);
        }
        if (identityMethods != null) {
            log.info("Social {} attempt in realm {}", "link".equals(request.mode()) ? "link" : "login", config.name());
            return identityMethods.social(config, bearerToken(), request);
        }
        if ("link".equals(request.mode())) {
            throw new BaseAuthException(AuthError.REALM_FEATURE_DISABLED);
        }
        log.info("Social login attempt in realm {}", config.name());
        return authService.socialLogin(config, request);
    }

    /** Game Center / Play Games sign-in (talay-keycloak-providers platform-identity). */
    @PostMapping({"/platform", "/{realm}/platform"})
    public TokenResponseDto platformLogin(@PathVariable(required = false) String realm,
                                          @Valid @RequestBody PlatformLoginRequest request) {
        RealmConfig config = realms.resolve(realm);
        log.info("Platform sign-in attempt in realm {} ({})", config.name(), request.platform());
        return authService.platformLogin(config, request);
    }

    /** Links a Game Center / Play Games identity to the signed-in account (sign-in on another device then opens it). */
    @PostMapping({"/platform/link", "/{realm}/platform/link"})
    public java.util.Map<String, Object> platformLink(@PathVariable(required = false) String realm,
                                                      @AuthenticationPrincipal Jwt jwt,
                                                      @Valid @RequestBody PlatformLoginRequest request) {
        RealmConfig config = realmOf(realm, jwt);
        log.info("Platform link in realm {} for user {} ({})", config.name(), jwt.getSubject(), request.platform());
        return authService.platformLink(config, jwt.getTokenValue(), request);
    }

    @GetMapping({"/platform/links", "/{realm}/platform/links"})
    public java.util.Map<String, Boolean> platformLinks(@PathVariable(required = false) String realm,
                                                        @AuthenticationPrincipal Jwt jwt) {
        return authService.platformLinks(realmOf(realm, jwt), jwt.getTokenValue());
    }

    /**
     * Access token of a request to a public endpoint ({@code /social}), {@code null} without one. Spring Security
     * authenticates a Bearer token on every path (an invalid one is 401 before the controller, as before).
     */
    private static Jwt bearerToken() {
        org.springframework.security.core.Authentication authentication =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getPrincipal() instanceof Jwt jwt ? jwt : null;
    }

    /** The token must have been issued by the realm addressed in the path. */
    private RealmConfig realmOf(String realm, Jwt jwt) {
        RealmConfig config = realms.resolve(realm);
        if (!config.issuerUri().equals(jwt.getClaimAsString("iss"))) {
            throw new BaseAuthException(AuthError.REALM_MISMATCH);
        }
        return config;
    }
}
