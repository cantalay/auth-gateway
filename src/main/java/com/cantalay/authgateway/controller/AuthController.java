package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;
    private final RealmRegistry realms;

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
                         @Valid @RequestBody RegisterRequest request) {
        RealmConfig config = realms.resolve(realm);
        log.info("Registration attempt in realm {} for {}", config.name(), maskEmail(request.email()));
        authService.register(config, request);
        log.info("Registration successful in realm {} for {}", config.name(), maskEmail(request.email()));
    }

    @PostMapping({"/resend-verification", "/{realm}/resend-verification"})
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void resendVerification(@PathVariable(required = false) String realm,
                                   @Valid @RequestBody ResendVerificationRequest request) {
        RealmConfig config = realms.resolve(realm);
        log.info("Verification email requested in realm {} for {}", config.name(), maskEmail(request.email()));
        authService.resendVerification(config, request);
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
    and posts the returned code here.
     */
    @PostMapping({"/social", "/{realm}/social"})
    public TokenResponseDto socialLogin(@PathVariable(required = false) String realm,
                                        @Valid @RequestBody SocialLoginRequest request) {
        RealmConfig config = realms.resolve(realm);
        log.info("Social login attempt in realm {}", config.name());
        return authService.socialLogin(config, request);
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
