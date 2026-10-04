package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.mail.MailProperties;
import com.cantalay.authgateway.mail.WelcomeMailService;
import com.cantalay.authgateway.realm.KeycloakErrors;
import com.cantalay.authgateway.realm.RealmConfig;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private final AuthAdminService adminService;
    private final KeycloakClient keycloakClient;
    private final KeycloakAdminClient keycloakAdminClient;
    private final WelcomeMailService welcomeMailService;
    private final MailProperties mailProperties;

    public TokenResponseDto login(RealmConfig realm, LoginRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", realm.clientId());
        form.add("username", request.email());
        form.add("password", request.password());
        form.add("scope", "openid profile email");

        try {
            return keycloakClient.token(realm.name(), form);
        } catch (FeignException.BadRequest | FeignException.Unauthorized e) {
            throw passwordGrantError(realm, e);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public TokenResponseDto refresh(RealmConfig realm, RefreshRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", realm.clientId());
        form.add("refresh_token", request.refreshToken());
        form.add("scope", "openid profile email");

        try {
            return keycloakClient.token(realm.name(), form);
        } catch (FeignException.BadRequest | FeignException.Unauthorized e) {
            if (KeycloakErrors.isClientMisconfigured(e)) {
                log.error("Keycloak client {} in realm {} rejected refresh_token grant", realm.clientId(), realm.name());
                throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
            }
            throw new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void logout(RealmConfig realm, LogoutRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", realm.clientId());
        form.add("refresh_token", request.refreshToken());

        try {
            keycloakClient.logout(realm.name(), form);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void register(RealmConfig realm, RegisterRequest request) {

        String token = adminService.getAdminAccessToken(realm);

        Map<String, Object> payload = Map.of(
                "username", request.email(),
                "email", request.email(),
                "firstName", request.firstName(),
                "lastName", request.lastName(),
                "enabled", true,
                "emailVerified", false,
                "credentials", List.of(
                        Map.of(
                                "type", "password",
                                "value", request.password(),
                                "temporary", false
                        )
                )
        );

        try {
            keycloakAdminClient.createUser(
                    realm.name(),
                    "Bearer " + token,
                    payload
            );

            // Get user ID by email to send verification email
            List<KeycloakUserDto> users = keycloakAdminClient.getUsersByEmail(
                    realm.name(),
                    "Bearer " + token,
                    request.email(),
                    true
            );

            if (!users.isEmpty()) {
                KeycloakUserDto user = users.get(0);
                String userId = user.id();
                log.info("Sending verification email in realm {} to user {}", realm.name(), userId);

                // Send verification email (Keycloak) — failures don't fail registration,
                // the user can ask for it again via /resend-verification.
                sendVerification(realm, userId, token);
            } else {
                log.warn("User created in realm {} but could not be found by email {}", realm.name(), maskEmail(request.email()));
            }
            welcomeMailService.sendWelcome(realm.name(), request.email(), request.firstName());
        } catch (FeignException.Conflict e) {
            throw new BaseAuthException(AuthError.USER_ALREADY_EXISTS);
        } catch (FeignException.BadRequest e) {
            throw new BaseAuthException(KeycloakErrors.isPasswordPolicyViolation(e)
                    ? AuthError.PASSWORD_POLICY_VIOLATION
                    : AuthError.REGISTRATION_REJECTED);
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Re-sends the Keycloak verification email when the address belongs to an unverified user.
     * Never reveals whether the address is registered.
     */
    public void resendVerification(RealmConfig realm, ResendVerificationRequest request) {
        try {
            String token = adminService.getAdminAccessToken(realm);
            List<KeycloakUserDto> users = keycloakAdminClient.getUsersByEmail(
                    realm.name(), "Bearer " + token, request.email(), true);
            users.stream()
                    .filter(user -> !Boolean.TRUE.equals(user.emailVerified()))
                    .findFirst()
                    .ifPresent(user -> sendVerification(realm, user.id(), token));
        } catch (FeignException e) {
            log.error("Resend verification failed in realm {}: HTTP {}", realm.name(), e.status());
        }
    }

    private void sendVerification(RealmConfig realm, String userId, String adminToken) {
        MailProperties.Realm mail = mailProperties.realm(realm.name());
        String clientId = mail == null ? null : emptyToNull(mail.getVerifyClientId());
        String redirectUri = mail == null ? null : emptyToNull(mail.getVerifyRedirectUri());
        if (clientId == null || redirectUri == null) {
            clientId = null;
            redirectUri = null;
        }
        try {
            keycloakAdminClient.sendVerificationEmail(realm.name(), userId, "Bearer " + adminToken, clientId, redirectUri);
            log.info("Verification email sent in realm {} to user {}", realm.name(), userId);
        } catch (FeignException e) {
            log.error("Failed to send verification email in realm {} to user {}: HTTP {}", realm.name(), userId, e.status());
        }
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    public void updateProfile(RealmConfig realm, String userId, UpdateProfileRequest request) {

        String token = adminService.getAdminAccessToken(realm);

        try {
            keycloakAdminClient.updateUser(
                    realm.name(),
                    userId,
                    "Bearer " + token,
                    Map.of(
                            "firstName", request.firstName(),
                            "lastName", request.lastName()
                    )
            );
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void changePassword(RealmConfig realm,
                               String userEmail,
                               String userId,
                               ChangePasswordRequest request) {

        // 1️⃣ Mevcut şifre doğru mu? (login ile doğrula)
        verifyPassword(realm, userEmail, request.currentPassword());

        // 2️⃣ Admin API ile yeni şifre set et
        String token = adminService.getAdminAccessToken(realm);

        try {
            keycloakAdminClient.resetPassword(
                    realm.name(),
                    userId,
                    "Bearer " + token,
                    Map.of(
                            "type", "password",
                            "value", request.newPassword(),
                            "temporary", false
                    )
            );
        } catch (FeignException.BadRequest e) {
            throw new BaseAuthException(AuthError.PASSWORD_POLICY_VIOLATION);
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void verifyPassword(RealmConfig realm, String email, String password) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", realm.clientId());
        form.add("username", email);
        form.add("password", password);
        form.add("scope", "openid profile email");

        try {
            keycloakClient.token(realm.name(), form);
        } catch (FeignException.BadRequest | FeignException.Unauthorized e) {
            if (KeycloakErrors.isClientMisconfigured(e)) {
                log.error("Keycloak client {} in realm {} rejected password grant", realm.clientId(), realm.name());
                throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
            }
            throw new BaseAuthException(AuthError.CURRENT_PASSWORD_INVALID);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }

    }

    public UserMeResponse getMe(RealmConfig realm, String accessToken) {

        try {
            return keycloakClient.userInfo(
                    realm.name(),
                    "Bearer " + accessToken
            );
        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public TokenResponseDto socialLogin(RealmConfig realm, SocialLoginRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", realm.clientId());
        form.add("code", request.code());
        form.add("redirect_uri", request.redirectUri());

        try {
            return keycloakClient.token(realm.name(), form);

        } catch (FeignException.BadRequest e) {
            // invalid_grant, expired code, redirect mismatch
            throw new BaseAuthException(AuthError.INVALID_CREDENTIALS);

        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.INVALID_CREDENTIALS);

        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    private BaseAuthException passwordGrantError(RealmConfig realm, FeignException e) {
        if (KeycloakErrors.isClientMisconfigured(e)) {
            log.error("Keycloak client {} in realm {} rejected password grant (HTTP {})", realm.clientId(), realm.name(), e.status());
            return new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
        if (KeycloakErrors.isAccountNotUsable(e)) {
            return new BaseAuthException(AuthError.AUTH_DISABLED_ACCOUNT);
        }
        return new BaseAuthException(AuthError.INVALID_CREDENTIALS);
    }
}
