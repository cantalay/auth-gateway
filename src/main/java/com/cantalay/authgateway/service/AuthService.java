package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.PlatformLoginRequest;
import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
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

    public TokenResponseDto login(RealmConfig realm, LoginRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", realm.clientId());
        form.add("username", request.email());
        form.add("password", request.password());
        form.add("scope", loginScope(realm));

        try {
            return keycloakClient.token(realm.name(), form);
        } catch (FeignException.BadRequest | FeignException.Unauthorized e) {
            throw passwordGrantError(realm, e);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    /** Login scope; realms of mobile apps ask for an offline token (the session lives while the app is used). */
    public static String loginScope(RealmConfig realm) {
        return realm.offlineAccess() ? "openid profile email offline_access" : "openid profile email";
    }

    public TokenResponseDto refresh(RealmConfig realm, RefreshRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", realm.clientId());
        form.add("refresh_token", request.refreshToken());
        // Offline token: the refresh keeps the scopes of the original grant (asking again for offline_access would be
        // rejected for sessions that started before the realm granted it).
        if (!realm.offlineAccess()) {
            form.add("scope", "openid profile email");
        }

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

                // Send verification email
                try {
                    keycloakAdminClient.sendVerificationEmail(
                            realm.name(),
                            userId,
                            "Bearer " + token
                    );
                    log.info("Verification email sent in realm {} to user {}", realm.name(), userId);
                } catch (FeignException e) {
                    log.error("Failed to send verification email in realm {} to user {}: HTTP {}",
                            realm.name(), userId, e.status());
                    // Log error but don't fail registration if email sending fails
                    // User can request verification email later
                }
            } else {
                log.warn("User created in realm {} but could not be found by email {}", realm.name(), maskEmail(request.email()));
            }
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

    /**
     * Deletes the signed-in user's account from the realm (its sessions go with it). The application deletes its own
     * data for the user before calling this; App Store and Google Play require that an account can be deleted in-app.
     */
    public void deleteAccount(RealmConfig realm, String userId) {

        String token = adminService.getAdminAccessToken(realm);

        try {
            keycloakAdminClient.deleteUser(realm.name(), userId, "Bearer " + token);
        } catch (FeignException.NotFound e) {
            // already gone: the outcome the caller wanted
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

    /**
     * Game Center / Play Games sign-in: the realm's platform client runs the platform-identity direct grant flow
     * (talay-keycloak-providers), which verifies the platform token and finds or creates the linked user.
     */
    public TokenResponseDto platformLogin(RealmConfig realm, PlatformLoginRequest request) {
        if (realm.platformClientId() == null) {
            throw new BaseAuthException(AuthError.PLATFORM_LOGIN_DISABLED);
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", realm.platformClientId());
        form.add("platform", request.platform());
        form.add("platform_token", request.token());
        form.add("scope", loginScope(realm));
        try {
            return keycloakClient.token(realm.name(), form);
        } catch (FeignException.BadRequest | FeignException.Unauthorized e) {
            if (KeycloakErrors.isClientMisconfigured(e)) {
                log.error("Keycloak client {} in realm {} rejected the platform grant", realm.platformClientId(), realm.name());
                throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
            }
            throw new BaseAuthException(AuthError.PLATFORM_TOKEN_INVALID);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    /** Links a platform identity to the signed-in user (Keycloak checks the token; another account's identity is 409). */
    public java.util.Map<String, Object> platformLink(RealmConfig realm, String accessToken, PlatformLoginRequest request) {
        if (realm.platformClientId() == null) {
            throw new BaseAuthException(AuthError.PLATFORM_LOGIN_DISABLED);
        }
        try {
            return keycloakClient.platformLink(realm.name(), "Bearer " + accessToken,
                    java.util.Map.of("platform", request.platform(), "token", request.token()));
        } catch (FeignException.Conflict e) {
            throw new BaseAuthException(AuthError.PLATFORM_ALREADY_LINKED);
        } catch (FeignException.Unauthorized | FeignException.BadRequest e) {
            throw new BaseAuthException(AuthError.PLATFORM_TOKEN_INVALID);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public java.util.Map<String, Boolean> platformLinks(RealmConfig realm, String accessToken) {
        if (realm.platformClientId() == null) {
            throw new BaseAuthException(AuthError.PLATFORM_LOGIN_DISABLED);
        }
        try {
            return keycloakClient.platformLinks(realm.name(), "Bearer " + accessToken);
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
