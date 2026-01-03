package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private final AuthAdminService adminService;
    private final KeycloakClient keycloakClient;
    private final KeycloakAdminClient keycloakAdminClient;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.realm}")
    private String realm;

    public TokenResponseDto login(LoginRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("username", request.email());
        form.add("password", request.password());
        form.add("scope", "openid profile email");

        try {
            return keycloakClient.token(realm, form);
        } catch (FeignException.BadRequest e) {
            throw new BaseAuthException(AuthError.AUTH_DISABLED_ACCOUNT);
        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.INVALID_CREDENTIALS);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public TokenResponseDto refresh(RefreshRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", clientId);
        form.add("refresh_token", request.refreshToken());
        form.add("scope", "openid profile email");

        try {
            return keycloakClient.token(realm, form);
        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void logout(LogoutRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("refresh_token", request.refreshToken());

        try {
            keycloakClient.logout(realm, form);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void register(RegisterRequest request) {

        String token = adminService.getAdminAccessToken();

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
                    realm,
                    "Bearer " + token,
                    payload
            );

            // Get user ID by email to send verification email
            List<KeycloakUserDto> users = keycloakAdminClient.getUsersByEmail(
                    realm,
                    "Bearer " + token,
                    request.email(),
                    true
            );

            if (!users.isEmpty()) {
                KeycloakUserDto user = users.get(0);
                String userId = user.id();
                log.info("Sending verification email to user: {} (userId: {})", request.email(), userId);
                
                // Send verification email
                try {
                    keycloakAdminClient.sendVerificationEmail(
                            realm,
                            userId,
                            "Bearer " + token
                    );
                    log.info("Verification email sent successfully to: {}", request.email());
                } catch (FeignException e) {
                    log.error("Failed to send verification email to: {} (userId: {}). Error: {}", 
                            request.email(), userId, e.getMessage());
                    // Log error but don't fail registration if email sending fails
                    // User can request verification email later
                }
            } else {
                log.warn("User created but could not be found by email to send verification: {}", request.email());
            }
        } catch (FeignException.Conflict e) {
            throw new BaseAuthException(AuthError.USER_ALREADY_EXISTS);
        } catch (FeignException.Forbidden e) {
            throw new BaseAuthException(AuthError.FORBIDDEN_OPERATION);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }

    public void updateProfile(String userId, UpdateProfileRequest request) {

        String token = adminService.getAdminAccessToken();

        Map<String, Object> payload = Map.of(
                "firstName", request.firstName(),
                "lastName", request.lastName()
        );


        try {
            keycloakAdminClient.updateUser(
                    realm,
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

    public void changePassword(String userEmail,
                               String userId,
                               ChangePasswordRequest request) {

        // 1️⃣ Mevcut şifre doğru mu? (login ile doğrula)
        verifyPassword(userEmail, request.currentPassword());

        // 2️⃣ Admin API ile yeni şifre set et
        String token = adminService.getAdminAccessToken();

        Map<String, Object> payload = Map.of(
                "type", "password",
                "value", request.newPassword(),
                "temporary", false
        );

        try {
            keycloakAdminClient.resetPassword(
                    realm,
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

    public void verifyPassword(String email, String password) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("username", email);
        form.add("password", password);
        form.add("scope", "openid profile email");

        try {
            keycloakClient.token(realm, form);
        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.CURRENT_PASSWORD_INVALID);
        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }

    }

    public UserMeResponse getMe(String accessToken) {

        try {
            return keycloakClient.userInfo(
                    realm,
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

    public TokenResponseDto socialLogin(SocialLoginRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("code", request.code());
        form.add("redirect_uri", request.redirectUri());

        try {
            return keycloakClient.token(realm, form);

        } catch (FeignException.BadRequest e) {
            // invalid_grant, expired code, redirect mismatch
            throw new BaseAuthException(AuthError.INVALID_CREDENTIALS);

        } catch (FeignException.Unauthorized e) {
            throw new BaseAuthException(AuthError.INVALID_CREDENTIALS);

        } catch (FeignException e) {
            throw new BaseAuthException(AuthError.AUTH_SERVICE_UNAVAILABLE);
        }
    }
}