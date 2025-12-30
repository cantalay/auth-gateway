package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService;

    @PostMapping("/login")
    public TokenResponseDto login(@RequestBody LoginRequest request) {
        log.info("Login attempt for email: {}", request.email());
        TokenResponseDto response = authService.login(request);
        log.info("Login successful for email: {}", request.email());
        return response;
    }

    @PostMapping("/refresh")
    public TokenResponseDto refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    public void logout(@AuthenticationPrincipal Jwt jwt,
                       @RequestBody LogoutRequest request) {
        String subject = jwt.getSubject();
        log.info("Logout request for user: {}", subject);
        authService.logout(request);
        log.info("Logout successful for user: {}", subject);
    }

    @GetMapping("/me")
    public UserMeResponse me(@AuthenticationPrincipal Jwt jwt) {
        String subject = jwt.getSubject();
        log.info("Get user info request for user: {}", subject);
        UserMeResponse response = authService.getMe(jwt.getTokenValue());
        log.info("User info retrieved successfully for user: {}", subject);
        return response;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration attempt for email: {}", request.email());
        authService.register(request);
        log.info("Registration successful for email: {}", request.email());
    }

    @PatchMapping("/me")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateProfile(@AuthenticationPrincipal Jwt jwt,
                              @Valid @RequestBody UpdateProfileRequest request) {
        String subject = jwt.getSubject();
        log.info("Profile update request for user: {}", subject);
        authService.updateProfile(subject, request);
        log.info("Profile update successful for user: {}", subject);
    }

    /* =========================
       POST /auth/change-password
       ========================= */
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@AuthenticationPrincipal Jwt jwt,
                               @Valid @RequestBody ChangePasswordRequest request) {
        String email = jwt.getClaimAsString("email");
        String subject = jwt.getSubject();
        log.info("Password change request for user: {} (email: {})", subject, email);
        authService.changePassword(email, subject, request);
        log.info("Password change successful for user: {} (email: {})", subject, email);
    }

    /*
    https://keycloak.cantalay.com/auth/realms/todogi-auth/protocol/openid-connect/auth
    ?client_id=auth&response_type=code&scope=openid%20profile%20email&
    redirect_uri=todogi://callback&kc_idp_hint=google
     */
    @PostMapping("/social")
    public TokenResponseDto socialLogin(
            @Valid @RequestBody SocialLoginRequest request) {
        log.info("Social login attempt with redirectUri: {}", request.redirectUri());
        TokenResponseDto response = authService.socialLogin(request);
        log.info("Social login successful with redirectUri: {}", request.redirectUri());
        return response;
    }
}
