package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.*;
import com.cantalay.authgateway.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public TokenResponseDto login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public TokenResponseDto refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    public void logout(@AuthenticationPrincipal Jwt jwt,
                       @RequestBody LogoutRequest request) {
        authService.logout(request);
    }

    @GetMapping("/me")
    public UserMeResponse me(@AuthenticationPrincipal Jwt jwt) {
        return authService.getMe(jwt.getTokenValue());
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
    }

    @PatchMapping("/me")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateProfile(@AuthenticationPrincipal Jwt jwt,
                              @Valid @RequestBody UpdateProfileRequest request) {

        authService.updateProfile(jwt.getSubject(), request);
    }

    /* =========================
       POST /auth/change-password
       ========================= */
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@AuthenticationPrincipal Jwt jwt,
                               @Valid @RequestBody ChangePasswordRequest request) {

        String email = jwt.getClaimAsString("email");
        authService.changePassword(email, jwt.getSubject(), request);
    }

    /*
    https://keycloak.cantalay.com/auth/realms/todogi-auth/protocol/openid-connect/auth
    ?client_id=auth&response_type=code&scope=openid%20profile%20email&
    redirect_uri=todogi://callback&kc_idp_hint=google
     */
    @PostMapping("/social")
    public TokenResponseDto socialLogin(
            @Valid @RequestBody SocialLoginRequest request) {

        return authService.socialLogin(request);
    }
}
