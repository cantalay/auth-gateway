package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** The realm's password policy is checked by Keycloak (400 {@code password_policy}). */
public record ResetPasswordRequest(
        @NotBlank String token,
        @NotBlank @Size(max = 256) String newPassword
) {
}
