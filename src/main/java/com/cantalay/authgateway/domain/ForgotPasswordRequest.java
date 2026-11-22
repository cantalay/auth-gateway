package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** @param locale optional email language ({@code tr}, {@code en}); falls back to the user's and the realm's language */
public record ForgotPasswordRequest(
        @Email @NotBlank String email,
        @Size(max = 16) String locale
) {
}
