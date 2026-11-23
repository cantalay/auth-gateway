package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.NotBlank;

/**
 * @param mode {@code login} (also when absent): sign in with the provider; {@code link}: add the provider to the
 *             account of the request's Bearer token (realms with identity methods only)
 */
public record SocialLoginRequest(
        @NotBlank String code,
        @NotBlank String redirectUri,
        String mode
) {
    public SocialLoginRequest(String code, String redirectUri) {
        this(code, redirectUri, null);
    }
}
