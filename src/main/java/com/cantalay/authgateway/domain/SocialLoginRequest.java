package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.NotBlank;

public record SocialLoginRequest(
        @NotBlank String code,
        @NotBlank String redirectUri
) {}
