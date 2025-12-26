package com.cantalay.authgateway.domain;

public record LogoutRequest(
        String refreshToken
) {}
