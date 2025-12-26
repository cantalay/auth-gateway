package com.cantalay.authgateway.domain;
import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenResponseDto(

        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("expires_in")
        long expiresIn,

        @JsonProperty("refresh_expires_in")
        long refreshExpiresIn,

        @JsonProperty("token_type")
        String tokenType,

        String scope
) {}
