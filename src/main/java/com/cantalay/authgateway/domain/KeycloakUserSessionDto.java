package com.cantalay.authgateway.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** A user session from the Keycloak admin API ({@code start} and {@code lastAccess} in epoch milliseconds). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakUserSessionDto(
        String id,
        Long start,
        Long lastAccess
) {
}
