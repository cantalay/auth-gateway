package com.cantalay.authgateway.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Credential metadata from the Keycloak admin API (the secret itself is never returned). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakCredentialDto(
        String id,
        String type,
        Long createdDate
) {
}
