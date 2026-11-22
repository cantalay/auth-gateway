package com.cantalay.authgateway.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Link between a user and an identity provider account (Google, Apple, ...). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakFederatedIdentityDto(
        String identityProvider,
        String userId,
        String userName
) {
}
