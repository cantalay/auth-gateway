package com.cantalay.authgateway.service;

import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.RegisterRequest;
import com.cantalay.authgateway.realm.RealmConfig;

import java.util.List;
import java.util.Map;

/** What happens around a registration besides creating the Keycloak user (verification and welcome emails). */
public interface RegistrationHook {

    /** Extra Keycloak attributes for the new user (e.g. {@code locale}); empty keeps the original payload. */
    default Map<String, List<String>> userAttributes(RealmConfig realm, RegisterRequest request) {
        return Map.of();
    }

    /** Called after the user was created; must not fail the registration. */
    void registered(RealmConfig realm, KeycloakUserDto user, String adminToken, RegisterRequest request);
}
