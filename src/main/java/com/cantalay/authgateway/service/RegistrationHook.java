package com.cantalay.authgateway.service;

import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.RegisterRequest;
import com.cantalay.authgateway.realm.RealmConfig;

import java.util.List;
import java.util.Map;

/** What happens around a registration besides creating the Keycloak user (verification and welcome emails). */
public interface RegistrationHook {

    /**
     * Called before the user is created; may refuse the registration (e.g. 429 {@code rate_limited}).
     *
     * @param clientIp caller address, {@code null} when unknown (no address limit then)
     */
    default void beforeRegistration(RealmConfig realm, RegisterRequest request, String clientIp) {
    }

    /** Extra Keycloak attributes for the new user (e.g. {@code locale}); empty keeps the original payload. */
    default Map<String, List<String>> userAttributes(RealmConfig realm, RegisterRequest request) {
        return Map.of();
    }

    /** Called after the user was created; must not fail the registration. */
    void registered(RealmConfig realm, KeycloakUserDto user, String adminToken, RegisterRequest request);
}
