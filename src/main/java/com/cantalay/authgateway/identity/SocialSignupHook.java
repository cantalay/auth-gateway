package com.cantalay.authgateway.identity;

import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.realm.RealmConfig;

/**
 * What happens when a Google / Apple sign-in has just created the account (Keycloak first broker login): the password
 * registration hook never runs for it, so e.g. the welcome email is sent from here. Must not throw or block.
 */
public interface SocialSignupHook {

    void accountCreated(RealmConfig realm, KeycloakUserDto user);
}
