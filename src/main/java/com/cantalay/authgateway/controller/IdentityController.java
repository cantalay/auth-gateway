package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.IdentitiesResponse;
import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.identity.IdentityMethodsService;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sign-in methods of the signed-in user (password, Google, Apple). Opt-in per realm; linking is
 * {@code POST /social} with {@code mode=link} ({@link AuthController}). Served at {@code /auth/{realm}/...} and, for
 * the default realm, {@code /auth/...}.
 */
@RestController
@RequestMapping("/auth")
public class IdentityController {

    private final IdentityMethodsService identityMethods;
    private final RealmRegistry realms;

    public IdentityController(IdentityMethodsService identityMethods, RealmRegistry realms) {
        this.identityMethods = identityMethods;
        this.realms = realms;
    }

    /** {@code {password, providers: [{alias, email}]}}. */
    @GetMapping({"/identities", "/{realm}/identities"})
    public IdentitiesResponse identities(@PathVariable(required = false) String realm,
                                         @AuthenticationPrincipal Jwt jwt) {
        RealmConfig config = realmOf(realm, jwt);
        return identityMethods.list(config, jwt.getSubject());
    }

    /** 204, also when the provider is not linked; 409 {@code last_method} when it is the only way to sign in. */
    @DeleteMapping({"/identities/{alias}", "/{realm}/identities/{alias}"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unlink(@PathVariable(required = false) String realm,
                       @PathVariable String alias,
                       @AuthenticationPrincipal Jwt jwt) {
        RealmConfig config = realmOf(realm, jwt);
        identityMethods.unlink(config, jwt.getSubject(), alias);
    }

    /** The token must have been issued by the realm addressed in the path. */
    private RealmConfig realmOf(String realm, Jwt jwt) {
        RealmConfig config = realms.resolve(realm);
        if (jwt == null) {
            throw new BaseAuthException(AuthError.TOKEN_INVALID_OR_EXPIRED);
        }
        if (!config.issuerUri().equals(jwt.getClaimAsString("iss"))) {
            throw new BaseAuthException(AuthError.REALM_MISMATCH);
        }
        return config;
    }
}
