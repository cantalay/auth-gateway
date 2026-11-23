package com.cantalay.authgateway.domain;

import java.util.List;

/**
 * Sign-in methods of the signed-in user.
 *
 * @param password  the account has a password
 * @param providers linked identity provider accounts
 */
public record IdentitiesResponse(boolean password, List<Provider> providers) {

    /**
     * @param alias identity provider alias in the realm ({@code google}, {@code apple})
     * @param email address of the provider account; {@code null} when the provider did not share one
     */
    public record Provider(String alias, String email) {
    }
}
