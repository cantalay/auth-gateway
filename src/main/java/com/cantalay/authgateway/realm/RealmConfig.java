package com.cantalay.authgateway.realm;

/**
 * Keycloak settings for one realm served by the gateway.
 *
 * @param name              realm name as used in paths and Keycloak URLs
 * @param clientId          public client with direct access grants used for login/refresh/logout
 * @param adminClientId     confidential service-account client with realm-management user roles
 * @param adminClientSecret secret of {@code adminClientId}
 * @param issuerUri         expected {@code iss} claim of tokens issued by this realm
 */
public record RealmConfig(
        String name,
        String clientId,
        String adminClientId,
        String adminClientSecret,
        String issuerUri
) {
    @Override
    public String toString() {
        return "RealmConfig[name=" + name + ", clientId=" + clientId + ", adminClientId=" + adminClientId
                + ", issuerUri=" + issuerUri + "]";
    }
}
