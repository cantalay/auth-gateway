package com.cantalay.authgateway.realm;

/**
 * Keycloak settings for one realm served by the gateway.
 *
 * @param name              realm name as used in paths and Keycloak URLs
 * @param clientId          public client with direct access grants used for login/refresh/logout
 * @param adminClientId     confidential service-account client with realm-management user roles
 * @param adminClientSecret secret of {@code adminClientId}
 * @param issuerUri         expected {@code iss} claim of tokens issued by this realm
 * @param offlineAccess     login asks for {@code offline_access}: mobile apps keep the session while they are used (no
 *                          SSO max lifespan); the realm must grant the {@code offline_access} role
 */
public record RealmConfig(
        String name,
        String clientId,
        String adminClientId,
        String adminClientSecret,
        String issuerUri,
        boolean offlineAccess
) {
    public RealmConfig(String name, String clientId, String adminClientId, String adminClientSecret, String issuerUri) {
        this(name, clientId, adminClientId, adminClientSecret, issuerUri, false);
    }

    @Override
    public String toString() {
        return "RealmConfig[name=" + name + ", clientId=" + clientId + ", adminClientId=" + adminClientId
                + ", issuerUri=" + issuerUri + ", offlineAccess=" + offlineAccess + "]";
    }
}
