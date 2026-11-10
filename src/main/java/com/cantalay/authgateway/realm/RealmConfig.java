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
 * @param platformClientId  client bound to the platform-identity direct grant flow (Game Center / Play Games sign-in,
 *                          talay-keycloak-providers); {@code null} when the realm has no platform sign-in
 */
public record RealmConfig(
        String name,
        String clientId,
        String adminClientId,
        String adminClientSecret,
        String issuerUri,
        boolean offlineAccess,
        String platformClientId
) {
    public RealmConfig(String name, String clientId, String adminClientId, String adminClientSecret, String issuerUri) {
        this(name, clientId, adminClientId, adminClientSecret, issuerUri, false, null);
    }

    public RealmConfig(String name, String clientId, String adminClientId, String adminClientSecret, String issuerUri, boolean offlineAccess) {
        this(name, clientId, adminClientId, adminClientSecret, issuerUri, offlineAccess, null);
    }

    @Override
    public String toString() {
        return "RealmConfig[name=" + name + ", clientId=" + clientId + ", adminClientId=" + adminClientId
                + ", issuerUri=" + issuerUri + ", offlineAccess=" + offlineAccess + ", platformClientId=" + platformClientId + "]";
    }
}
