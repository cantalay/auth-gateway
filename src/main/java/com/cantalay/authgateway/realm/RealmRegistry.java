package com.cantalay.authgateway.realm;

import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Realms the gateway is allowed to serve. The default realm keeps the original single-realm
 * configuration ({@code KEYCLOAK_REALM}, {@code KEYCLOAK_ADMIN_*}) so existing clients calling
 * {@code /auth/*} keep working; additional realms come from {@link GatewayProperties}.
 */
@Component
public class RealmRegistry {

    private final String defaultRealm;
    private final Map<String, RealmConfig> realms;

    public RealmRegistry(String baseUrl, String defaultRealm, String defaultClientId, String defaultAdminClientId,
                         String defaultAdminClientSecret, String defaultIssuerUri, GatewayProperties properties) {
        this(baseUrl, defaultRealm, defaultClientId, defaultAdminClientId, defaultAdminClientSecret, defaultIssuerUri,
                false, properties);
    }

    /**
     * @param defaultOfflineAccess {@code KEYCLOAK_OFFLINE_ACCESS}: login in the default realm asks for
     *                             {@code offline_access} (as {@code GATEWAY_REALMS_<REALM>_OFFLINEACCESS} does for the
     *                             other realms); off by default
     */
    public RealmRegistry(String baseUrl, String defaultRealm, String defaultClientId, String defaultAdminClientId,
                         String defaultAdminClientSecret, String defaultIssuerUri, boolean defaultOfflineAccess,
                         GatewayProperties properties) {
        this(baseUrl, defaultRealm, defaultClientId, defaultAdminClientId, defaultAdminClientSecret, defaultIssuerUri,
                defaultOfflineAccess, false, properties);
    }

    /**
     * @param defaultIdentityMethods {@code KEYCLOAK_IDENTITY_METHODS}: sign-in method endpoints in the default realm
     *                               (as {@code GATEWAY_REALMS_<REALM>_IDENTITYMETHODS} does for the other realms); off
     *                               by default
     */
    @Autowired
    public RealmRegistry(
            @Value("${keycloak.base-url}") String baseUrl,
            @Value("${keycloak.realm}") String defaultRealm,
            @Value("${keycloak.client-id:auth}") String defaultClientId,
            @Value("${keycloak.admin.client-id}") String defaultAdminClientId,
            @Value("${keycloak.admin.client-secret}") String defaultAdminClientSecret,
            @Value("${keycloak.issuer-uri:}") String defaultIssuerUri,
            @Value("${keycloak.offline-access:false}") boolean defaultOfflineAccess,
            @Value("${keycloak.identity-methods:false}") boolean defaultIdentityMethods,
            GatewayProperties properties
    ) {
        String base = trimTrailingSlash(baseUrl);
        Map<String, RealmConfig> configured = new LinkedHashMap<>();
        configured.put(defaultRealm, new RealmConfig(
                defaultRealm,
                defaultClientId,
                defaultAdminClientId,
                defaultAdminClientSecret,
                StringUtils.hasText(defaultIssuerUri) ? defaultIssuerUri : issuer(base, defaultRealm),
                defaultOfflineAccess,
                null,
                defaultIdentityMethods
        ));
        properties.getRealms().forEach((name, realm) -> {
            String realmName = name.toLowerCase();
            if (configured.containsKey(realmName)) {
                throw new IllegalStateException("Realm configured twice: " + realmName);
            }
            if (!StringUtils.hasText(realm.getAdminClientSecret())) {
                throw new IllegalStateException("gateway.realms." + realmName + ".admin-client-secret is required");
            }
            configured.put(realmName, new RealmConfig(
                    realmName,
                    StringUtils.hasText(realm.getClientId()) ? realm.getClientId() : realmName + "-gateway",
                    StringUtils.hasText(realm.getAdminClientId()) ? realm.getAdminClientId() : realmName + "-gateway-admin",
                    realm.getAdminClientSecret(),
                    StringUtils.hasText(realm.getIssuerUri()) ? realm.getIssuerUri() : issuer(base, realmName),
                    realm.isOfflineAccess(),
                    realm.isPlatformLogin()
                            ? (StringUtils.hasText(realm.getPlatformClientId()) ? realm.getPlatformClientId() : realmName + "-platform")
                            : null,
                    realm.isIdentityMethods()
            ));
        });
        this.defaultRealm = defaultRealm;
        this.realms = Collections.unmodifiableMap(configured);
    }

    public RealmConfig defaultRealm() {
        return realms.get(defaultRealm);
    }

    /** Resolves a realm from a request path; {@code null} selects the default realm. */
    public RealmConfig resolve(String name) {
        if (name == null) {
            return defaultRealm();
        }
        RealmConfig realm = realms.get(name);
        if (realm == null) {
            throw new BaseAuthException(AuthError.REALM_NOT_FOUND);
        }
        return realm;
    }

    public Optional<RealmConfig> byIssuer(String issuer) {
        return realms.values().stream().filter(realm -> realm.issuerUri().equals(issuer)).findFirst();
    }

    public Collection<RealmConfig> all() {
        return realms.values();
    }

    private static String issuer(String baseUrl, String realm) {
        return baseUrl + "/realms/" + realm;
    }

    private static String trimTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
