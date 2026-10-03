package com.cantalay.authgateway.realm;

import com.cantalay.authgateway.exception.AuthError;
import com.cantalay.authgateway.exception.BaseAuthException;
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

    public RealmRegistry(
            @Value("${keycloak.base-url}") String baseUrl,
            @Value("${keycloak.realm}") String defaultRealm,
            @Value("${keycloak.client-id:auth}") String defaultClientId,
            @Value("${keycloak.admin.client-id}") String defaultAdminClientId,
            @Value("${keycloak.admin.client-secret}") String defaultAdminClientSecret,
            @Value("${keycloak.issuer-uri:}") String defaultIssuerUri,
            GatewayProperties properties
    ) {
        String base = trimTrailingSlash(baseUrl);
        Map<String, RealmConfig> configured = new LinkedHashMap<>();
        configured.put(defaultRealm, new RealmConfig(
                defaultRealm,
                defaultClientId,
                defaultAdminClientId,
                defaultAdminClientSecret,
                StringUtils.hasText(defaultIssuerUri) ? defaultIssuerUri : issuer(base, defaultRealm)
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
                    StringUtils.hasText(realm.getIssuerUri()) ? realm.getIssuerUri() : issuer(base, realmName)
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
