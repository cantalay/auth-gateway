package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.realm.RealmConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service-account token of a realm's admin client. Cached per realm until 30 seconds before it expires, so bursts of
 * account emails do not mint a token per request.
 */
@Service
public class AuthAdminService {

    static final long EXPIRY_MARGIN_SECONDS = 30;

    private final KeycloakClient keycloakClient;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(String token, long expiresAtMillis) {
    }

    public AuthAdminService(KeycloakClient keycloakClient) {
        this(keycloakClient, Clock.systemUTC());
    }

    @Autowired
    public AuthAdminService(KeycloakClient keycloakClient, Clock clock) {
        this.keycloakClient = keycloakClient;
        this.clock = clock;
    }

    public String getAdminAccessToken(RealmConfig realm) {
        String key = realm.name() + "|" + realm.adminClientId();
        long now = clock.millis();
        Cached cached = cache.get(key);
        if (cached != null && now < cached.expiresAtMillis()) {
            return cached.token();
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", realm.adminClientId());
        form.add("client_secret", realm.adminClientSecret());

        TokenResponseDto resp = keycloakClient.token(realm.name(), form);
        long lifetime = resp.expiresIn() - EXPIRY_MARGIN_SECONDS;
        if (lifetime > 0) {
            cache.put(key, new Cached(resp.accessToken(), now + lifetime * 1000));
        } else {
            cache.remove(key);
        }
        return resp.accessToken();
    }
}
