package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.realm.RealmConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Service
@RequiredArgsConstructor
public class AuthAdminService {

    private final KeycloakClient keycloakClient;

    public String getAdminAccessToken(RealmConfig realm) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", realm.adminClientId());
        form.add("client_secret", realm.adminClientSecret());

        TokenResponseDto resp = keycloakClient.token(realm.name(), form);
        return resp.accessToken();
    }
}
