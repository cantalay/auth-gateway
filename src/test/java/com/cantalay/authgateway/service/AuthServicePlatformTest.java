package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.PlatformLoginRequest;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.realm.RealmConfig;
import feign.FeignException;
import feign.Request;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServicePlatformTest {
    private final KeycloakClient keycloak = mock(KeycloakClient.class);
    private final AuthService service = new AuthService(mock(AuthAdminService.class), keycloak, mock(KeycloakAdminClient.class));
    private final RealmConfig conquest = new RealmConfig("conquest", "conquest-gateway", "conquest-gateway-admin", "s",
            "https://auth.cantalay.com/realms/conquest", true, "conquest-platform");
    private final RealmConfig hello = new RealmConfig("hello", "hello-gateway", "hello-gateway-admin", "s", "iss");

    @SuppressWarnings("unchecked")
    @Test
    void platformSignInUsesThePlatformClientAndAsksForAnOfflineToken() {
        TokenResponseDto tokens = mock(TokenResponseDto.class);
        when(keycloak.token(eq("conquest"), any())).thenReturn(tokens);

        assertThat(service.platformLogin(conquest, new PlatformLoginRequest("gamecenter", "eyJ..."))).isSameAs(tokens);

        ArgumentCaptor<MultiValueMap<String, String>> form = ArgumentCaptor.forClass(MultiValueMap.class);
        verify(keycloak).token(eq("conquest"), form.capture());
        assertThat(form.getValue().getFirst("grant_type")).isEqualTo("password");
        assertThat(form.getValue().getFirst("client_id")).isEqualTo("conquest-platform");
        assertThat(form.getValue().getFirst("platform")).isEqualTo("gamecenter");
        assertThat(form.getValue().getFirst("platform_token")).isEqualTo("eyJ...");
        assertThat(form.getValue().getFirst("scope")).contains("offline_access");
        assertThat(form.getValue().containsKey("username")).isFalse();
    }

    @Test
    void realmsWithoutPlatformSignInAndRejectedTokens() {
        assertThatThrownBy(() -> service.platformLogin(hello, new PlatformLoginRequest("gamecenter", "x")))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(e -> assertThat(((BaseAuthException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND));

        when(keycloak.token(eq("conquest"), any())).thenThrow(feign(401, "{\"error\":\"invalid_grant\"}"));
        assertThatThrownBy(() -> service.platformLogin(conquest, new PlatformLoginRequest("playgames", "bad")))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(e -> assertThat(((BaseAuthException) e).getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void linkingAnIdentityOfAnotherAccountIsAConflict() {
        when(keycloak.platformLink(eq("conquest"), eq("Bearer at"), anyMap())).thenThrow(feign(409, "{\"error\":\"already_linked\"}"));
        assertThatThrownBy(() -> service.platformLink(conquest, "at", new PlatformLoginRequest("gamecenter", "x")))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(e -> assertThat(((BaseAuthException) e).getStatus()).isEqualTo(HttpStatus.CONFLICT));
    }

    @Test
    void linkForwardsTheUsersToken() {
        when(keycloak.platformLink(eq("conquest"), eq("Bearer at"), anyMap())).thenReturn(Map.of("platform", "gamecenter", "linked", true));
        assertThat(service.platformLink(conquest, "at", new PlatformLoginRequest("gamecenter", "x"))).containsEntry("linked", true);
    }

    private static FeignException feign(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST, "https://auth/token", Map.of(), null, StandardCharsets.UTF_8, null);
        return FeignException.errorStatus("token", feign.Response.builder().status(status).request(request)
                .body(body, StandardCharsets.UTF_8).headers(Map.of()).build());
    }
}
