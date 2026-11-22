package com.cantalay.authgateway.service;

import com.cantalay.authgateway.account.RateLimiterTest;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.realm.RealmConfig;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthAdminServiceTest {

    @Test
    void cachesTheTokenPerRealmUntil30SecondsBeforeExpiry() {
        KeycloakClient keycloak = mock(KeycloakClient.class);
        when(keycloak.token(eq("todogi"), any())).thenReturn(
                new TokenResponseDto("t1", null, 300, 0, "Bearer", null),
                new TokenResponseDto("t2", null, 300, 0, "Bearer", null));
        when(keycloak.token(eq("tela"), any())).thenReturn(new TokenResponseDto("x", null, 300, 0, "Bearer", null));
        RateLimiterTest.MutableClock clock = new RateLimiterTest.MutableClock();
        AuthAdminService service = new AuthAdminService(keycloak, clock);
        RealmConfig todogi = new RealmConfig("todogi", "auth", "auth-gateway-admin", "s", "iss");
        RealmConfig tela = new RealmConfig("tela", "tela-gateway", "tela-gateway-admin", "s", "iss");

        assertThat(service.getAdminAccessToken(todogi)).isEqualTo("t1");
        clock.now = clock.now.plus(Duration.ofSeconds(269));
        assertThat(service.getAdminAccessToken(todogi)).isEqualTo("t1");
        assertThat(service.getAdminAccessToken(tela)).isEqualTo("x");
        clock.now = clock.now.plus(Duration.ofSeconds(1)); // 270 s = 300 - 30
        assertThat(service.getAdminAccessToken(todogi)).isEqualTo("t2");
        verify(keycloak, times(2)).token(eq("todogi"), any());
    }

    @Test
    void shortLivedTokensAreNotCached() {
        KeycloakClient keycloak = mock(KeycloakClient.class);
        when(keycloak.token(eq("todogi"), any())).thenReturn(new TokenResponseDto("t", null, 20, 0, "Bearer", null));
        AuthAdminService service = new AuthAdminService(keycloak, new RateLimiterTest.MutableClock());
        RealmConfig todogi = new RealmConfig("todogi", "auth", "auth-gateway-admin", "s", "iss");

        service.getAdminAccessToken(todogi);
        service.getAdminAccessToken(todogi);
        verify(keycloak, times(2)).token(eq("todogi"), any());
    }
}
