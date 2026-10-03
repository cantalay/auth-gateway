package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.domain.UserMeResponse;
import com.cantalay.authgateway.exception.BaseAuthException;
import com.cantalay.authgateway.realm.GatewayProperties;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerTest {

    private final AuthService authService = mock(AuthService.class);
    private final RealmRegistry realms = registry();
    private final AuthController controller = new AuthController(authService, realms);

    private static RealmRegistry registry() {
        GatewayProperties properties = new GatewayProperties();
        GatewayProperties.Realm hello = new GatewayProperties.Realm();
        hello.setAdminClientSecret("hello-secret");
        properties.getRealms().put("hello", hello);
        return new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "", properties);
    }

    private static Jwt jwt(String issuer) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject("user-1")
                .claim("iss", issuer).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }

    @Test
    void servesTokenFromMatchingRealm() {
        RealmConfig hello = realms.resolve("hello");
        UserMeResponse me = new UserMeResponse("user-1", "a@b.c", "A", "B");
        when(authService.getMe(eq(hello), any())).thenReturn(me);

        assertThat(controller.me("hello", jwt("https://auth.cantalay.com/realms/hello"))).isEqualTo(me);
    }

    @Test
    void legacyPathUsesDefaultRealm() {
        RealmConfig todogi = realms.resolve(null);
        UserMeResponse me = new UserMeResponse("user-1", "a@b.c", "A", "B");
        when(authService.getMe(eq(todogi), any())).thenReturn(me);

        assertThat(controller.me(null, jwt("https://auth.cantalay.com/realms/todogi"))).isEqualTo(me);
    }

    @Test
    void rejectsTokenFromAnotherRealm() {
        assertThatThrownBy(() -> controller.me("hello", jwt("https://auth.cantalay.com/realms/todogi")))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(e -> assertThat(((BaseAuthException) e).getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
        assertThatThrownBy(() -> controller.me(null, jwt("https://auth.cantalay.com/realms/hello")))
                .isInstanceOf(BaseAuthException.class);
    }
}
