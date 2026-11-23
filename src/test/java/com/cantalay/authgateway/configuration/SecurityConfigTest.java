package com.cantalay.authgateway.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigTest {

    @Test
    void usesConfiguredCorsOrigins() {
        SecurityConfig securityConfig = new SecurityConfig(List.of("https://todogi.singlestranger.com"));
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/auth/login");

        CorsConfiguration cors = securityConfig.corsConfigurationSource().getCorsConfiguration(request);

        assertThat(cors).isNotNull();
        assertThat(cors.getAllowedOrigins()).containsExactly("https://todogi.singlestranger.com");
        assertThat(cors.getAllowCredentials()).isTrue();
    }

    /** O3 (review): only access tokens are Bearer tokens; an ID token of the same realm and key is refused. */
    @Test
    void onlyAccessTokensAreAccepted() {
        java.util.Map<String, String> types = java.util.Map.of("access", "Bearer", "id", "ID", "none", "");
        org.springframework.security.oauth2.jwt.JwtDecoder decoder = SecurityConfig.accessTokensOnly(token -> {
            org.springframework.security.oauth2.jwt.Jwt.Builder jwt = org.springframework.security.oauth2.jwt.Jwt
                    .withTokenValue(token).header("alg", "RS256").subject("u");
            if (!types.get(token).isEmpty()) {
                jwt.claim("typ", types.get(token));
            }
            return jwt.build();
        });

        assertThat(decoder.decode("access").getSubject()).isEqualTo("u");
        for (String token : List.of("id", "none")) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> decoder.decode(token))
                    .isInstanceOf(org.springframework.security.oauth2.jwt.JwtValidationException.class);
        }
    }
}
