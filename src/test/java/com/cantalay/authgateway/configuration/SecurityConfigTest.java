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
}
