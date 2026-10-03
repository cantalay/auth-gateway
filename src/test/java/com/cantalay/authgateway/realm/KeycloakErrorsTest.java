package com.cantalay.authgateway.realm;

import feign.FeignException;
import feign.Request;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakErrorsTest {

    private static FeignException error(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST, "https://kc/token", Map.of(), null, StandardCharsets.UTF_8, null);
        return FeignException.errorStatus("token", feign.Response.builder()
                .status(status).reason("x").request(request).headers(Map.of())
                .body(body, StandardCharsets.UTF_8).build());
    }

    @Test
    void classifiesPasswordGrantErrors() {
        assertThat(KeycloakErrors.isAccountNotUsable(error(400,
                "{\"error\":\"invalid_grant\",\"error_description\":\"Account is not fully set up\"}"))).isTrue();
        assertThat(KeycloakErrors.isAccountNotUsable(error(401,
                "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}"))).isFalse();
        assertThat(KeycloakErrors.isClientMisconfigured(error(400,
                "{\"error\":\"unauthorized_client\",\"error_description\":\"Client not allowed for direct access grants\"}"))).isTrue();
        assertThat(KeycloakErrors.isPasswordPolicyViolation(error(400,
                "{\"errorMessage\":\"invalidPasswordMinLengthMessage\"}"))).isTrue();
    }

    @Test
    void masksEmails() {
        assertThat(KeycloakErrors.maskEmail("ayse@example.com")).isEqualTo("a***@example.com");
        assertThat(KeycloakErrors.maskEmail("broken")).isEqualTo("***");
    }
}
