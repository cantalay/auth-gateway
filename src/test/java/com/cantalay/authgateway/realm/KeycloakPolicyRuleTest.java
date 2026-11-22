package com.cantalay.authgateway.realm;

import feign.FeignException;
import feign.Request;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakPolicyRuleTest {

    private static FeignException badRequest(String body) {
        Request request = Request.create(Request.HttpMethod.PUT, "https://auth/x", Map.of(), null, StandardCharsets.UTF_8, null);
        return FeignException.errorStatus("x", feign.Response.builder().status(400).request(request)
                .body(body, StandardCharsets.UTF_8).headers(Map.of()).build());
    }

    @Test
    void namesTheRejectedRule() {
        assertThat(KeycloakErrors.passwordPolicyRule(badRequest(
                "{\"error\":\"invalidPasswordMinLengthMessage\",\"error_description\":\"Invalid password: minimum length 12.\"}")))
                .isEqualTo("length");
        assertThat(KeycloakErrors.passwordPolicyRule(badRequest("{\"error\":\"invalidPasswordHistoryMessage\"}"))).isEqualTo("passwordHistory");
        assertThat(KeycloakErrors.passwordPolicyRule(badRequest("{\"error\":\"invalidPasswordMinSpecialCharsMessage\"}"))).isEqualTo("specialChars");
        assertThat(KeycloakErrors.passwordPolicyRule(badRequest("{\"error\":\"invalidPasswordFancyMessage\"}"))).isEqualTo("policy");
        assertThat(KeycloakErrors.passwordPolicyRule(badRequest("{\"error\":\"something\"}"))).isNull();
    }
}
