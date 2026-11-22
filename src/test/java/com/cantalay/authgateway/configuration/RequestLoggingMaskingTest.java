package com.cantalay.authgateway.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class RequestLoggingMaskingTest {

    private final RequestLoggingFilter filter = new RequestLoggingFilter();

    private String mask(String body) {
        return ReflectionTestUtils.invokeMethod(filter, "maskSensitiveData", body);
    }

    @Test
    void escapedQuotesDoNotEndTheMaskedValue() {
        String masked = mask("{\"newPassword\":\"ab\\\"cd-Gizli-2026!\",\"token\":\"x\\\\\\\"y-tail\",\"email\":\"a@b.co\"}");

        assertThat(masked).doesNotContain("cd-Gizli-2026!").doesNotContain("y-tail");
        assertThat(masked).contains("\"newPassword\":\"***MASKED***\"").contains("\"token\":\"***MASKED***\"");
        assertThat(masked).contains("\"email\":\"a***@b.co\"");
    }

    @Test
    void escapedQuoteInATruncatedValue() {
        assertThat(mask("{\"token\":\"abc\\\"def-secret-rest... (truncated)")).doesNotContain("def-secret-rest");
    }
}
