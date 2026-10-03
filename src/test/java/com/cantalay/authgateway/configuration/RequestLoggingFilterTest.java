package com.cantalay.authgateway.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class RequestLoggingFilterTest {

    private final RequestLoggingFilter filter = new RequestLoggingFilter();

    private String mask(String body) {
        return ReflectionTestUtils.invokeMethod(filter, "maskSensitiveData", body);
    }

    @Test
    void masksTokensAndPasswordsWhateverTheFieldName() {
        String masked = mask("{\"access_token\":\"eyJabc\",\"refresh_token\":\"eyJdef\",\"refreshToken\":\"r\","
                + "\"currentPassword\":\"old\",\"newPassword\":\"new\",\"password\":\"p\",\"email\":\"a@b.c\"}");

        assertThat(masked).doesNotContain("eyJabc", "eyJdef", "\"r\"", "old", "\"new\"", "\"p\"");
        assertThat(masked).contains("\"email\":\"a***@b.c\"");
    }

    @Test
    void masksEmailAddresses() {
        assertThat(mask("{\"sub\":\"1\",\"email\":\"ayse.yilmaz@example.com\"}"))
                .contains("a***@example.com")
                .doesNotContain("ayse.yilmaz");
    }

    @Test
    void masksTruncatedValues() {
        assertThat(mask("{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI... (truncated)")).doesNotContain("eyJhbGci");
    }
}
