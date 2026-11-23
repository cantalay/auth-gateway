package com.cantalay.authgateway.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/** k5: the authorization code of {@code /social} (body or query) never reaches the request log; error codes still do. */
@ExtendWith(OutputCaptureExtension.class)
class RequestLoggingCodeMaskingTest {

    @Test
    void authorizationCodeIsMaskedInRequestsOnly(CapturedOutput output) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/todogi/social");
        request.setContentType("application/json");
        request.setCharacterEncoding("UTF-8");
        request.setQueryString("code=query-code-123&state=s&id_token=eyJquery");
        request.setContent("{\"code\":\"body-code-456.abc\",\"redirectUri\":\"todogi://auth\",\"provider\":\"google\"}"
                .getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain(new jakarta.servlet.http.HttpServlet() {
            @Override
            protected void service(jakarta.servlet.http.HttpServletRequest req, jakarta.servlet.http.HttpServletResponse res)
                    throws java.io.IOException {
                req.getInputStream().readAllBytes();
                res.setStatus(409);
                res.setContentType("application/json");
                res.getWriter().write("{\"success\":false,\"error\":{\"code\":\"account_exists_unverified\"}}");
            }
        });

        new RequestLoggingFilter().doFilter(request, response, chain);

        String logs = output.getAll();
        assertThat(logs).doesNotContain("body-code-456", "query-code-123", "eyJquery");
        assertThat(logs).contains("code=***MASKED***", "state=s");
        assertThat(logs).contains("\"code\":\"account_exists_unverified\""); // response error codes stay readable

        // the request body is logged when it is already cached; its code field is masked then
        java.util.regex.Pattern codeField = (java.util.regex.Pattern) org.springframework.test.util.ReflectionTestUtils
                .getField(RequestLoggingFilter.class, "CODE_JSON_FIELD");
        assertThat(codeField.matcher("{\"code\":\"body-code-456.abc\",\"redirectUri\":\"todogi://auth\"}")
                .replaceAll("\"$1\":\"***MASKED***\"")).isEqualTo("{\"code\":\"***MASKED***\",\"redirectUri\":\"todogi://auth\"}");
    }
}
