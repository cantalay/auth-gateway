package com.cantalay.authgateway.exception;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.common.ApiResponse;
import com.cantalay.authgateway.controller.AuthController;
import com.cantalay.authgateway.realm.GatewayProperties;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Unknown paths are 404 in the usual error body (they were 500); every other error keeps its status and body. */
class UnknownPathTest {

    private final KeycloakClient keycloak = mock(KeycloakClient.class);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        RealmRegistry realms = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                new GatewayProperties());
        AuthService auth = new AuthService(mock(AuthAdminService.class), keycloak, mock(KeycloakAdminClient.class));
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(auth, realms))
                .setControllerAdvice(new GlobalAuthExceptionHandler())
                .build();
    }

    @Test
    void unknownPathIs404() throws Exception {
        for (String path : java.util.List.of("/auth/todogi/nope", "/auth/todogi/identities", "/nope")) {
            mvc.perform(get(path))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error.status").value(404))
                    .andExpect(jsonPath("$.error.error").value("Not Found"))
                    .andExpect(jsonPath("$.error.code").value("not_found"))
                    .andExpect(jsonPath("$.error.path").value(path))
                    .andExpect(jsonPath("$.error.timestamp").exists());
        }
    }

    @Test
    void staticResourceMissIs404() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/todogi/nope");
        ResponseEntity<ApiResponse<Void>> response = new GlobalAuthExceptionHandler().handleUnknownPath(
                new NoResourceFoundException(HttpMethod.GET, "/auth/todogi/nope", "auth/todogi/nope"), request);

        assertThat(response.getStatusCode().value()).isEqualTo(404);
        assertThat(response.getBody().getSuccess()).isFalse();
        assertThat(response.getBody().getError().getCode()).isEqualTo("not_found");
        assertThat(response.getBody().getError().getPath()).isEqualTo("/auth/todogi/nope");
    }

    @Test
    void otherErrorsAreUnchanged() throws Exception {
        // unknown realm: 404 without a code, as before
        mvc.perform(post("/auth/hello/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.c\",\"password\":\"x\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.message").value("Unknown realm."))
                .andExpect(jsonPath("$.error.code").doesNotExist());
        // malformed body: 400
        mvc.perform(post("/auth/todogi/login").contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value("Malformed request body"));
        // validation: 400 with field errors
        mvc.perform(post("/auth/todogi/social").contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value("Validation failed"))
                .andExpect(jsonPath("$.error.validationErrors.redirectUri").exists());
        // unexpected failure: still 500
        when(keycloak.token(any(), any())).thenThrow(new IllegalStateException("boom"));
        mvc.perform(post("/auth/todogi/refresh").contentType(MediaType.APPLICATION_JSON).content("{\"refreshToken\":\"r\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error.message").value("Unexpected authentication error."))
                .andExpect(jsonPath("$.error.code").doesNotExist());
        // an identity method error carries no email unless it is about one
        mvc.perform(post("/auth/todogi/social").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"c\",\"redirectUri\":\"app://cb\",\"mode\":\"link\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"))
                .andExpect(jsonPath("$.error.email").doesNotExist());
    }
}
