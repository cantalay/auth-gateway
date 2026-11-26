package com.cantalay.authgateway.identity;

import com.cantalay.authgateway.account.RateLimiterTest;
import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.controller.AuthController;
import com.cantalay.authgateway.controller.IdentityController;
import com.cantalay.authgateway.domain.KeycloakCredentialDto;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.KeycloakUserSessionDto;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.GlobalAuthExceptionHandler;
import com.cantalay.authgateway.realm.GatewayProperties;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import feign.FeignException;
import feign.Request;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Component tests: real controllers and services, Keycloak (token endpoint and admin API) mocked. */
class IdentityMethodsControllerTest {

    private static final String BASE = "https://auth.cantalay.com";
    private static final String CAN = "4c1f0d6e-0000-4000-8000-00000000000c";
    private static final String AYSE = "4c1f0d6e-0000-4000-8000-00000000000a";
    private static final String NEW = "4c1f0d6e-0000-4000-8000-00000000000e";
    private static final String ADMIN = "Bearer adm";

    private final RateLimiterTest.MutableClock clock = new RateLimiterTest.MutableClock();
    private final KeycloakClient keycloak = mock(KeycloakClient.class);
    private final KeycloakAdminClient admin = mock(KeycloakAdminClient.class);
    private final AuthAdminService adminService = mock(AuthAdminService.class);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private MockMvc mvc;
    private IdentityMethodsService identity;

    @BeforeEach
    void setUp() {
        GatewayProperties properties = new GatewayProperties();
        GatewayProperties.Realm vitafinder = new GatewayProperties.Realm();
        vitafinder.setAdminClientSecret("vf");
        properties.getRealms().put("vitafinder", vitafinder);
        GatewayProperties.Realm hello = new GatewayProperties.Realm();
        hello.setAdminClientSecret("h");
        hello.setIdentityMethods(true);
        properties.getRealms().put("hello", hello);
        RealmRegistry realms = new RealmRegistry(BASE, "todogi", "auth", "auth-gateway-admin", "s", "", true, true,
                properties);

        AuthService auth = new AuthService(adminService, keycloak, admin);
        identity = new IdentityMethodsService(adminService, auth, admin, meters, clock);
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(auth, realms, identity), new IdentityController(identity, realms))
                .setControllerAdvice(new GlobalAuthExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
                .build();

        when(adminService.getAdminAccessToken(any())).thenReturn("adm");
        user(CAN, "can@ornek.com", true, Instant.parse("2026-01-01T00:00:00Z"));
        when(admin.getCredentials("todogi", CAN, ADMIN)).thenReturn(List.of(password()));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of());
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    /* ======================= identities ======================= */

    @Test
    void listsPasswordAndProviders() throws Exception {
        signedIn("todogi", CAN);
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(
                link("google", "can@gmail.com"), link("apple", "001234.abcdef")));

        mvc.perform(get("/auth/todogi/identities"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"password\":true,\"providers\":[{\"alias\":\"google\",\"email\":\"can@gmail.com\"},"
                        + "{\"alias\":\"apple\",\"email\":null}]}", true));
        assertThat(count("todogi", "list", "ok")).isEqualTo(1);
    }

    @Test
    void legacyPathListsTheDefaultRealm() throws Exception {
        signedIn("todogi", CAN);
        when(admin.getCredentials("todogi", CAN, ADMIN)).thenReturn(List.of(new KeycloakCredentialDto("otp", "otp", 1L)));

        mvc.perform(get("/auth/identities"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"password\":false,\"providers\":[]}", true));
    }

    @Test
    void unlinksAProviderWhenAnotherMethodRemains() throws Exception {
        signedIn("todogi", CAN);
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));

        mvc.perform(delete("/auth/todogi/identities/google")).andExpect(status().isNoContent());
        verify(admin).removeFederatedIdentity("todogi", CAN, "google", ADMIN);

        // passwordless with two providers: one of them may go
        when(admin.getCredentials("todogi", CAN, ADMIN)).thenReturn(List.of());
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(
                link("google", "can@ornek.com"), link("apple", "can@ornek.com")));
        mvc.perform(delete("/auth/identities/apple")).andExpect(status().isNoContent());
        verify(admin).removeFederatedIdentity("todogi", CAN, "apple", ADMIN);
        assertThat(count("todogi", "unlink", "ok")).isEqualTo(2);
    }

    @Test
    void refusesToRemoveTheLastMethod() throws Exception {
        signedIn("todogi", CAN);
        when(admin.getCredentials("todogi", CAN, ADMIN)).thenReturn(List.of());
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));

        mvc.perform(delete("/auth/todogi/identities/google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.status").value(409))
                .andExpect(jsonPath("$.error.code").value("last_method"));
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        assertThat(count("todogi", "unlink", "last_method")).isEqualTo(1);
    }

    @Test
    void removingAProviderThatIsNotLinkedIsANoOp() throws Exception {
        signedIn("todogi", CAN);

        mvc.perform(delete("/auth/todogi/identities/apple")).andExpect(status().isNoContent());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        assertThat(count("todogi", "unlink", "not_linked")).isEqualTo(1);

        // removed meanwhile (Keycloak 404): still 204
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));
        doThrow(feign(404, "{}")).when(admin).removeFederatedIdentity("todogi", CAN, "google", ADMIN);
        mvc.perform(delete("/auth/todogi/identities/google")).andExpect(status().isNoContent());
    }

    @Test
    void realmsWithoutTheFeatureAnswer404() throws Exception {
        signedIn("vitafinder", CAN);

        mvc.perform(get("/auth/vitafinder/identities"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"));
        mvc.perform(delete("/auth/vitafinder/identities/google"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"));
        social("/auth/vitafinder/social", Map.of("code", "c", "redirectUri", "app://cb", "mode", "link"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"));
        verifyNoInteractions(admin, keycloak);
        assertThat(count("vitafinder", "list", "disabled")).isEqualTo(1);
        assertThat(count("vitafinder", "link", "disabled")).isEqualTo(1);
    }

    @Test
    void additionalRealmTurnsTheFeatureOnWithItsOwnFlag() throws Exception {
        signedIn("hello", CAN);
        when(admin.getCredentials("hello", CAN, ADMIN)).thenReturn(List.of(password()));
        when(admin.getFederatedIdentities("hello", CAN, ADMIN)).thenReturn(List.of());

        mvc.perform(get("/auth/hello/identities")).andExpect(status().isOk());
    }

    @Test
    void tokenOfAnotherRealmIs403() throws Exception {
        signedIn("todogi", CAN);

        mvc.perform(get("/auth/hello/identities")).andExpect(status().isForbidden());
        mvc.perform(delete("/auth/hello/identities/google")).andExpect(status().isForbidden());
        social("/auth/hello/social", Map.of("code", "c", "redirectUri", "app://cb", "mode", "link"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(admin, keycloak);
    }

    /* ======================= /social without mode: unchanged ======================= */

    @Test
    void socialWithoutModeIsUnchangedWhereTheFeatureIsOff() throws Exception {
        when(keycloak.token(eq("vitafinder"), any())).thenReturn(tokens(AYSE));

        for (Map<String, String> body : List.of(
                Map.of("code", "c", "redirectUri", "app://cb"),
                Map.of("code", "c", "redirectUri", "app://cb", "mode", "login"),
                Map.of("code", "c", "redirectUri", "app://cb", "mode", "something-else"))) {
            social("/auth/vitafinder/social", body)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.access_token").value(tokens(AYSE).accessToken()))
                    .andExpect(jsonPath("$.refresh_token").value("refresh-" + AYSE));
        }
        verify(keycloak, org.mockito.Mockito.times(3)).token(eq("vitafinder"), argThat(form ->
                form.toSingleValueMap().equals(Map.of("grant_type", "authorization_code", "client_id", "vitafinder-gateway",
                        "code", "c", "redirect_uri", "app://cb"))));
        verifyNoInteractions(admin);
        verify(keycloak, never()).logout(any(), any());

        // a code Keycloak rejects: 401 as before
        when(keycloak.token(eq("vitafinder"), any())).thenThrow(feign(400, "{\"error\":\"invalid_grant\"}"));
        social("/auth/vitafinder/social", Map.of("code", "old", "redirectUri", "app://cb"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").doesNotExist());
    }

    @Test
    void socialSignInIntoAConfirmedAccount() throws Exception {
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));

        for (String path : List.of("/auth/todogi/social", "/auth/social")) {
            social(path, Map.of("code", "c", "redirectUri", "todogi://auth"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.access_token").value(tokens(CAN).accessToken()));
        }
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "login"))
                .andExpect(status().isOk());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        verify(keycloak, never()).logout(any(), any());
        assertThat(count("todogi", "login", "ok")).isEqualTo(3);
    }

    /** 2026-11-26: Google / Apple sign-up sent no welcome email; the sign-up hook runs once, only for a new account. */
    @Test
    void socialSignUpCallsTheSignupHookOnlyForAJustCreatedAccount() throws Exception {
        List<String> created = new java.util.ArrayList<>();
        identity.setSignupHook((realm, u) -> created.add(realm.name() + ":" + u.id()));
        user(NEW, "yeni@ornek.com", true, clock.now.minus(java.time.Duration.ofMinutes(1)));
        when(admin.getCredentials("todogi", NEW, ADMIN)).thenReturn(List.of());
        when(admin.getFederatedIdentities("todogi", NEW, ADMIN)).thenReturn(List.of(link("apple", "yeni@ornek.com")));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(NEW));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "provider", "apple"))
                .andExpect(status().isOk());
        assertThat(created).containsExactly("todogi:" + NEW);

        // an account from before (CAN, created in January) signing in again: no hook
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isOk());
        assertThat(created).containsExactly("todogi:" + NEW);

        // the new account signing in again after the window: no hook either
        clock.now = clock.now.plus(IdentityMethodsService.NEW_ACCOUNT_WINDOW);
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(NEW));
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isOk());
        assertThat(created).containsExactly("todogi:" + NEW);
    }

    /**
     * Criterion 17 (component), second line: Keycloak (an older flow, or a link from before) signed Google in to a
     * password account nobody has confirmed. The session is ended through the admin API (online and offline), links
     * stay, no tokens.
     */
    @Test
    void socialSignInIntoAnUnconfirmedPasswordAccountIsRefused() throws Exception {
        user(CAN, "can@ornek.com", false, Instant.parse("2026-01-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN, "google", clock.instant(), "sid-can"));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "provider", "google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("account_exists_unverified"))
                .andExpect(jsonPath("$.error.email").value("can@ornek.com"))
                .andExpect(jsonPath("$.error.path").value("/auth/todogi/social"))
                .andExpect(jsonPath("$.error.message").exists())
                .andExpect(jsonPath("$.error.timestamp").exists())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.data").doesNotExist());
        verify(admin).deleteSession("todogi", "sid-can", false, ADMIN);
        verify(admin).deleteSession("todogi", "sid-can", true, ADMIN);
        verify(keycloak, never()).logout(any(), any());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any()); // Ö3: links are not touched
        verify(admin, never()).logoutUser(any(), any(), any()); // the account's other sessions are not ours to end
        verify(admin, never()).updateUser(any(), any(), any(), any());
        assertThat(count("todogi", "login", "unverified")).isEqualTo(1);
    }

    /** Ö1: an SSO session left from before (no links any more) still cannot sign in to such an account. */
    @Test
    void unconfirmedPasswordAccountIsRefusedWhateverItsLinks() throws Exception {
        user(CAN, "can@ornek.com", false, Instant.parse("2026-01-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN, "google", clock.instant().minusSeconds(3600), "sid-old"));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of());

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("account_exists_unverified"));
        verify(admin).deleteSession("todogi", "sid-old", false, ADMIN);
    }

    /** Admin API down: the refresh token is logged out instead; when that fails too the open session is counted. */
    @Test
    void sessionEndFallsBackToTheRefreshToken() throws Exception {
        user(CAN, "can@ornek.com", false, Instant.parse("2026-01-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN, "google", clock.instant(), "sid-can"));
        doThrow(feign(503, "{}")).when(admin).deleteSession(eq("todogi"), eq("sid-can"), org.mockito.ArgumentMatchers.anyBoolean(), eq(ADMIN));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isConflict());
        verify(admin, org.mockito.Mockito.times(2)).deleteSession("todogi", "sid-can", false, ADMIN); // retried once
        verify(keycloak).logout(eq("todogi"), argThat(form -> ("refresh-" + CAN).equals(form.getFirst("refresh_token"))));
        assertThat(count("todogi", "login", "session_left")).isZero();

        doThrow(feign(503, "{}")).when(keycloak).logout(eq("todogi"), any());
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.access_token").doesNotExist());
        assertThat(count("todogi", "login", "session_left")).isEqualTo(1);
    }

    @Test
    void unconfirmedAccountsWithoutPasswordOrEmailSignIn() throws Exception {
        // Apple without an address: no email, nothing to confirm
        user(NEW, null, false, clock.instant());
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(NEW));
        when(admin.getCredentials("todogi", NEW, ADMIN)).thenReturn(List.of());
        when(admin.getFederatedIdentities("todogi", NEW, ADMIN)).thenReturn(List.of(link("apple", "001234.abcdef")));
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth")).andExpect(status().isOk());

        // unconfirmed but passwordless
        user(NEW, "x@privaterelay.appleid.com", false, clock.instant());
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth")).andExpect(status().isOk());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        verify(admin, never()).deleteSession(any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any());
    }

    @Test
    void accountThatCannotBeCheckedGetsNoTokens() throws Exception {
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN));
        when(admin.getUser("todogi", CAN, ADMIN)).thenThrow(feign(503, "{}"));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth"))
                .andExpect(status().isServiceUnavailable());
        verify(keycloak).logout(eq("todogi"), any());
        assertThat(count("todogi", "login", "error")).isEqualTo(1);
    }

    @Test
    void unknownModeIs400WhereTheFeatureIsOn() throws Exception {
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "merge"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("invalid_mode"));
        verifyNoInteractions(keycloak);
    }

    /* ======================= /social with Keycloak's refusal ======================= */

    /**
     * talay-keycloak-providers refuses the link in Keycloak and the app's redirect gets {@code error} instead of a
     * code: the gateway translates it, in every realm (vitafinder has no identity methods), without calling Keycloak.
     */
    @Test
    void keycloaksRefusalIsTranslatedInEveryRealm() throws Exception {
        signedIn("todogi", CAN);
        for (String path : List.of("/auth/vitafinder/social", "/auth/todogi/social", "/auth/social")) {
            social(path, Map.of("error", "access_denied", "errorDescription", "account_exists_unverified",
                    "redirectUri", "app://cb"))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.error.code").value("account_exists_unverified"))
                    .andExpect(jsonPath("$.error.email").doesNotExist());
            social(path, Map.of("error", "access_denied", "error_description", "account_exists", "redirectUri", "app://cb",
                    "mode", "link"))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.error.code").value("account_exists"));
            social(path, Map.of("error", "access_denied", "redirectUri", "app://cb"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error.code").value("social_cancelled"));
            social(path, Map.of("error", "server_error", "errorDescription", "x", "redirectUri", "app://cb"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error.code").value("social_failed"));
        }
        verifyNoInteractions(keycloak, admin);
        assertThat(count("vitafinder", "login", "refused_account_exists_unverified")).isEqualTo(1);
        assertThat(count("todogi", "link", "refused_account_exists")).isEqualTo(2);
    }

    @Test
    void codeIsRequiredWithoutAnError() throws Exception {
        social("/auth/vitafinder/social", Map.of("redirectUri", "app://cb", "errorDescription", "account_exists_unverified"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value("Validation failed"))
                .andExpect(jsonPath("$.error.validationErrors.code").exists());
        social("/auth/vitafinder/social", Map.of("code", " ", "redirectUri", "app://cb"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.validationErrors.code").exists());
        verifyNoInteractions(keycloak, admin);
    }

    /* ======================= /social mode=link ======================= */

    /** The code proves a Google sign-in of the signed-in user made just now: linked; no admin call after it (k3). */
    @Test
    void linkProvenBySignInReturnsTheNewSession() throws Exception {
        signedIn("todogi", CAN);
        user(CAN, "can@ornek.com", false, Instant.parse("2026-01-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(CAN, "google", clock.instant().minusSeconds(20), "sid-can"));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value(tokens(CAN, "google", clock.instant().minusSeconds(20), "sid-can").accessToken()))
                .andExpect(jsonPath("$.refresh_token").value("refresh-" + CAN));
        // K1: linking never marks the email confirmed
        verifyNoInteractions(admin);
        verify(adminService, never()).getAdminAccessToken(any());
        verify(keycloak, never()).logout(any(), any());
        assertThat(count("todogi", "link", "ok")).isEqualTo(1);
    }

    @Test
    void linkNeedsTheProvider() throws Exception {
        signedIn("todogi", CAN);

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("invalid_provider"));
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "Google!"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(keycloak, admin);
    }

    /**
     * Ö2 / K1: a code that does not prove a fresh sign-in with the provider (a password session, a session of another
     * provider, an old SSO session) links nothing: 409 identity_unproven, its session ended, the email untouched.
     */
    @Test
    void linkWithoutProofIsRefused() throws Exception {
        signedIn("todogi", CAN);
        user(CAN, "can@ornek.com", false, Instant.parse("2026-01-01T00:00:00Z"));
        when(admin.getFederatedIdentities("todogi", CAN, ADMIN)).thenReturn(List.of(link("google", "can@ornek.com")));
        List<TokenResponseDto> unproven = List.of(
                tokens(CAN, null, clock.instant(), "sid-1"),                              // password sign-in
                tokens(CAN, "apple", clock.instant(), "sid-2"),                           // another provider
                tokens(CAN, "google", clock.instant().minus(Duration.ofMinutes(3)), "sid-3"), // old SSO session
                tokens(CAN, "google", null, "sid-4"));                                    // no auth_time
        for (TokenResponseDto t : unproven) {
            when(keycloak.token(eq("todogi"), any())).thenReturn(t);
            social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.error.code").value("identity_unproven"))
                    .andExpect(jsonPath("$.access_token").doesNotExist());
        }
        for (int i = 1; i <= 4; i++) {
            verify(admin).deleteSession("todogi", "sid-" + i, false, ADMIN);
        }
        verify(admin, never()).updateUser(any(), any(), any(), any());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        assertThat(count("todogi", "link", "unproven")).isEqualTo(4);
    }

    /** Criterion 16 (component): a different address made Keycloak create a user for exactly this sign-in; it is deleted. */
    @Test
    void linkResolvingToAUserCreatedForItDeletesThatUser() throws Exception {
        signedIn("todogi", CAN);
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new"), 2);

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("identity_mismatch"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
        verify(admin).deleteUser("todogi", NEW, ADMIN);
        verify(admin).deleteSession("todogi", "sid-new", false, ADMIN);
        verifySignedInUserUntouched();
        assertThat(count("todogi", "link", "mismatch")).isEqualTo(1);
    }

    /** k2: the user Keycloak created could not be deleted: the client is told (503), not a silent 409. */
    @Test
    void failedDeletionIsReported() throws Exception {
        signedIn("todogi", CAN);
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new"), 2);
        doThrow(feign(503, "{}")).when(admin).deleteUser("todogi", NEW, ADMIN);

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.access_token").doesNotExist());
        verify(admin, org.mockito.Mockito.times(2)).deleteUser("todogi", NEW, ADMIN);
        assertThat(count("todogi", "link", "delete_failed")).isEqualTo(1);
    }

    /** k1: deletion needs every sign of "created for this sign-in"; any other user is only refused. */
    @Test
    void usersNotCreatedForThisSignInAreNotDeleted() throws Exception {
        signedIn("todogi", CAN);
        // signed up 30 s before this sign-in (another device)
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new"), 30);
        assertInUse();
        // the code's session is not its only one
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new", "sid-phone"), 2);
        assertInUse();
        // its only session is another one
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-phone"), 2);
        assertInUse();
        // a password, or a second provider
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new"), 2);
        when(admin.getCredentials("todogi", NEW, ADMIN)).thenReturn(List.of(password()));
        assertInUse();
        newBrokerUser(NEW, "baska@gmail.com", List.of("sid-new"), 2);
        when(admin.getFederatedIdentities("todogi", NEW, ADMIN)).thenReturn(List.of(link("google", "baska@gmail.com"),
                link("apple", "x")));
        assertInUse();
        verify(admin, never()).deleteUser(any(), any(), any());
        assertThat(count("todogi", "link", "in_use")).isEqualTo(5);
    }

    /** Criterion 16 (component): the provider account belongs to another existing user. */
    @Test
    void linkResolvingToAnotherExistingUserIsInUse() throws Exception {
        signedIn("todogi", CAN);
        user(AYSE, "ayse@gmail.com", true, Instant.parse("2026-03-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(AYSE, "google", clock.instant(), "sid-ayse"));
        when(admin.getFederatedIdentities("todogi", AYSE, ADMIN)).thenReturn(List.of(link("google", "ayse@gmail.com")));
        when(admin.getCredentials("todogi", AYSE, ADMIN)).thenReturn(List.of());

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("identity_in_use"));
        verify(admin, never()).deleteUser(any(), any(), any());
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        verify(admin).deleteSession("todogi", "sid-ayse", false, ADMIN);
        verify(admin).deleteSession("todogi", "sid-ayse", true, ADMIN);
        verifySignedInUserUntouched();
        assertThat(count("todogi", "link", "in_use")).isEqualTo(1);
    }

    /** Ö3: refusing never removes another account's links (an old realm's links stay). */
    @Test
    void linkIntoAnUnconfirmedPasswordAccountLeavesItsLinks() throws Exception {
        signedIn("todogi", CAN);
        user(AYSE, "ayse@gmail.com", false, Instant.parse("2026-03-01T00:00:00Z"));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(AYSE, "google", clock.instant(), "sid-ayse"));
        when(admin.getFederatedIdentities("todogi", AYSE, ADMIN)).thenReturn(List.of(link("google", "ayse@gmail.com"),
                link("apple", "x")));
        when(admin.getCredentials("todogi", AYSE, ADMIN)).thenReturn(List.of(password()));

        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("identity_in_use"));
        verify(admin, never()).removeFederatedIdentity(any(), any(), any(), any());
        verify(admin, never()).deleteUser(any(), any(), any());
    }

    @Test
    void linkNeedsTheAccountsToken() throws Exception {
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(keycloak, admin);
    }

    @Test
    void rejectedCodeIs401AsForSignIn() throws Exception {
        signedIn("todogi", CAN);
        when(keycloak.token(eq("todogi"), any())).thenThrow(feign(400, "{\"error\":\"invalid_grant\"}"));

        social("/auth/todogi/social", Map.of("code", "old", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isUnauthorized());
        assertThat(count("todogi", "link", "invalid")).isEqualTo(1);
    }

    /* ======================= rate limits (k4) ======================= */

    @Test
    void identitiesAreRateLimitedPerUser() throws Exception {
        signedIn("todogi", CAN);
        for (int i = 0; i < IdentityMethodsService.LIST_PER_USER.max(); i++) {
            mvc.perform(get("/auth/todogi/identities")).andExpect(status().isOk());
        }
        mvc.perform(get("/auth/todogi/identities"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("rate_limited"));
        for (int i = 0; i < IdentityMethodsService.UNLINK_PER_USER.max(); i++) {
            mvc.perform(delete("/auth/todogi/identities/apple")).andExpect(status().isNoContent());
        }
        mvc.perform(delete("/auth/todogi/identities/apple")).andExpect(status().isTooManyRequests());
        assertThat(count("todogi", "list", "rate_limited")).isEqualTo(1);
        assertThat(count("todogi", "unlink", "rate_limited")).isEqualTo(1);

        // per user: another account is not affected; the window passes
        signedIn("todogi", AYSE);
        when(admin.getCredentials("todogi", AYSE, ADMIN)).thenReturn(List.of(password()));
        when(admin.getFederatedIdentities("todogi", AYSE, ADMIN)).thenReturn(List.of());
        mvc.perform(get("/auth/todogi/identities")).andExpect(status().isOk());
        signedIn("todogi", CAN);
        clock.now = clock.now.plus(Duration.ofMinutes(11));
        mvc.perform(get("/auth/todogi/identities")).andExpect(status().isOk());
    }

    /** k6: a known path with the wrong method is 405 with Allow (was 500). */
    @Test
    void wrongMethodIs405() throws Exception {
        signedIn("todogi", CAN);
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/auth/todogi/identities"))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Allow", org.hamcrest.Matchers.containsString("GET")))
                .andExpect(jsonPath("$.error.code").value("method_not_allowed"));
        mvc.perform(get("/auth/todogi/social"))
                .andExpect(status().isMethodNotAllowed());
    }

    /* ======================= helpers ======================= */

    private void verifySignedInUserUntouched() {
        verify(admin, never()).deleteUser(eq("todogi"), eq(CAN), anyString());
        verify(admin, never()).logoutUser(any(), any(), any());
        verify(admin, never()).updateUser(any(), any(), any(), any());
        verify(admin, never()).removeFederatedIdentity(eq("todogi"), eq(CAN), any(), any());
        verify(admin, never()).deleteSession(any(), eq("sid-can"), org.mockito.ArgumentMatchers.anyBoolean(), any());
    }

    /** A Google-only user created {@code secondsBefore} the sign-in whose code the link presents. */
    private void newBrokerUser(String id, String email, List<String> sessions, int secondsBefore) {
        Instant signIn = clock.instant().minusSeconds(1);
        user(id, email, true, signIn.minusSeconds(secondsBefore));
        when(keycloak.token(eq("todogi"), any())).thenReturn(tokens(id, "google", signIn, "sid-new"));
        when(admin.getFederatedIdentities("todogi", id, ADMIN)).thenReturn(List.of(link("google", email)));
        when(admin.getCredentials("todogi", id, ADMIN)).thenReturn(List.of());
        when(admin.getUserSessions("todogi", id, ADMIN)).thenReturn(sessions.stream()
                .map(sid -> new KeycloakUserSessionDto(sid, clock.millis(), clock.millis())).toList());
    }

    private void assertInUse() throws Exception {
        social("/auth/todogi/social", Map.of("code", "c", "redirectUri", "todogi://auth", "mode", "link", "provider", "google"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("identity_in_use"));
    }

    private void user(String id, String email, boolean verified, Instant created) {
        when(admin.getUser("todogi", id, ADMIN)).thenReturn(new KeycloakUserDto(id, email, email, "A", "B", true, verified,
                created.toEpochMilli(), null));
    }

    private ResultActions social(String path, Map<String, String> body) throws Exception {
        StringBuilder json = new StringBuilder("{");
        body.forEach((k, v) -> json.append(json.length() > 1 ? "," : "").append('"').append(k).append("\":\"").append(v).append('"'));
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json.append('}').toString()));
    }

    private static void signedIn(String realm, String userId) {
        Jwt jwt = Jwt.withTokenValue("bearer-" + userId).header("alg", "RS256").subject(userId)
                .claim("iss", BASE + "/realms/" + realm).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }

    private static TokenResponseDto tokens(String subject) {
        String access = new PlainJWT(new JWTClaimsSet.Builder().subject(subject).build()).serialize();
        return new TokenResponseDto(access, "refresh-" + subject, 300, 1800, "Bearer", "openid email profile");
    }

    /** Access token as Keycloak issues it after a provider sign-in (talay-identity identity_provider claim). */
    private static TokenResponseDto tokens(String subject, String provider, Instant authTime, String sid) {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject(subject).claim("sid", sid);
        if (provider != null) {
            claims.claim("identity_provider", provider);
        }
        if (authTime != null) {
            claims.claim("auth_time", authTime.getEpochSecond());
        }
        return new TokenResponseDto(new PlainJWT(claims.build()).serialize(), "refresh-" + subject, 300, 1800, "Bearer",
                "openid email profile");
    }

    private static KeycloakCredentialDto password() {
        return new KeycloakCredentialDto("cred", "password", 1L);
    }

    private static KeycloakFederatedIdentityDto link(String alias, String userName) {
        return new KeycloakFederatedIdentityDto(alias, alias + "-id", userName);
    }

    private double count(String realm, String action, String result) {
        var counter = meters.find("auth.gateway.identity.requests")
                .tags("realm", realm, "action", action, "result", result).counter();
        return counter == null ? 0 : counter.count();
    }

    private static FeignException feign(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST, "https://auth/x", Map.of(), null, StandardCharsets.UTF_8, null);
        return FeignException.errorStatus("x", feign.Response.builder().status(status).request(request)
                .body(body, StandardCharsets.UTF_8).headers(Map.of()).build());
    }
}
