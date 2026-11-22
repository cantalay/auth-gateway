package com.cantalay.authgateway.account;

import com.cantalay.authgateway.action.ActionPurpose;
import com.cantalay.authgateway.action.ActionTokenService;
import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.controller.AccountController;
import com.cantalay.authgateway.controller.AuthController;
import com.cantalay.authgateway.domain.KeycloakCredentialDto;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.exception.GlobalAuthExceptionHandler;
import com.cantalay.authgateway.mail.AccountMailService;
import com.cantalay.authgateway.mail.MailProperties;
import com.cantalay.authgateway.mail.MailTemplates;
import com.cantalay.authgateway.realm.GatewayProperties;
import com.cantalay.authgateway.realm.RealmRegistry;
import com.cantalay.authgateway.service.AuthAdminService;
import com.cantalay.authgateway.service.AuthService;
import com.cantalay.authgateway.support.Mails;
import feign.FeignException;
import feign.Request;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Component tests: real controllers and services, Keycloak admin API and SMTP mocked. */
class AccountControllerTest {

    private static final String SECRETS = "k1:" + Base64.getEncoder().encodeToString(
            "component-test-secret-0123456789".getBytes(StandardCharsets.US_ASCII));
    private static final String USER_ID = "4c1f0d6e-0000-4000-8000-000000000001";
    private static final String SOCIAL_ID = "4c1f0d6e-0000-4000-8000-000000000002";

    private final RateLimiterTest.MutableClock clock = new RateLimiterTest.MutableClock();
    private final KeycloakClient keycloak = mock(KeycloakClient.class);
    private final KeycloakAdminClient admin = mock(KeycloakAdminClient.class);
    private final AuthAdminService adminService = mock(AuthAdminService.class);
    private final JavaMailSender sender = mock(JavaMailSender.class);
    private final List<MimeMessage> sent = new ArrayList<>();
    private final AtomicLong passwordCreated = new AtomicLong(1_700_000_000_000L);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private ActionTokenService tokens;
    private MailProperties mailProperties;
    private AccountActionService actions;
    private MockMvc mvc;
    private KeycloakUserDto can;

    @BeforeEach
    void setUp() {
        mailProperties = new MailProperties();
        MailProperties.Realm todogi = new MailProperties.Realm();
        todogi.setFrom("noreply@todogi.net");
        todogi.setFromName("ToDoGi");
        todogi.setAppName("ToDoGi");
        todogi.setAppUrl("https://todogi.net");
        todogi.setResetUrl("https://todogi.net/sifre-sifirla");
        todogi.setVerifyUrl("https://todogi.net/eposta-onay");
        todogi.setLocales(List.of("tr", "en"));
        todogi.setDefaultLocale("tr");
        mailProperties.getRealms().put("todogi", todogi);

        @SuppressWarnings("unchecked")
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        when(provider.getObject()).thenReturn(sender);
        when(sender.createMimeMessage()).thenAnswer(i -> new MimeMessage(Session.getInstance(new Properties())));
        doAnswer(i -> sent.add(i.getArgument(0))).when(sender).send(any(MimeMessage.class));

        tokens = new ActionTokenService(SECRETS, Duration.ofMinutes(60), Duration.ofHours(24), clock);
        AccountMailService mail = new AccountMailService(provider, mailProperties, new MailTemplates(), meters, "smtp.test");
        actions = new AccountActionService(adminService, keycloak, admin, tokens, mail, mailProperties,
                new RateLimiter(clock), meters, Runnable::run);

        GatewayProperties gatewayProperties = new GatewayProperties();
        GatewayProperties.Realm vitafinder = new GatewayProperties.Realm();
        vitafinder.setAdminClientSecret("vf");
        gatewayProperties.getRealms().put("vitafinder", vitafinder);
        RealmRegistry realms = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                true, gatewayProperties);

        mvc = MockMvcBuilders.standaloneSetup(
                        new AccountController(actions, realms),
                        new AuthController(new AuthService(adminService, keycloak, admin, actions), realms))
                .setControllerAdvice(new GlobalAuthExceptionHandler())
                .build();

        when(adminService.getAdminAccessToken(any())).thenReturn("adm");
        can = new KeycloakUserDto(USER_ID, "can@ornek.com", "can@ornek.com", "Can", "Yılmaz", true, false, 0L,
                Map.of("locale", List.of("en")));
        KeycloakUserDto social = new KeycloakUserDto(SOCIAL_ID, "ayse@gmail.com", "ayse@gmail.com", "Ayşe", "K", true, true, 0L, null);
        when(admin.getUsersByEmail(eq("todogi"), anyString(), anyString(), eq(true))).thenReturn(List.of());
        when(admin.getUsersByEmail("todogi", "Bearer adm", "can@ornek.com", true)).thenReturn(List.of(can));
        when(admin.getUsersByEmail("todogi", "Bearer adm", "ayse@gmail.com", true)).thenReturn(List.of(social));
        when(admin.getUser("todogi", USER_ID, "Bearer adm")).thenAnswer(i -> can);
        when(admin.getUser("todogi", SOCIAL_ID, "Bearer adm")).thenReturn(social);
        when(admin.getCredentials("todogi", USER_ID, "Bearer adm"))
                .thenAnswer(i -> List.of(new KeycloakCredentialDto("cred-1", "password", passwordCreated.get())));
        when(admin.getCredentials("todogi", SOCIAL_ID, "Bearer adm")).thenReturn(List.of());
        when(admin.getFederatedIdentities("todogi", SOCIAL_ID, "Bearer adm"))
                .thenReturn(List.of(new KeycloakFederatedIdentityDto("google", "1093", "ayse@gmail.com")));
        doAnswer(i -> {
            passwordCreated.addAndGet(1000);
            return null;
        }).when(admin).resetPassword(eq("todogi"), eq(USER_ID), eq("Bearer adm"), anyMap());
    }

    private MvcResult postJson(String path, String body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)
                .header("X-Forwarded-For", "203.0.113.9")).andReturn();
    }

    private String resetToken() throws Exception {
        postJson("/auth/todogi/forgot-password", "{\"email\":\"can@ornek.com\"}");
        return Mails.token(sent.get(sent.size() - 1));
    }

    /* ---------- forgot-password ---------- */

    @Test
    void forgotPasswordSendsAResetLinkInTheUsersLanguage() throws Exception {
        MvcResult result = postJson("/auth/todogi/forgot-password", "{\"email\":\"can@ornek.com\"}");

        assertThat(result.getResponse().getStatus()).isEqualTo(202);
        assertThat(sent).hasSize(1);
        MimeMessage mail = sent.get(0);
        assertThat(mail.getFrom()[0].toString()).isEqualTo("ToDoGi <noreply@todogi.net>");
        assertThat(Mails.subject(mail)).isEqualTo("Reset your ToDoGi password"); // user's locale attribute: en
        assertThat(Mails.plainText(mail)).contains("https://todogi.net/sifre-sifirla#t=").contains("1 hour");
        assertThat(tokens.verify(Mails.token(mail), "todogi", ActionPurpose.RESET).subject()).isEqualTo(USER_ID);

        postJson("/auth/forgot-password", "{\"email\":\"can@ornek.com\",\"locale\":\"tr-TR\"}"); // legacy path, default realm
        assertThat(Mails.subject(sent.get(1))).isEqualTo("ToDoGi parolanı sıfırla");
    }

    @Test
    void unknownAddressGetsTheSameAnswerAndNoEmail() throws Exception {
        MvcResult known = postJson("/auth/todogi/forgot-password", "{\"email\":\"can@ornek.com\"}");
        MvcResult unknown = postJson("/auth/todogi/forgot-password", "{\"email\":\"nobody@ornek.com\"}");

        assertThat(unknown.getResponse().getStatus()).isEqualTo(known.getResponse().getStatus()).isEqualTo(202);
        assertThat(unknown.getResponse().getContentAsString()).isEqualTo(known.getResponse().getContentAsString());
        assertThat(sent).hasSize(1);
    }

    @Test
    void passwordlessSocialAccountIsToldToUseItsProvider() throws Exception {
        postJson("/auth/todogi/forgot-password", "{\"email\":\"ayse@gmail.com\"}");

        assertThat(sent).hasSize(1);
        String text = Mails.plainText(sent.get(0));
        assertThat(Mails.subject(sent.get(0))).isEqualTo("ToDoGi hesabına giriş");
        assertThat(text).contains("Google ile giriş yapıyorsun").doesNotContain("#t=").doesNotContain("sifre-sifirla");
    }

    @Test
    void fourthRequestWithinAnHourSendsNothing() throws Exception {
        for (int i = 0; i < 4; i++) {
            assertThat(postJson("/auth/todogi/forgot-password", "{\"email\":\"Can@Ornek.com\"}").getResponse().getStatus()).isEqualTo(202);
        }
        assertThat(sent).hasSize(3);
        clock.now = clock.now.plus(Duration.ofMinutes(61));
        postJson("/auth/todogi/forgot-password", "{\"email\":\"can@ornek.com\"}");
        assertThat(sent).hasSize(4);
    }

    @Test
    void realmsWithoutGatewayEmailsAnswerFeatureDisabled() throws Exception {
        for (String path : List.of("/auth/vitafinder/forgot-password", "/auth/vitafinder/reset-password/check",
                "/auth/vitafinder/reset-password", "/auth/vitafinder/verify-email")) {
            String body = path.endsWith("forgot-password") ? "{\"email\":\"a@b.co\"}"
                    : path.endsWith("reset-password") ? "{\"token\":\"x\",\"newPassword\":\"y\"}" : "{\"token\":\"x\"}";
            mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.success").value(false))
                    .andExpect(jsonPath("$.error.status").value(404))
                    .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"));
        }
        mvc.perform(post("/auth/master/forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"a@b.co\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").doesNotExist()); // unknown realm: unchanged error
        verify(adminService, never()).getAdminAccessToken(any());
    }

    @Test
    void malformedBodiesAreClientErrors() throws Exception {
        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/auth/todogi/forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"not-an-email\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    /* ---------- reset-password ---------- */

    @Test
    void resetSetsThePasswordEndsSessionsAndSignsIn() throws Exception {
        String token = resetToken();
        TokenResponseDto session = new TokenResponseDto("at", "rt", 300, 0, "Bearer", "openid offline_access");
        when(keycloak.token(eq("todogi"), any())).thenReturn(session);

        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}")).andExpect(status().isNoContent());
        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("at"))
                .andExpect(jsonPath("$.refresh_token").value("rt"));

        verify(admin).resetPassword(eq("todogi"), eq(USER_ID), eq("Bearer adm"),
                eq(Map.of("type", "password", "value", "Yeni-Parola-2026", "temporary", false)));
        verify(admin).logoutUser("todogi", USER_ID, "Bearer adm");
        verify(admin).revokeConsent("todogi", USER_ID, "auth", "Bearer adm");
        verify(admin).clearBruteForce("todogi", USER_ID, "Bearer adm");
        assertThat(Mails.subject(sent.get(sent.size() - 1))).isEqualTo("Your ToDoGi password was changed");

        // single use: the credential changed, so the same link is gone
        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2027\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("reset_token_invalid"));
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}")).andExpect(status().isGone());
    }

    @Test
    void resetWithoutSignInAnswers204() throws Exception {
        String token = resetToken();
        when(keycloak.token(eq("todogi"), any())).thenThrow(feign(400, "{\"error\":\"invalid_grant\"}"));

        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void policyViolationKeepsTheLinkUsable() throws Exception {
        String token = resetToken();
        doThrow(feign(400, "{\"error\":\"invalidPasswordMinLengthMessage\",\"error_description\":\"Invalid password: minimum length 12.\"}"))
                .when(admin).resetPassword(eq("todogi"), eq(USER_ID), eq("Bearer adm"), anyMap());

        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"kisa\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("password_policy"))
                .andExpect(jsonPath("$.error.validationErrors.newPassword").value("length"));
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}")).andExpect(status().isNoContent());
        verify(admin, never()).logoutUser(any(), any(), any());
    }

    @Test
    void expiredTamperedForeignAndWrongPurposeTokensAre410() throws Exception {
        String fp = ActionTokenService.fingerprint("password", "cred-1", String.valueOf(passwordCreated.get()));
        clock.now = clock.now.minus(Duration.ofMinutes(61));
        String expired = tokens.issue("todogi", ActionPurpose.RESET, USER_ID, fp);
        clock.now = clock.now.plus(Duration.ofMinutes(61));
        String valid = tokens.issue("todogi", ActionPurpose.RESET, USER_ID, fp);
        char last = valid.charAt(valid.length() - 1);
        String tampered = valid.substring(0, valid.length() - 1) + (last == 'A' ? 'B' : 'A');
        String otherRealm = tokens.issue("vitafinder", ActionPurpose.RESET, USER_ID, fp);
        String verifyPurpose = tokens.issue("todogi", ActionPurpose.VERIFY, USER_ID, fp);

        for (String token : List.of(expired, tampered, otherRealm, verifyPurpose, "garbage", "a".repeat(5000))) {
            mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                    .andExpect(status().isGone())
                    .andExpect(jsonPath("$.error.code").value("reset_token_invalid"));
        }
        verify(admin, never()).resetPassword(any(), any(), any(), anyMap());
        assertThat(meters.find("auth.gateway.action.requests").tag("action", "reset").tag("result", "expired").counter().count()).isEqualTo(1);
    }

    @Test
    void tokenEndpointsAreRateLimitedPerAddress() throws Exception {
        for (int i = 0; i < 20; i++) {
            mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", "198.51.100.7").content("{\"token\":\"x\"}")).andExpect(status().isGone());
        }
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "198.51.100.7").content("{\"token\":\"x\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("rate_limited"));
        // a spoofed leading entry does not change the address Traefik appended
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "10.0.0.1, 198.51.100.7").content("{\"token\":\"x\"}"))
                .andExpect(status().isTooManyRequests());
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "198.51.100.8").content("{\"token\":\"x\"}")).andExpect(status().isGone());
    }

    /* ---------- registration and email confirmation ---------- */

    @Test
    void registrationSendsGatewayConfirmationAndWelcome() throws Exception {
        when(admin.getUsersByEmail("todogi", "Bearer adm", "can@ornek.com", true)).thenReturn(List.of(
                new KeycloakUserDto(USER_ID, "can@ornek.com", "can@ornek.com", "Can", "Yılmaz", true, false, 0L, null)));

        mvc.perform(post("/auth/todogi/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"can@ornek.com\",\"password\":\"Parola-2026-xyz\",\"firstName\":\"Can\",\"lastName\":\"Yılmaz\",\"locale\":\"tr\"}"))
                .andExpect(status().isCreated());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> payload = ArgumentCaptor.forClass(Map.class);
        verify(admin).createUser(eq("todogi"), eq("Bearer adm"), payload.capture());
        assertThat(payload.getValue()).containsEntry("attributes", Map.of("locale", List.of("tr")));
        verify(admin, never()).sendVerificationEmail(any(), any(), any(), any(), any());
        assertThat(sent).extracting(Mails::subject).containsExactly("ToDoGi için e-postanı onayla", "Hoş geldin — ToDoGi");
        assertThat(Mails.plainText(sent.get(0))).contains("https://todogi.net/eposta-onay#t=").contains("24 saat");
        assertThat(Mails.plainText(sent.get(1))).contains("ayrı bir e-posta");

        // the first send counts: "send again" within a minute sends nothing
        postJson("/auth/todogi/resend-verification", "{\"email\":\"can@ornek.com\"}");
        assertThat(sent).hasSize(2);
        clock.now = clock.now.plusSeconds(61);
        postJson("/auth/todogi/resend-verification", "{\"email\":\"can@ornek.com\"}");
        assertThat(sent).hasSize(3);
        postJson("/auth/todogi/resend-verification", "{\"email\":\"can@ornek.com\"}");
        assertThat(sent).hasSize(3);
    }

    @Test
    void verifyEmailIsIdempotentAndBoundToTheAddress() throws Exception {
        postJson("/auth/todogi/resend-verification", "{\"email\":\"can@ornek.com\"}");
        String token = Mails.token(sent.get(0));

        mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isNoContent());
        verify(admin).updateUser("todogi", USER_ID, "Bearer adm", Map.of("emailVerified", true));

        can = new KeycloakUserDto(USER_ID, "can@ornek.com", "can@ornek.com", "Can", "Yılmaz", true, true, 0L, null);
        mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isNoContent());
        verify(admin, times(1)).updateUser(any(), any(), any(), anyMap());

        can = new KeycloakUserDto(USER_ID, "yeni@ornek.com", "yeni@ornek.com", "Can", "Yılmaz", true, false, 0L, null);
        mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("verify_token_invalid"));
        String resetPurpose = tokens.issue("todogi", ActionPurpose.RESET, USER_ID, ActionTokenService.emailFingerprint("yeni@ornek.com"));
        mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + resetPurpose + "\"}"))
                .andExpect(status().isGone());
    }

    @Test
    void verifiedOrUnknownAddressesGetNoConfirmation() throws Exception {
        postJson("/auth/todogi/resend-verification", "{\"email\":\"ayse@gmail.com\"}");
        postJson("/auth/todogi/resend-verification", "{\"email\":\"nobody@ornek.com\"}");
        assertThat(sent).isEmpty();
    }

    @Test
    void realmsWithoutVerifyUrlKeepKeycloaksVerificationEmail() throws Exception {
        KeycloakUserDto vf = new KeycloakUserDto("vf-1", "a@b.co", "a@b.co", "A", "B", true, false, 0L, null);
        when(admin.getUsersByEmail("vitafinder", "Bearer adm", "a@b.co", true)).thenReturn(List.of(vf));

        mvc.perform(post("/auth/vitafinder/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.co\",\"password\":\"Parola-2026-xyz\",\"firstName\":\"A\",\"lastName\":\"B\",\"locale\":\"tr\"}"))
                .andExpect(status().isCreated());
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> payload = ArgumentCaptor.forClass(Map.class);
        verify(admin).createUser(eq("vitafinder"), eq("Bearer adm"), payload.capture());
        assertThat(payload.getValue()).doesNotContainKey("attributes"); // payload as before
        verify(admin).sendVerificationEmail(eq("vitafinder"), eq("vf-1"), eq("Bearer adm"), isNull(), isNull());

        // resend-verification is opt-in per realm
        mvc.perform(post("/auth/vitafinder/resend-verification").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@b.co\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("realm_feature_disabled"));
        MailProperties.Realm optIn = new MailProperties.Realm();
        optIn.setResendVerification(true);
        mailProperties.getRealms().put("vitafinder", optIn);

        mvc.perform(post("/auth/vitafinder/resend-verification").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"a@b.co\"}")).andExpect(status().isAccepted());
        verify(admin, times(1)).sendVerificationEmail(any(), any(), any(), any(), any()); // within the minute
        clock.now = clock.now.plusSeconds(61);
        mvc.perform(post("/auth/vitafinder/resend-verification").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"a@b.co\"}")).andExpect(status().isAccepted());
        verify(admin, times(2)).sendVerificationEmail(eq("vitafinder"), eq("vf-1"), eq("Bearer adm"), isNull(), isNull());
        assertThat(sent).isEmpty(); // no gateway email for realms without a sender
    }

    /* ---------- review fixes ---------- */

    @Test
    void failedSessionRevocationIsA503WithoutANewSession() throws Exception {
        String token = resetToken();
        doThrow(feign(503, "{}")).when(admin).logoutUser("todogi", USER_ID, "Bearer adm");

        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error.code").value("sessions_revoke_failed"));

        verify(admin, times(2)).logoutUser("todogi", USER_ID, "Bearer adm"); // retried once
        verify(keycloak, never()).token(eq("todogi"), any());
        assertThat(Mails.subject(sent.get(sent.size() - 1))).isEqualTo("Your ToDoGi password was changed");
        assertThat(meters.find("auth.gateway.action.requests").tag("action", "reset").tag("result", "sessions_failed")
                .counter().count()).isEqualTo(1);

        // the way to try again: a new link (the old one is spent because the password changed)
        mvc.perform(post("/auth/todogi/reset-password/check").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}")).andExpect(status().isGone());
        org.mockito.Mockito.doNothing().when(admin).logoutUser("todogi", USER_ID, "Bearer adm");
        when(keycloak.token(eq("todogi"), any())).thenReturn(new TokenResponseDto("at", "rt", 300, 0, "Bearer", "openid"));
        String second = resetToken();
        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + second + "\",\"newPassword\":\"Ucuncu-Parola-2026\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void aTransientRevocationErrorIsRetried() throws Exception {
        String token = resetToken();
        doThrow(feign(500, "{}")).doNothing().when(admin).revokeConsent("todogi", USER_ID, "auth", "Bearer adm");
        when(keycloak.token(eq("todogi"), any())).thenReturn(new TokenResponseDto("at", "rt", 300, 0, "Bearer", "openid"));

        mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                .andExpect(status().isOk());
        verify(admin, times(2)).revokeConsent("todogi", USER_ID, "auth", "Bearer adm");
    }

    @Test
    void concurrentResetsWithOneLinkChangeThePasswordOnce() throws Exception {
        String token = resetToken();
        java.util.concurrent.atomic.AtomicInteger inside = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger maxInside = new java.util.concurrent.atomic.AtomicInteger();
        doAnswer(i -> {
            maxInside.accumulateAndGet(inside.incrementAndGet(), Math::max);
            Thread.sleep(150);
            passwordCreated.addAndGet(1000);
            inside.decrementAndGet();
            return null;
        }).when(admin).resetPassword(eq("todogi"), eq(USER_ID), eq("Bearer adm"), anyMap());
        when(keycloak.token(eq("todogi"), any())).thenReturn(new TokenResponseDto("at", "rt", 300, 0, "Bearer", "openid"));

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(4);
        List<java.util.concurrent.Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            results.add(pool.submit(() -> mvc.perform(post("/auth/todogi/reset-password").contentType(MediaType.APPLICATION_JSON)
                            .header("X-Forwarded-For", "203.0.113.50")
                            .content("{\"token\":\"" + token + "\",\"newPassword\":\"Yeni-Parola-2026\"}"))
                    .andReturn().getResponse().getStatus()));
        }
        List<Integer> statuses = new ArrayList<>();
        for (java.util.concurrent.Future<Integer> f : results) {
            statuses.add(f.get());
        }
        pool.shutdown();

        assertThat(statuses).containsOnly(200, 410);
        assertThat(statuses.stream().filter(c -> c == 200).count()).isEqualTo(1);
        assertThat(maxInside.get()).isEqualTo(1);
        verify(admin, times(1)).resetPassword(any(), any(), any(), anyMap());
    }

    @Test
    void concurrentConfirmationsAreSerialized() throws Exception {
        postJson("/auth/todogi/resend-verification", "{\"email\":\"can@ornek.com\"}");
        String token = Mails.token(sent.get(0));
        java.util.concurrent.atomic.AtomicInteger inside = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger maxInside = new java.util.concurrent.atomic.AtomicInteger();
        doAnswer(i -> {
            maxInside.accumulateAndGet(inside.incrementAndGet(), Math::max);
            Thread.sleep(100);
            can = new KeycloakUserDto(USER_ID, "can@ornek.com", "can@ornek.com", "Can", "Yılmaz", true, true, 0L, null);
            inside.decrementAndGet();
            return null;
        }).when(admin).updateUser(eq("todogi"), eq(USER_ID), eq("Bearer adm"), anyMap());

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(3);
        List<java.util.concurrent.Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            results.add(pool.submit(() -> mvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON)
                    .content("{\"token\":\"" + token + "\"}")).andReturn().getResponse().getStatus()));
        }
        for (java.util.concurrent.Future<Integer> f : results) {
            assertThat(f.get()).isEqualTo(204);
        }
        pool.shutdown();
        assertThat(maxInside.get()).isEqualTo(1);
        verify(admin, times(1)).updateUser(any(), any(), any(), anyMap());
    }

    @Test
    void registrationIsRateLimitedPerAddressAndEmail() throws Exception {
        String body = "{\"email\":\"new@ornek.com\",\"password\":\"Parola-2026-xyz\",\"firstName\":\"N\",\"lastName\":\"U\"}";
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/auth/vitafinder/register").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", "198.51.100." + (10 + i)).content(body)).andExpect(status().isCreated());
        }
        mvc.perform(post("/auth/vitafinder/register").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "198.51.100.99").content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("rate_limited"));

        for (int i = 0; i < 20; i++) {
            mvc.perform(post("/auth/vitafinder/register").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Forwarded-For", "2001:db8:1:2::" + Integer.toHexString(i + 1))
                    .content(body.replace("new@", "ip" + i + "@"))).andExpect(status().isCreated());
        }
        // another address in the same IPv6 /64
        mvc.perform(post("/auth/vitafinder/register").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "2001:db8:1:2:ffff::1").content(body.replace("new@", "other@")))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void namesOnlyGreetConfirmedAccounts() throws Exception {
        when(admin.getUsersByEmail("todogi", "Bearer adm", "can@ornek.com", true)).thenReturn(List.of(
                new KeycloakUserDto(USER_ID, "can@ornek.com", "can@ornek.com", "Tıkla evil.example", "X", true, false, 0L, null)));
        mvc.perform(post("/auth/todogi/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"can@ornek.com\",\"password\":\"Parola-2026-xyz\",\"firstName\":\"Tıkla evil.example\",\"lastName\":\"X\"}"))
                .andExpect(status().isCreated());
        assertThat(sent).hasSize(2);
        for (MimeMessage m : sent) {
            assertThat(Mails.plainText(m)).doesNotContain("evil.example").startsWith("Merhaba,");
        }

        sent.clear();
        postJson("/auth/todogi/forgot-password", "{\"email\":\"ayse@gmail.com\"}"); // verified (Google) account
        assertThat(Mails.plainText(sent.get(0))).startsWith("Merhaba Ayşe,");
    }

    @Test
    void verifyUrlWithoutEmailFallsBackToKeycloak() throws Exception {
        @SuppressWarnings("unchecked")
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        AccountMailService noSmtp = new AccountMailService(provider, mailProperties, new MailTemplates(), meters, "");
        AccountActionService degraded = new AccountActionService(adminService, keycloak, admin, tokens, noSmtp, mailProperties,
                new RateLimiter(clock), meters, Runnable::run);
        RealmRegistry realms = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                new GatewayProperties());
        MockMvc degradedMvc = MockMvcBuilders.standaloneSetup(new AccountController(degraded, realms),
                        new AuthController(new AuthService(adminService, keycloak, admin, degraded), realms))
                .setControllerAdvice(new GlobalAuthExceptionHandler()).build();

        assertThat(degraded.verifyMode(realms.resolve("todogi"))).isEqualTo(AccountActionService.VerifyMode.KEYCLOAK);
        degradedMvc.perform(post("/auth/todogi/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"can@ornek.com\",\"password\":\"Parola-2026-xyz\",\"firstName\":\"C\",\"lastName\":\"Y\"}"))
                .andExpect(status().isCreated());
        verify(admin).sendVerificationEmail(eq("todogi"), eq(USER_ID), eq("Bearer adm"), isNull(), isNull());
        degradedMvc.perform(post("/auth/todogi/verify-email").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"x\"}"))
                .andExpect(status().isNotFound());
        degradedMvc.perform(post("/auth/todogi/forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"a@b.co\"}"))
                .andExpect(status().isNotFound());

        org.springframework.context.ConfigurableApplicationContext context = mock(org.springframework.context.ConfigurableApplicationContext.class);
        when(context.getBean(RealmRegistry.class)).thenReturn(realms);
        degraded.reportConfiguration(new org.springframework.boot.context.event.ApplicationReadyEvent(
                new org.springframework.boot.SpringApplication(), new String[0], context, Duration.ZERO));
        assertThat(meters.find("auth.gateway.feature.degraded").tag("realm", "todogi").tag("feature", "verify").gauge().value()).isEqualTo(1.0);
        assertThat(meters.find("auth.gateway.feature.degraded").tag("realm", "todogi").tag("feature", "reset").gauge().value()).isEqualTo(1.0);
    }

    private static FeignException feign(int status, String body) {
        Request request = Request.create(Request.HttpMethod.PUT, "https://auth/x", Map.of(), null, StandardCharsets.UTF_8, null);
        return FeignException.errorStatus("x", feign.Response.builder().status(status).request(request)
                .body(body, StandardCharsets.UTF_8).headers(Map.of()).build());
    }
}
