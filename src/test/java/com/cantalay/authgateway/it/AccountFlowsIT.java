package com.cantalay.authgateway.it;

import com.cantalay.authgateway.action.ActionPurpose;
import com.cantalay.authgateway.action.ActionTokenService;
import com.cantalay.authgateway.support.Mails;
import com.icegreen.greenmail.configuration.GreenMailConfiguration;
import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.mail.Message;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End to end against a real Keycloak (realm settings close to the talay-identity module: password policy, brute-force
 * detection, offline_access default role, tr/en) with GreenMail as the SMTP server. Covers İP-04 acceptance criteria
 * 1–12 and 15 locally; nothing here talks to a live system.
 */
@Testcontainers(disabledWithoutDocker = true)
// GreenMail (the test SMTP server) logs the addresses it creates; only the gateway's own logs are checked (criterion 15)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "logging.level.com.icegreen=WARN")
@ExtendWith(OutputCaptureExtension.class)
class AccountFlowsIT {

    private static final String KEYCLOAK_IMAGE = System.getProperty("it.keycloak.image", "quay.io/keycloak/keycloak:26.7.3");
    private static final String SECRETS = "k1:" + Base64.getEncoder().encodeToString(
            "integration-test-secret-0123456789".getBytes(StandardCharsets.US_ASCII));
    private static final String PASSWORD = "Ilk-Parola-2026!";
    private static final String NEW_PASSWORD = "Yeni-Parola-2026!";
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final AtomicInteger IPS = new AtomicInteger();

    @SuppressWarnings("resource")
    static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(KEYCLOAK_IMAGE)
            .withCommand("start-dev", "--import-realm")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forClasspathResource("it/realm-todogi.json"), "/opt/keycloak/data/import/realm-todogi.json")
            .withCopyFileToContainer(MountableFile.forClasspathResource("it/realm-vitafinder.json"), "/opt/keycloak/data/import/realm-vitafinder.json")
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/realms/vitafinder/.well-known/openid-configuration").forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    static final GreenMail SMTP = new GreenMail(new ServerSetup(0, "127.0.0.1", ServerSetup.PROTOCOL_SMTP))
            .withConfiguration(GreenMailConfiguration.aConfig().withUser("gateway", "smtp-password"));

    static {
        KEYCLOAK.start();
        SMTP.start();
    }

    @AfterAll
    static void stopSmtp() {
        SMTP.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("keycloak.base-url", AccountFlowsIT::keycloakUrl);
        registry.add("keycloak.realm", () -> "todogi");
        registry.add("keycloak.client-id", () -> "auth");
        registry.add("keycloak.admin.client-id", () -> "auth-gateway-admin");
        registry.add("keycloak.admin.client-secret", () -> "it-todogi-admin-secret");
        registry.add("keycloak.offline-access", () -> "true");
        registry.add("gateway.realms.vitafinder.admin-client-secret", () -> "it-vitafinder-admin-secret");
        registry.add("gateway.action-token.secrets", () -> SECRETS);
        registry.add("gateway.mail.realms.todogi.from", () -> "noreply@todogi.net");
        registry.add("gateway.mail.realms.todogi.from-name", () -> "ToDoGi");
        registry.add("gateway.mail.realms.todogi.app-name", () -> "ToDoGi");
        registry.add("gateway.mail.realms.todogi.app-url", () -> "https://todogi.net");
        registry.add("gateway.mail.realms.todogi.reset-url", () -> "https://todogi.net/sifre-sifirla");
        registry.add("gateway.mail.realms.todogi.verify-url", () -> "https://todogi.net/eposta-onay");
        registry.add("gateway.mail.realms.todogi.locales", () -> "tr,en");
        registry.add("gateway.mail.realms.todogi.default-locale", () -> "tr");
        registry.add("spring.mail.host", () -> "127.0.0.1");
        registry.add("spring.mail.port", () -> SMTP.getSmtp().getPort());
        registry.add("spring.mail.username", () -> "gateway");
        registry.add("spring.mail.password", () -> "smtp-password");
        registry.add("spring.mail.properties.mail.smtp.ssl.enable", () -> "false");
        registry.add("otel.sdk.disabled", () -> "true");
        registry.add("otel.exporter.otlp.endpoint", () -> "http://127.0.0.1:4318");
        registry.add("otel.exporter.otlp.protocol", () -> "http/protobuf");
    }

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void clearMail() throws Exception {
        SMTP.purgeEmailFromAllMailboxes();
    }

    /* ======================= criteria ======================= */

    /** Criteria 10 and 12: register → confirmation + welcome, confirm, refresh shows email_verified, offline token. */
    @Test
    void registrationConfirmationAndOfflineSession(CapturedOutput output) throws Exception {
        String email = newEmail();
        assertThat(gateway("/auth/todogi/register", Map.of("email", email, "password", PASSWORD, "firstName", "Can",
                "lastName", "Yılmaz", "locale", "tr")).statusCode()).isEqualTo(201);

        List<MimeMessage> mails = awaitMail(email, 2);
        MimeMessage verify = mails.stream().filter(m -> Mails.subject(m).contains("onayla")).findFirst().orElseThrow();
        assertThat(mails).extracting(Mails::subject).contains("Hoş geldin — ToDoGi");
        assertThat(Mails.plainText(verify)).contains("https://todogi.net/eposta-onay#t=").contains("24 saat");
        assertThat(verify.getFrom()[0].toString()).isEqualTo("ToDoGi <noreply@todogi.net>");
        String token = Mails.token(verify);

        JsonNode session = json(gateway("/auth/todogi/login", Map.of("email", email, "password", PASSWORD)), 200);
        assertThat(claims(session.get("refresh_token").asString()).get("typ").asString()).isEqualTo("Offline");
        assertThat(claims(session.get("access_token").asString()).get("email_verified").asBoolean()).isFalse();

        assertThat(gateway("/auth/todogi/verify-email", Map.of("token", token)).statusCode()).isEqualTo(204);
        JsonNode refreshed = json(gateway("/auth/todogi/refresh", Map.of("refreshToken", session.get("refresh_token").asString())), 200);
        assertThat(claims(refreshed.get("access_token").asString()).get("email_verified").asBoolean()).isTrue();
        assertThat(gateway("/auth/todogi/verify-email", Map.of("token", token)).statusCode()).isEqualTo(204);

        String id = userId("todogi", email);
        JsonNode user = adminGet("/admin/realms/todogi/users/" + id);
        assertThat(user.get("firstName").asString()).isEqualTo("Can"); // the partial update kept the profile
        assertThat(user.get("attributes").get("locale").get(0).asString()).isEqualTo("tr");
        adminPut("/admin/realms/todogi/users/" + id, Map.of("email", "degisti-" + email));
        HttpResponse<String> gone = gateway("/auth/todogi/verify-email", Map.of("token", token));
        assertThat(gone.statusCode()).isEqualTo(410);
        assertThat(json(gone, 410).get("error").get("code").asString()).isEqualTo("verify_token_invalid");

        assertNoSecretsLogged(output, token, session.get("refresh_token").asString(), session.get("access_token").asString(),
                PASSWORD, email);
    }

    /** Criteria 1, 4, 5, 7: forgot → link, policy error keeps the link, reset signs in, old sessions and password die. */
    @Test
    void forgotAndResetPassword(CapturedOutput output) throws Exception {
        String email = registeredUser();
        JsonNode before = json(gateway("/auth/todogi/login", Map.of("email", email, "password", PASSWORD)), 200);

        HttpResponse<String> accepted = gateway("/auth/todogi/forgot-password", Map.of("email", email));
        assertThat(accepted.statusCode()).isEqualTo(202);
        MimeMessage mail = awaitMail(email, 1).get(0);
        assertThat(Mails.subject(mail)).isEqualTo("ToDoGi parolanı sıfırla");
        assertThat(Mails.plainText(mail)).contains("https://todogi.net/sifre-sifirla#t=").contains("1 saat");
        String token = Mails.token(mail);

        HttpResponse<String> weak = gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", "kisaparola"));
        assertThat(weak.statusCode()).isEqualTo(400);
        assertThat(json(weak, 400).get("error").get("code").asString()).isEqualTo("password_policy");
        assertThat(gateway("/auth/todogi/reset-password/check", Map.of("token", token)).statusCode()).isEqualTo(204);

        JsonNode after = json(gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", NEW_PASSWORD)), 200);
        assertThat(claims(after.get("refresh_token").asString()).get("typ").asString()).isEqualTo("Offline");

        assertThat(gateway("/auth/todogi/login", Map.of("email", email, "password", PASSWORD)).statusCode()).isEqualTo(401);
        assertThat(gateway("/auth/todogi/refresh", Map.of("refreshToken", before.get("refresh_token").asString())).statusCode()).isEqualTo(401);
        HttpResponse<String> raw = keycloakToken("todogi", Map.of("grant_type", "refresh_token", "client_id", "auth",
                "refresh_token", before.get("refresh_token").asString()));
        assertThat(raw.statusCode()).isEqualTo(400);
        assertThat(raw.body()).contains("invalid_grant");
        assertThat(gateway("/auth/todogi/refresh", Map.of("refreshToken", after.get("refresh_token").asString())).statusCode()).isEqualTo(200);

        List<MimeMessage> all = awaitMail(email, 2);
        assertThat(all).extracting(Mails::subject).contains("ToDoGi parolan değişti");

        HttpResponse<String> reused = gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", "Ucuncu-Parola-2026!"));
        assertThat(reused.statusCode()).isEqualTo(410);
        assertThat(json(reused, 410).get("error").get("code").asString()).isEqualTo("reset_token_invalid");

        assertNoSecretsLogged(output, token, PASSWORD, NEW_PASSWORD, email, after.get("access_token").asString(),
                after.get("refresh_token").asString());
    }

    /** Single use under concurrency: parallel requests with one link change the password once. */
    @Test
    void parallelResetsWithOneLink() throws Exception {
        String email = registeredUser();
        gateway("/auth/todogi/forgot-password", Map.of("email", email));
        String token = Mails.token(awaitMail(email, 1).get(0));

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(4);
        List<java.util.concurrent.Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String password = "Paralel-Parola-" + i + "!";
            futures.add(pool.submit(() -> gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", password)).statusCode()));
        }
        List<Integer> statuses = new ArrayList<>();
        for (java.util.concurrent.Future<Integer> f : futures) {
            statuses.add(f.get());
        }
        pool.shutdown();

        assertThat(statuses).containsOnly(200, 410);
        assertThat(statuses.stream().filter(c -> c == 200).count()).isEqualTo(1);
    }

    /** Criterion 8: a brute-force lockout does not survive a successful reset. */
    @Test
    void resetLiftsTheLockout() throws Exception {
        String email = registeredUser();
        for (int i = 0; i < 6; i++) {
            gateway("/auth/todogi/login", Map.of("email", email, "password", "Yanlis-Parola-" + i + "!"));
        }
        assertThat(gateway("/auth/todogi/login", Map.of("email", email, "password", PASSWORD)).statusCode()).isNotEqualTo(200);

        gateway("/auth/todogi/forgot-password", Map.of("email", email));
        String token = Mails.token(awaitMail(email, 1).get(0));
        assertThat(gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", NEW_PASSWORD)).statusCode()).isEqualTo(200);
        assertThat(gateway("/auth/todogi/login", Map.of("email", email, "password", NEW_PASSWORD)).statusCode()).isEqualTo(200);
    }

    /** Criterion 3: an account with only a Google link gets "sign in with Google", no reset link. */
    @Test
    void passwordlessGoogleAccount() throws Exception {
        String email = newEmail();
        adminPost("/admin/realms/todogi/users", Map.of("username", email, "email", email, "firstName", "Ayşe",
                "lastName", "K", "enabled", true, "emailVerified", true));
        String id = userId("todogi", email);
        adminPost("/admin/realms/todogi/users/" + id + "/federated-identity/google",
                Map.of("identityProvider", "google", "userId", "g-" + id, "userName", email));

        assertThat(gateway("/auth/todogi/forgot-password", Map.of("email", email)).statusCode()).isEqualTo(202);
        MimeMessage mail = awaitMail(email, 1).get(0);
        assertThat(Mails.subject(mail)).isEqualTo("ToDoGi hesabına giriş");
        assertThat(Mails.plainText(mail)).contains("Google ile giriş yapıyorsun").doesNotContain("#t=").doesNotContain("sifre-sifirla");
    }

    /** Criterion 6: expired, tampered, foreign realm and wrong purpose tokens are 410, never 500. */
    @Test
    void invalidResetTokens() throws Exception {
        String email = registeredUser();
        String id = userId("todogi", email);
        JsonNode password = Arrays.stream(JSON.readValue(adminGetRaw("/admin/realms/todogi/users/" + id + "/credentials"), JsonNode[].class))
                .filter(c -> c.get("type").asString().equals("password")).findFirst().orElseThrow();
        String fp = ActionTokenService.fingerprint("password", password.get("id").asString(), password.get("createdDate").asString());
        ActionTokenService anHourAgo = new ActionTokenService(SECRETS, Duration.ofMinutes(60), Duration.ofHours(24),
                Clock.fixed(Instant.now().minus(Duration.ofMinutes(61)), ZoneOffset.UTC));
        ActionTokenService now = new ActionTokenService(SECRETS, Duration.ofMinutes(60), Duration.ofHours(24), Clock.systemUTC());
        String valid = now.issue("todogi", ActionPurpose.RESET, id, fp);
        assertThat(gateway("/auth/todogi/reset-password/check", Map.of("token", valid)).statusCode()).isEqualTo(204);

        int middle = valid.length() / 2;
        String tampered = valid.substring(0, middle) + (valid.charAt(middle) == 'x' ? 'y' : 'x') + valid.substring(middle + 1);
        List<String> bad = List.of(anHourAgo.issue("todogi", ActionPurpose.RESET, id, fp), tampered,
                now.issue("vitafinder", ActionPurpose.RESET, id, fp), now.issue("todogi", ActionPurpose.VERIFY, id, fp),
                "%%%", "a".repeat(4000));
        for (String token : bad) {
            HttpResponse<String> response = gateway("/auth/todogi/reset-password", Map.of("token", token, "newPassword", NEW_PASSWORD));
            assertThat(response.statusCode()).isEqualTo(410);
            assertThat(json(response, 410).get("error").get("code").asString()).isEqualTo("reset_token_invalid");
        }
        assertThat(gateway("/auth/todogi/login", Map.of("email", email, "password", PASSWORD)).statusCode()).isEqualTo(200);
    }

    /** Criterion 9: limits stop the email, not the 202. */
    @Test
    void limitsAreSilent() throws Exception {
        String email = registeredUser();
        for (int i = 0; i < 4; i++) {
            assertThat(gateway("/auth/todogi/forgot-password", Map.of("email", email)).statusCode()).isEqualTo(202);
        }
        Thread.sleep(1500);
        assertThat(awaitMail(email, 3)).hasSize(3);

        String unverified = newEmail();
        adminPost("/admin/realms/todogi/users", Map.of("username", unverified, "email", unverified, "firstName", "U",
                "lastName", "V", "enabled", true, "emailVerified", false));
        assertThat(gateway("/auth/todogi/resend-verification", Map.of("email", unverified)).statusCode()).isEqualTo(202);
        assertThat(gateway("/auth/todogi/resend-verification", Map.of("email", unverified)).statusCode()).isEqualTo(202);
        Thread.sleep(1500);
        assertThat(awaitMail(unverified, 1)).hasSize(1);
    }

    /** Criterion 2: registered and unknown addresses answer alike; p50 difference under 20 ms over 100 requests. */
    @Test
    void forgotPasswordTimingDoesNotRevealAccounts() throws Exception {
        List<String> known = new ArrayList<>();
        for (int i = 0; i < 34; i++) {
            known.add(registeredUser());
        }
        for (int i = 0; i < 10; i++) { // warm-up
            gateway("/auth/todogi/forgot-password", Map.of("email", "warmup-" + i + "@ornek.test"));
        }
        long[] knownTimes = new long[100];
        long[] unknownTimes = new long[100];
        for (int i = 0; i < 100; i++) {
            long t0 = System.nanoTime();
            HttpResponse<String> a = gateway("/auth/todogi/forgot-password", Map.of("email", known.get(i % known.size())));
            knownTimes[i] = System.nanoTime() - t0;
            long t1 = System.nanoTime();
            HttpResponse<String> b = gateway("/auth/todogi/forgot-password", Map.of("email", "nobody-" + i + "@ornek.test"));
            unknownTimes[i] = System.nanoTime() - t1;
            assertThat(a.statusCode()).isEqualTo(b.statusCode()).isEqualTo(202);
            assertThat(a.body()).isEqualTo(b.body());
        }
        double diffMs = Math.abs(median(knownTimes) - median(unknownTimes)) / 1_000_000.0;
        System.out.printf("forgot-password p50 known=%.2f ms unknown=%.2f ms diff=%.2f ms%n",
                median(knownTimes) / 1e6, median(unknownTimes) / 1e6, diffMs);
        assertThat(diffMs).isLessThan(20.0);
    }

    /** Criterion 11 (and 12 with the flag off): a realm without gateway emails behaves as before. */
    @Test
    void otherRealmsAreUnchanged() throws Exception {
        String email = newEmail();
        assertThat(gateway("/auth/vitafinder/register", Map.of("email", email, "password", PASSWORD, "firstName", "V",
                "lastName", "F")).statusCode()).isEqualTo(201);
        JsonNode session = json(gateway("/auth/vitafinder/login", Map.of("email", email, "password", PASSWORD)), 200);
        assertThat(claims(session.get("refresh_token").asString()).get("typ").asString()).isEqualTo("Refresh");
        assertThat(gateway("/auth/vitafinder/login", Map.of("email", email, "password", "Yanlis-Parola-1!")).statusCode()).isEqualTo(401);
        // resend-verification is opt-in per realm (the endpoint did not exist before this change)
        assertThat(gateway("/auth/vitafinder/resend-verification", Map.of("email", email)).statusCode()).isEqualTo(404);

        HttpResponse<String> forgot = gateway("/auth/vitafinder/forgot-password", Map.of("email", email));
        assertThat(forgot.statusCode()).isEqualTo(404);
        assertThat(json(forgot, 404).get("error").get("code").asString()).isEqualTo("realm_feature_disabled");
        assertThat(gateway("/auth/vitafinder/verify-email", Map.of("token", "x")).statusCode()).isEqualTo(404);
        Thread.sleep(1000);
        assertThat(mailsTo(email)).isEmpty(); // no FROM for vitafinder: no gateway email

        // legacy default-realm path
        String todogi = registeredUser();
        assertThat(gateway("/auth/login", Map.of("email", todogi, "password", PASSWORD)).statusCode()).isEqualTo(200);
        assertThat(gateway("/auth/login", Map.of("email", todogi, "password", "Yanlis-Parola-1!")).statusCode()).isEqualTo(401);
    }

    /* ======================= helpers ======================= */

    private static String keycloakUrl() {
        return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
    }

    private static String newEmail() {
        return "it-" + UUID.randomUUID().toString().substring(0, 8) + "@ornek.test";
    }

    /** A todogi user with {@link #PASSWORD}, created through the gateway. */
    private String registeredUser() throws Exception {
        String email = newEmail();
        assertThat(gateway("/auth/todogi/register", Map.of("email", email, "password", PASSWORD, "firstName", "Test",
                "lastName", "User")).statusCode()).isEqualTo(201);
        awaitMail(email, 2); // confirmation + welcome
        SMTP.purgeEmailFromAllMailboxes();
        return email;
    }

    private HttpResponse<String> gateway(String path, Map<String, ?> body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/json")
                // every request from its own address so the per-IP limits do not couple the tests
                .header("X-Forwarded-For", "198.18." + (IPS.get() / 250 % 250) + "." + (IPS.getAndIncrement() % 250 + 1))
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> keycloakToken(String realm, Map<String, String> form) throws Exception {
        String encoded = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return http.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/" + realm + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encoded)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private String masterToken() throws Exception {
        HttpResponse<String> response = keycloakToken("master", Map.of("grant_type", "password", "client_id", "admin-cli",
                "username", "admin", "password", "admin"));
        return JSON.readTree(response.body()).get("access_token").asString();
    }

    private String adminGetRaw(String path) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return response.body();
    }

    private JsonNode adminGet(String path) throws Exception {
        return JSON.readTree(adminGetRaw(path));
    }

    private void adminPost(String path, Map<String, ?> body) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isBetween(200, 204);
    }

    private void adminPut(String path, Map<String, ?> body) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(204);
    }

    private String userId(String realm, String email) throws Exception {
        JsonNode users = JSON.readTree(adminGetRaw("/admin/realms/" + realm + "/users?exact=true&email="
                + URLEncoder.encode(email, StandardCharsets.UTF_8)));
        return users.get(0).get("id").asString();
    }

    private static JsonNode json(HttpResponse<String> response, int expectedStatus) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(expectedStatus);
        return JSON.readTree(response.body());
    }

    private static JsonNode claims(String jwt) {
        return JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    private static List<MimeMessage> mailsTo(String email) throws Exception {
        List<MimeMessage> result = new ArrayList<>();
        for (MimeMessage message : SMTP.getReceivedMessages()) {
            if (message.getRecipients(Message.RecipientType.TO)[0].toString().equalsIgnoreCase(email)) {
                result.add(message);
            }
        }
        return result;
    }

    private static List<MimeMessage> awaitMail(String email, int count) throws Exception {
        long deadline = System.currentTimeMillis() + 15_000;
        List<MimeMessage> found = mailsTo(email);
        while (found.size() < count && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
            found = mailsTo(email);
        }
        assertThat(found).as("emails to %s", email).hasSizeGreaterThanOrEqualTo(count);
        return found;
    }

    private static double median(long[] values) {
        long[] sorted = values.clone();
        Arrays.sort(sorted);
        return (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2.0;
    }

    /** Criterion 15: tokens, passwords and full addresses never reach the logs. */
    private static void assertNoSecretsLogged(CapturedOutput output, String... secrets) {
        String logs = output.getAll();
        for (String secret : secrets) {
            assertThat(logs).as("logs must not contain a secret").doesNotContain(secret);
        }
    }
}
