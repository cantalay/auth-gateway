package com.cantalay.authgateway.it;

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
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sign-in methods (ToDoGi İP-06 §2.9, criteria 15–17) end to end against a real Keycloak. A second realm,
 * {@code fakegoogle}, stands in for Google: realm {@code todogi} brokers it as an OIDC identity provider with the alias
 * {@code google} and the first broker login flow of talay-identity ({@code social-first-login}: create the user if
 * unique, otherwise link the account with the same email automatically). The test drives the browser part of the code
 * flow ({@code kc_idp_hint=google} → fake Google's login form → redirect to the app with a code) with an HTTP client, then
 * posts the code to the gateway like the app does. Nothing here talks to a live system.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class IdentityMethodsIT {

    private static final String KEYCLOAK_IMAGE = System.getProperty("it.keycloak.image", "quay.io/keycloak/keycloak:26.7.3");
    private static final String PASSWORD = "Ilk-Parola-2026!";
    private static final String GOOGLE_PASSWORD = "google-password";
    private static final String REDIRECT = "todogi://auth";
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @SuppressWarnings("resource")
    static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(KEYCLOAK_IMAGE)
            .withCommand("start-dev", "--import-realm")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forClasspathResource("it/realm-todogi-identity.json"), "/opt/keycloak/data/import/realm-todogi.json")
            .withCopyFileToContainer(MountableFile.forClasspathResource("it/realm-fakegoogle.json"), "/opt/keycloak/data/import/realm-fakegoogle.json")
            .withCopyFileToContainer(MountableFile.forClasspathResource("it/realm-vitafinder.json"), "/opt/keycloak/data/import/realm-vitafinder.json")
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/realms/fakegoogle/.well-known/openid-configuration").forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    static {
        KEYCLOAK.start();
        try {
            configureBroker();
        } catch (Exception e) {
            throw new IllegalStateException("Could not set up the Google stand-in", e);
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("keycloak.base-url", IdentityMethodsIT::keycloakUrl);
        registry.add("keycloak.realm", () -> "todogi");
        registry.add("keycloak.client-id", () -> "auth");
        registry.add("keycloak.admin.client-id", () -> "auth-gateway-admin");
        registry.add("keycloak.admin.client-secret", () -> "it-identity-admin-secret");
        registry.add("keycloak.identity-methods", () -> "true");
        registry.add("gateway.realms.vitafinder.admin-client-secret", () -> "it-vitafinder-admin-secret");
        registry.add("otel.sdk.disabled", () -> "true");
        registry.add("otel.exporter.otlp.endpoint", () -> "http://127.0.0.1:4318");
        registry.add("otel.exporter.otlp.protocol", () -> "http/protobuf");
    }

    @Value("${local.server.port}")
    int port;

    /* ======================= criteria ======================= */

    /** Criterion 15: password + Google → list, remove Google (204, again 204); Google-only account → 409 last_method. */
    @Test
    void listAndRemoveSignInMethods() throws Exception {
        String email = newEmail();
        String id = createUser("todogi", email, true, PASSWORD);
        String googleId = createUser("fakegoogle", email, true, GOOGLE_PASSWORD);
        adminPost("/admin/realms/todogi/users/" + id + "/federated-identity/google",
                Map.of("identityProvider", "google", "userId", googleId, "userName", email));
        String bearer = accessToken(json(gateway("POST", "/auth/todogi/login", null, Map.of("email", email, "password", PASSWORD)), 200));

        JsonNode identities = json(gateway("GET", "/auth/todogi/identities", bearer, null), 200);
        assertThat(identities.get("password").asBoolean()).isTrue();
        assertThat(identities.get("providers")).hasSize(1);
        assertThat(identities.get("providers").get(0).get("alias").asString()).isEqualTo("google");
        assertThat(identities.get("providers").get(0).get("email").asString()).isEqualTo(email);
        assertThat(json(gateway("GET", "/auth/identities", bearer, null), 200)).isEqualTo(identities); // default realm path

        assertThat(gateway("DELETE", "/auth/todogi/identities/google", bearer, null).statusCode()).isEqualTo(204);
        assertThat(json(gateway("GET", "/auth/todogi/identities", bearer, null), 200).get("providers")).isEmpty();
        assertThat(adminGetArray("/admin/realms/todogi/users/" + id + "/federated-identity")).isEmpty();
        assertThat(gateway("DELETE", "/auth/todogi/identities/google", bearer, null).statusCode()).isEqualTo(204); // idempotent

        // Google only: a user Keycloak creates on the first Google sign-in
        String onlyGoogle = newEmail();
        createUser("fakegoogle", onlyGoogle, true, GOOGLE_PASSWORD);
        JsonNode session = json(gateway("POST", "/auth/todogi/social", null, Map.of("code", googleCode(onlyGoogle).code(),
                "redirectUri", REDIRECT)), 200);
        String googleBearer = accessToken(session);
        JsonNode googleIdentities = json(gateway("GET", "/auth/todogi/identities", googleBearer, null), 200);
        assertThat(googleIdentities.get("password").asBoolean()).isFalse();
        assertThat(googleIdentities.get("providers").get(0).get("alias").asString()).isEqualTo("google");
        assertThat(googleIdentities.get("providers").get(0).get("email").asString()).isEqualTo(onlyGoogle);

        HttpResponse<String> last = gateway("DELETE", "/auth/todogi/identities/google", googleBearer, null);
        assertThat(errorCode(last, 409)).isEqualTo("last_method");
        assertThat(json(gateway("GET", "/auth/todogi/identities", googleBearer, null), 200).get("providers")).hasSize(1);
    }

    /**
     * Criterion 16: Can links a Google account that belongs to another account → 409 identity_in_use, Can's session
     * keeps working; a Google account with another address makes Keycloak create a user → it is deleted, 409
     * identity_mismatch.
     */
    @Test
    void linkingAnotherAccountsGoogleLeavesEverybodyAlone(CapturedOutput output) throws Exception {
        String canEmail = newEmail();
        String can = createUser("todogi", canEmail, true, PASSWORD);
        JsonNode canSession = json(gateway("POST", "/auth/todogi/login", null, Map.of("email", canEmail, "password", PASSWORD)), 200);
        String canBearer = accessToken(canSession);

        // Ayşe signed up with Google a moment ago and is still signed in
        String ayseEmail = newEmail();
        createUser("fakegoogle", ayseEmail, true, GOOGLE_PASSWORD);
        JsonNode ayseSession = json(gateway("POST", "/auth/todogi/social", null, Map.of("code", googleCode(ayseEmail).code(),
                "redirectUri", REDIRECT)), 200);
        String ayse = subject(ayseSession);

        HttpResponse<String> inUse = gateway("POST", "/auth/todogi/social", canBearer, Map.of("code", googleCode(ayseEmail).code(),
                "redirectUri", REDIRECT, "mode", "link"));
        assertThat(errorCode(inUse, 409)).isEqualTo("identity_in_use");
        assertThat(inUse.body()).doesNotContain("access_token");
        assertThat(adminGet("/admin/realms/todogi/users/" + ayse).get("id").asString()).isEqualTo(ayse); // not deleted
        assertThat(adminGetArray("/admin/realms/todogi/users/" + ayse + "/federated-identity")).hasSize(1);
        assertThat(adminGetArray("/admin/realms/todogi/users/" + ayse + "/sessions")).hasSize(1); // only her own

        // an older account with a password and Google linked
        String bertaEmail = newEmail();
        String berta = createUser("todogi", bertaEmail, true, PASSWORD);
        String bertaGoogle = createUser("fakegoogle", bertaEmail, true, GOOGLE_PASSWORD);
        adminPost("/admin/realms/todogi/users/" + berta + "/federated-identity/google",
                Map.of("identityProvider", "google", "userId", bertaGoogle, "userName", bertaEmail));
        assertThat(errorCode(gateway("POST", "/auth/todogi/social", canBearer, Map.of("code", googleCode(bertaEmail).code(),
                "redirectUri", REDIRECT, "mode", "link")), 409)).isEqualTo("identity_in_use");
        assertThat(adminGetArray("/admin/realms/todogi/users/" + berta + "/federated-identity")).hasSize(1);
        assertThat(adminGetArray("/admin/realms/todogi/users/" + berta + "/sessions")).isEmpty(); // the link's session ended

        // a Google address with no ToDoGi account: Keycloak creates one, the gateway deletes it
        String otherEmail = newEmail();
        createUser("fakegoogle", otherEmail, true, GOOGLE_PASSWORD);
        HttpResponse<String> mismatch = gateway("POST", "/auth/todogi/social", canBearer, Map.of("code",
                googleCode(otherEmail).code(), "redirectUri", REDIRECT, "mode", "link"));
        assertThat(errorCode(mismatch, 409)).isEqualTo("identity_mismatch");
        assertThat(adminGetArray("/admin/realms/todogi/users?exact=true&email=" + enc(otherEmail))).isEmpty();

        // Can is untouched: same session, no provider
        assertThat(json(gateway("GET", "/auth/todogi/me", canBearer, null), 200).get("email").asString()).isEqualTo(canEmail);
        assertThat(json(gateway("GET", "/auth/todogi/identities", canBearer, null), 200).get("providers")).isEmpty();
        JsonNode refreshed = json(gateway("POST", "/auth/todogi/refresh", null,
                Map.of("refreshToken", canSession.get("refresh_token").asString())), 200);
        assertThat(subject(refreshed)).isEqualTo(can);

        assertNoSecretsLogged(output, canBearer, canSession.get("refresh_token").asString(),
                ayseSession.get("access_token").asString(), canEmail, ayseEmail, otherEmail);
    }

    /** Linking the account's own address: same user, 200 with the new session; the provider confirms the address. */
    @Test
    void linkingTheAccountsOwnGoogle() throws Exception {
        String email = newEmail();
        String id = createUser("todogi", email, false, PASSWORD);
        createUser("fakegoogle", email, true, GOOGLE_PASSWORD);
        String bearer = accessToken(json(gateway("POST", "/auth/todogi/login", null, Map.of("email", email, "password", PASSWORD)), 200));

        JsonNode linked = json(gateway("POST", "/auth/todogi/social", bearer, Map.of("code", googleCode(email).code(),
                "redirectUri", REDIRECT, "mode", "link")), 200);
        assertThat(subject(linked)).isEqualTo(id);
        JsonNode identities = json(gateway("GET", "/auth/todogi/identities", bearer, null), 200);
        assertThat(identities.get("password").asBoolean()).isTrue();
        assertThat(identities.get("providers").get(0).get("alias").asString()).isEqualTo("google");
        assertThat(adminGet("/admin/realms/todogi/users/" + id).get("emailVerified").asBoolean()).isTrue();

        // from now on Google signs in to the same account
        JsonNode viaGoogle = json(gateway("POST", "/auth/todogi/social", null, Map.of("code", googleCode(email).code(),
                "redirectUri", REDIRECT)), 200);
        assertThat(subject(viaGoogle)).isEqualTo(id);
    }

    /**
     * Criterion 17: Google sign-in with the address of a password account whose email is not confirmed → 409
     * account_exists_unverified, no second user, no link left; with a confirmed address the same user signs in.
     * <p>
     * Observed Keycloak behavior (26.7.3, talay-identity social-first-login): Keycloak does not refuse — the automatic
     * link step links Google to the unconfirmed account and the browser comes back to the app with a code (no
     * {@code error=}). The gateway is what refuses, when the code is exchanged.
     */
    @Test
    void googleSignInIntoAnUnconfirmedAccount(CapturedOutput output) throws Exception {
        String email = newEmail();
        String id = createUser("todogi", email, false, PASSWORD);
        createUser("fakegoogle", email, true, GOOGLE_PASSWORD);

        BrokerResult result = googleCode(email);
        assertThat(result.error()).isNull();
        assertThat(result.code()).isNotBlank();
        // Keycloak has already linked Google to the unconfirmed account
        assertThat(adminGetArray("/admin/realms/todogi/users/" + id + "/federated-identity")).hasSize(1);

        HttpResponse<String> refused = gateway("POST", "/auth/todogi/social", null, Map.of("code", result.code(), "redirectUri", REDIRECT));
        assertThat(errorCode(refused, 409)).isEqualTo("account_exists_unverified");
        assertThat(JSON.readTree(refused.body()).get("error").get("email").asString()).isEqualTo(email);
        assertThat(refused.body()).doesNotContain("access_token");
        assertThat(adminGetArray("/admin/realms/todogi/users?exact=true&email=" + enc(email))).hasSize(1);
        assertThat(adminGetArray("/admin/realms/todogi/users/" + id + "/federated-identity")).isEmpty();
        assertThat(adminGetArray("/admin/realms/todogi/users/" + id + "/sessions")).isEmpty();
        assertThat(adminGet("/admin/realms/todogi/users/" + id).get("emailVerified").asBoolean()).isFalse();
        // the way out the app offers: password sign-in, then link from the profile
        assertThat(gateway("POST", "/auth/todogi/login", null, Map.of("email", email, "password", PASSWORD)).statusCode()).isEqualTo(200);

        // confirmed address: the existing user signs in with Google
        String confirmed = newEmail();
        String confirmedId = createUser("todogi", confirmed, true, PASSWORD);
        createUser("fakegoogle", confirmed, true, GOOGLE_PASSWORD);
        JsonNode session = json(gateway("POST", "/auth/todogi/social", null, Map.of("code", googleCode(confirmed).code(),
                "redirectUri", REDIRECT)), 200);
        assertThat(subject(session)).isEqualTo(confirmedId);
        assertThat(adminGetArray("/admin/realms/todogi/users?exact=true&email=" + enc(confirmed))).hasSize(1);

        assertNoSecretsLogged(output, session.get("access_token").asString(), session.get("refresh_token").asString(),
                email, confirmed, PASSWORD);
    }

    /** Realms without the flag answer as before; tokens of another realm are 403; unknown paths 404 (were 500). */
    @Test
    void otherRealmsAndPathsAreUnchanged() throws Exception {
        String email = newEmail();
        createUser("vitafinder", email, true, PASSWORD);
        String vitafinder = accessToken(json(gateway("POST", "/auth/vitafinder/login", null, Map.of("email", email, "password", PASSWORD)), 200));

        assertThat(errorCode(gateway("GET", "/auth/vitafinder/identities", vitafinder, null), 404)).isEqualTo("realm_feature_disabled");
        assertThat(errorCode(gateway("DELETE", "/auth/vitafinder/identities/google", vitafinder, null), 404)).isEqualTo("realm_feature_disabled");
        assertThat(errorCode(gateway("POST", "/auth/vitafinder/social", vitafinder, Map.of("code", "x", "redirectUri", REDIRECT,
                "mode", "link")), 404)).isEqualTo("realm_feature_disabled");
        // no mode / mode=login: the old answer to a code Keycloak rejects (401, no code field)
        for (Map<String, String> body : List.of(Map.of("code", "x", "redirectUri", REDIRECT),
                Map.of("code", "x", "redirectUri", REDIRECT, "mode", "login"))) {
            HttpResponse<String> response = gateway("POST", "/auth/vitafinder/social", null, body);
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(JSON.readTree(response.body()).get("error").has("code")).isFalse();
        }
        assertThat(gateway("GET", "/auth/todogi/identities", vitafinder, null).statusCode()).isEqualTo(403);
        assertThat(gateway("GET", "/auth/todogi/identities", null, null).statusCode()).isEqualTo(401);

        HttpResponse<String> unknown = gateway("GET", "/auth/vitafinder/nope", vitafinder, null);
        assertThat(errorCode(unknown, 404)).isEqualTo("not_found");
        assertThat(JSON.readTree(unknown.body()).get("success").asBoolean()).isFalse();
        assertThat(gateway("GET", "/auth/vitafinder/nope", null, null).statusCode()).isEqualTo(401); // still 401 first
        assertThat(gateway("GET", "/auth/vitafinder/me", vitafinder, null).statusCode()).isEqualTo(200);
    }

    /* ======================= the browser part of the Google sign-in ======================= */

    /** Where the code flow ended: the app's redirect with a {@code code} or an {@code error}. */
    record BrokerResult(String code, String error) {
    }

    /**
     * Opens the todogi authorization endpoint with {@code kc_idp_hint=google} in a fresh "browser" (own cookies), signs
     * in on fake Google's form and follows the redirects back to {@link #REDIRECT}.
     */
    private BrokerResult googleCode(String googleEmail) throws Exception {
        CookieJar cookies = new CookieJar();
        URI next = URI.create(keycloakUrl() + "/realms/todogi/protocol/openid-connect/auth?client_id=auth&response_type=code"
                + "&scope=" + enc("openid email profile") + "&redirect_uri=" + enc(REDIRECT) + "&kc_idp_hint=google"
                + "&state=" + UUID.randomUUID() + "&nonce=" + UUID.randomUUID());
        HttpRequest request = HttpRequest.newBuilder(next).GET().build();
        for (int hop = 0; hop < 25; hop++) {
            HttpResponse<String> response = HTTP.send(cookies.attach(request, next), HttpResponse.BodyHandlers.ofString());
            cookies.store(next, response);
            int status = response.statusCode();
            if (status >= 300 && status < 400) {
                String location = response.headers().firstValue("Location").orElseThrow();
                if (location.startsWith(REDIRECT)) {
                    Map<String, String> query = query(URI.create(location).getRawQuery());
                    return new BrokerResult(query.get("code"), query.get("error"));
                }
                next = next.resolve(location);
                request = HttpRequest.newBuilder(next).GET().build();
                continue;
            }
            Matcher form = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"").matcher(response.body());
            if (status == 200 && form.find()) {
                next = URI.create(form.group(1).replace("&amp;", "&"));
                request = HttpRequest.newBuilder(next)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("username", googleEmail,
                                "password", GOOGLE_PASSWORD, "credentialId", ""))))
                        .build();
                continue;
            }
            Matcher title = Pattern.compile("<title>([^<]*)</title>").matcher(response.body());
            throw new AssertionError("Sign-in stopped on " + next.getPath() + " with HTTP " + status + ": "
                    + (title.find() ? title.group(1) : response.body().substring(0, Math.min(300, response.body().length()))));
        }
        throw new AssertionError("Too many redirects");
    }

    /** Minimal cookie store: Keycloak's cookies are path scoped and over plain HTTP here (no Secure handling). */
    private static final class CookieJar {
        private final Map<String, String[]> cookies = new LinkedHashMap<>(); // name|path -> [name, value, path]

        HttpRequest attach(HttpRequest request, URI uri) {
            String header = cookies.values().stream()
                    .filter(c -> uri.getPath().startsWith(c[2]))
                    .map(c -> c[0] + "=" + c[1])
                    .collect(Collectors.joining("; "));
            if (header.isEmpty()) {
                return request;
            }
            HttpRequest.Builder copy = HttpRequest.newBuilder(request.uri()).method(request.method(),
                    request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
            request.headers().map().forEach((name, values) -> values.forEach(v -> copy.header(name, v)));
            return copy.header("Cookie", header).build();
        }

        void store(URI uri, HttpResponse<?> response) {
            for (String setCookie : response.headers().allValues("Set-Cookie")) {
                String[] parts = setCookie.split(";");
                int eq = parts[0].indexOf('=');
                String name = parts[0].substring(0, eq).trim();
                String value = parts[0].substring(eq + 1).trim();
                String path = "/";
                boolean expired = value.isEmpty();
                for (int i = 1; i < parts.length; i++) {
                    String attribute = parts[i].trim();
                    String lower = attribute.toLowerCase();
                    if (lower.startsWith("path=")) {
                        path = attribute.substring(5);
                    } else if (lower.equals("max-age=0")) {
                        expired = true;
                    }
                }
                if (expired) {
                    cookies.remove(name + "|" + path);
                } else {
                    cookies.put(name + "|" + path, new String[]{name, value, path});
                }
            }
        }
    }

    /* ======================= Keycloak set-up ======================= */

    /** realm todogi: the talay-identity first broker login flow and fake Google as the {@code google} provider. */
    private static void configureBroker() throws Exception {
        adminPost("/admin/realms/todogi/authentication/flows", Map.of("alias", "social-first-login",
                "description", "talay-identity social-first-login", "providerId", "basic-flow", "topLevel", true, "builtIn", false));
        for (String authenticator : List.of("idp-create-user-if-unique", "idp-auto-link")) {
            adminPost("/admin/realms/todogi/authentication/flows/social-first-login/executions/execution",
                    Map.of("provider", authenticator));
        }
        for (JsonNode execution : adminGetArray("/admin/realms/todogi/authentication/flows/social-first-login/executions")) {
            Map<String, Object> update = JSON.convertValue(execution, Map.class);
            update.put("requirement", "ALTERNATIVE");
            adminPut("/admin/realms/todogi/authentication/flows/social-first-login/executions", update);
        }
        String browserFacing = keycloakUrl() + "/realms/fakegoogle/protocol/openid-connect";
        String insideContainer = "http://localhost:8080/realms/fakegoogle/protocol/openid-connect";
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", "todogi-broker");
        config.put("clientSecret", "it-broker-secret");
        config.put("clientAuthMethod", "client_secret_post");
        config.put("authorizationUrl", browserFacing + "/auth");
        config.put("tokenUrl", insideContainer + "/token");
        config.put("defaultScope", "openid email profile");
        config.put("validateSignature", "false");
        config.put("syncMode", "IMPORT");
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("alias", "google");
        provider.put("displayName", "Google");
        provider.put("providerId", "oidc");
        provider.put("enabled", true);
        provider.put("trustEmail", true);
        provider.put("storeToken", false);
        provider.put("hideOnLogin", true);
        provider.put("firstBrokerLoginFlowAlias", "social-first-login");
        provider.put("config", config);
        adminPost("/admin/realms/todogi/identity-provider/instances", provider);
    }

    /* ======================= helpers ======================= */

    private static String keycloakUrl() {
        return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
    }

    private static String newEmail() {
        return "it-" + UUID.randomUUID().toString().substring(0, 8) + "@ornek.test";
    }

    /** @return the new user's id */
    private static String createUser(String realm, String email, boolean verified, String password) throws Exception {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", email);
        user.put("email", email);
        user.put("firstName", "Test");
        user.put("lastName", "Kişi");
        user.put("enabled", true);
        user.put("emailVerified", verified);
        user.put("credentials", List.of(Map.of("type", "password", "value", password, "temporary", false)));
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/admin/realms/" + realm + "/users"))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(user))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(201);
        String location = response.headers().firstValue("Location").orElseThrow();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private HttpResponse<String> gateway(String method, String path, String bearer, Map<String, ?> body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String masterToken() throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("grant_type", "password", "client_id", "admin-cli",
                        "username", "admin", "password", "admin")))).build(), HttpResponse.BodyHandlers.ofString());
        return JSON.readTree(response.body()).get("access_token").asString();
    }

    private static JsonNode adminGet(String path) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private static List<JsonNode> adminGetArray(String path) throws Exception {
        List<JsonNode> items = new ArrayList<>();
        adminGet(path).forEach(items::add);
        return items;
    }

    private static void adminPost(String path, Map<String, ?> body) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(path + ": " + response.body()).isBetween(200, 204);
    }

    private static void adminPut(String path, Map<String, ?> body) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(path + ": " + response.body()).isBetween(200, 204);
    }

    private static String formBody(Map<String, String> form) {
        return form.entrySet().stream().map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));
    }

    private static Map<String, String> query(String rawQuery) {
        Map<String, String> values = new LinkedHashMap<>();
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&")) {
                int eq = pair.indexOf('=');
                values.put(URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8),
                        eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static JsonNode json(HttpResponse<String> response, int expectedStatus) {
        assertThat(response.statusCode()).as(response.body()).isEqualTo(expectedStatus);
        return JSON.readTree(response.body());
    }

    private static String errorCode(HttpResponse<String> response, int expectedStatus) {
        JsonNode error = json(response, expectedStatus).get("error");
        return error.has("code") ? error.get("code").asString() : null;
    }

    private static String accessToken(JsonNode session) {
        return session.get("access_token").asString();
    }

    private static String subject(JsonNode session) {
        return JSON.readTree(Base64.getUrlDecoder().decode(accessToken(session).split("\\.")[1])).get("sub").asString();
    }

    /** Tokens and full addresses never reach the gateway's logs. */
    private static void assertNoSecretsLogged(CapturedOutput output, String... secrets) {
        String logs = output.getAll();
        for (String secret : secrets) {
            assertThat(logs).as("logs must not contain a secret").doesNotContain(secret);
        }
    }
}
