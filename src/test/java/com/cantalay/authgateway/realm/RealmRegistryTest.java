package com.cantalay.authgateway.realm;

import com.cantalay.authgateway.exception.BaseAuthException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.http.HttpStatus;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RealmRegistryTest {

    private static GatewayProperties bindFromEnv(Map<String, Object> env) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, env));
        return new Binder(ConfigurationPropertySources.get(environment))
                .bind("gateway", GatewayProperties.class)
                .orElseGet(GatewayProperties::new);
    }

    private static RealmRegistry registry(GatewayProperties properties) {
        return new RealmRegistry("https://auth.cantalay.com/", "todogi", "auth",
                "auth-gateway-admin", "legacy-secret", "", properties);
    }

    @Test
    void keepsLegacyDefaultRealm() {
        RealmRegistry registry = registry(new GatewayProperties());

        RealmConfig todogi = registry.resolve(null);
        assertThat(todogi.name()).isEqualTo("todogi");
        assertThat(todogi.clientId()).isEqualTo("auth");
        assertThat(todogi.adminClientId()).isEqualTo("auth-gateway-admin");
        assertThat(todogi.issuerUri()).isEqualTo("https://auth.cantalay.com/realms/todogi");
        assertThat(registry.resolve("todogi")).isEqualTo(todogi);
    }

    @Test
    void bindsAdditionalRealmsFromEnvironmentWithConventionalDefaults() {
        GatewayProperties properties = bindFromEnv(Map.of(
                "GATEWAY_REALMS_HELLO_ADMINCLIENTSECRET", "hello-secret",
                "GATEWAY_REALMS_VITAFINDER_ADMINCLIENTSECRET", "vf-secret",
                "GATEWAY_REALMS_VITAFINDER_CLIENTID", "vitafinder-login"
        ));
        RealmRegistry registry = registry(properties);

        RealmConfig hello = registry.resolve("hello");
        assertThat(hello.clientId()).isEqualTo("hello-gateway");
        assertThat(hello.adminClientId()).isEqualTo("hello-gateway-admin");
        assertThat(hello.adminClientSecret()).isEqualTo("hello-secret");
        assertThat(hello.issuerUri()).isEqualTo("https://auth.cantalay.com/realms/hello");
        assertThat(registry.resolve("vitafinder").clientId()).isEqualTo("vitafinder-login");
        assertThat(registry.byIssuer("https://auth.cantalay.com/realms/hello")).contains(hello);
        assertThat(registry.all()).hasSize(3);
    }

    @Test
    void rejectsUnknownRealm() {
        RealmRegistry registry = registry(new GatewayProperties());

        assertThatThrownBy(() -> registry.resolve("master"))
                .isInstanceOf(BaseAuthException.class)
                .satisfies(e -> assertThat(((BaseAuthException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    @Test
    void requiresAdminSecretForAdditionalRealms() {
        GatewayProperties properties = bindFromEnv(Map.of("GATEWAY_REALMS_HELLO_CLIENTID", "hello-gateway"));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("hello");
    }

    @Test
    void secretIsNotPrinted() {
        RealmConfig realm = new RealmConfig("hello", "hello-gateway", "hello-gateway-admin", "s3cr3t", "iss");
        assertThat(realm.toString()).doesNotContain("s3cr3t");
    }
}
