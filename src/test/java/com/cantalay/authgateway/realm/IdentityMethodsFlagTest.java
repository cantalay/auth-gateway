package com.cantalay.authgateway.realm;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The identity methods switch is off unless a realm turns it on: GATEWAY_REALMS_<R>_IDENTITYMETHODS / KEYCLOAK_IDENTITY_METHODS. */
class IdentityMethodsFlagTest {

    @Test
    void realmsTurnTheSwitchOnOneByOne() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, Map.of(
                "GATEWAY_REALMS_HELLO_ADMINCLIENTSECRET", "h",
                "GATEWAY_REALMS_HELLO_IDENTITYMETHODS", "true",
                "GATEWAY_REALMS_CONQUEST_ADMINCLIENTSECRET", "c",
                "GATEWAY_REALMS_CONQUEST_PLATFORMLOGIN", "true")));
        GatewayProperties properties = Binder.get(environment).bind("gateway", GatewayProperties.class).get();

        RealmRegistry registry = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                true, properties);
        assertThat(registry.resolve("hello").identityMethods()).isTrue();
        assertThat(registry.resolve("conquest").identityMethods()).isFalse();
        assertThat(registry.resolve("conquest").platformClientId()).isEqualTo("conquest-platform");
        assertThat(registry.resolve(null).identityMethods()).isFalse();
        assertThat(registry.resolve(null).offlineAccess()).isTrue();

        RealmRegistry on = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                false, true, new GatewayProperties());
        assertThat(on.resolve("todogi").identityMethods()).isTrue();
        assertThat(on.resolve("todogi").offlineAccess()).isFalse();
        assertThat(new RealmConfig("x", "c", "a", "s", "iss").identityMethods()).isFalse();
        assertThat(new RealmConfig("x", "c", "a", "s", "iss", true, "x-platform").identityMethods()).isFalse();
    }
}
