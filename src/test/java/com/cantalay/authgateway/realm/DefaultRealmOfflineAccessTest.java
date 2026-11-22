package com.cantalay.authgateway.realm;

import com.cantalay.authgateway.service.AuthService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultRealmOfflineAccessTest {

    @Test
    void defaultRealmAsksForOfflineTokensOnlyWhenEnabled() {
        RealmRegistry on = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                true, new GatewayProperties());
        RealmRegistry off = new RealmRegistry("https://auth.cantalay.com", "todogi", "auth", "auth-gateway-admin", "s", "",
                new GatewayProperties());

        assertThat(AuthService.loginScope(on.resolve(null))).isEqualTo("openid profile email offline_access");
        assertThat(on.resolve("todogi").offlineAccess()).isTrue();
        assertThat(on.resolve(null).clientId()).isEqualTo("auth");
        assertThat(AuthService.loginScope(off.resolve(null))).isEqualTo("openid profile email");
    }
}
