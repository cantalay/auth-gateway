package com.cantalay.authgateway.service;

import com.cantalay.authgateway.client.KeycloakAdminClient;
import com.cantalay.authgateway.client.KeycloakClient;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.ResendVerificationRequest;
import com.cantalay.authgateway.mail.MailProperties;
import com.cantalay.authgateway.mail.WelcomeMailService;
import com.cantalay.authgateway.realm.RealmConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthServiceVerificationTest {

    private final AuthAdminService adminService = mock(AuthAdminService.class);
    private final KeycloakAdminClient admin = mock(KeycloakAdminClient.class);
    private final MailProperties mailProperties = new MailProperties();
    private final AuthService service = new AuthService(adminService, mock(KeycloakClient.class), admin,
            mock(WelcomeMailService.class), mailProperties);
    private final RealmConfig realm = new RealmConfig("vitafinder", "vitafinder-gateway", "vitafinder-gateway-admin", "s", "iss");

    private static KeycloakUserDto user(String id, boolean verified) {
        return new KeycloakUserDto(id, "a@b.co", "a@b.co", "A", "B", true, verified, 0L, null);
    }

    @Test
    void resendsForUnverifiedUserWithAppRedirect() {
        MailProperties.Realm mail = new MailProperties.Realm();
        mail.setVerifyClientId("vitafinder-storefront");
        mail.setVerifyRedirectUri("https://vitafinder.cantalay.com/");
        mailProperties.getRealms().put("vitafinder", mail);
        when(adminService.getAdminAccessToken(realm)).thenReturn("t");
        when(admin.getUsersByEmail("vitafinder", "Bearer t", "a@b.co", true)).thenReturn(List.of(user("u1", false)));

        service.resendVerification(realm, new ResendVerificationRequest("a@b.co"));

        verify(admin).sendVerificationEmail("vitafinder", "u1", "Bearer t", "vitafinder-storefront", "https://vitafinder.cantalay.com/");
    }

    @Test
    void doesNothingForVerifiedOrUnknownUsers() {
        when(adminService.getAdminAccessToken(realm)).thenReturn("t");
        when(admin.getUsersByEmail(anyString(), anyString(), eq("verified@b.co"), eq(true))).thenReturn(List.of(user("u2", true)));
        when(admin.getUsersByEmail(anyString(), anyString(), eq("unknown@b.co"), eq(true))).thenReturn(List.of());

        service.resendVerification(realm, new ResendVerificationRequest("verified@b.co"));
        service.resendVerification(realm, new ResendVerificationRequest("unknown@b.co"));

        verify(admin, never()).sendVerificationEmail(any(), any(), any(), any(), any());
    }
}
