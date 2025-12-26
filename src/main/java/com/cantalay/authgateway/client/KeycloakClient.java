package com.cantalay.authgateway.client;

import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.domain.UserMeResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@FeignClient(
        name = "keycloak-auth",
        url = "${keycloak.base-url}"
)
public interface KeycloakClient {

    @PostMapping(
            value = "/realms/{realm}/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    TokenResponseDto token(
            @PathVariable String realm,
            @RequestBody MultiValueMap<String, String> form
    );

    @PostMapping(
            value = "/realms/{realm}/protocol/openid-connect/logout",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    void logout(
            @PathVariable String realm,
            @RequestBody MultiValueMap<String, String> form
    );

    @GetMapping(
            value = "/realms/{realm}/protocol/openid-connect/userinfo"
    )
    UserMeResponse userInfo(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorization
    );
}

