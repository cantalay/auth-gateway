package com.cantalay.authgateway.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@FeignClient(
        name = "keycloak-admin",
        url = "${keycloak.base-url}"
)
public interface KeycloakAdminClient {

    @PostMapping(
            value = "/admin/realms/{realm}/users",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    void createUser(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorization,
            @RequestBody Map<String, Object> payload
    );

    @GetMapping(
            value = "/admin/realms/{realm}/users",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    List<Map<String, Object>> getUsersByEmail(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorization,
            @RequestParam("email") String email,
            @RequestParam("exact") boolean exact
    );

    @PutMapping(
            value = "/admin/realms/{realm}/users/{userId}/send-verify-email"
    )
    void sendVerificationEmail(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    @PutMapping(
            value = "/admin/realms/{realm}/users/{userId}",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    void updateUser(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization,
            @RequestBody Map<String, Object> payload
    );

    @PutMapping(
            value = "/admin/realms/{realm}/users/{userId}/reset-password",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    void resetPassword(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization,
            @RequestBody Map<String, Object> payload
    );
}
