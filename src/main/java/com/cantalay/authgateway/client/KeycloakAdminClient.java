package com.cantalay.authgateway.client;

import com.cantalay.authgateway.domain.KeycloakCredentialDto;
import com.cantalay.authgateway.domain.KeycloakFederatedIdentityDto;
import com.cantalay.authgateway.domain.KeycloakUserDto;
import com.cantalay.authgateway.domain.KeycloakUserSessionDto;
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
    List<KeycloakUserDto> getUsersByEmail(
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
            @RequestHeader("Authorization") String authorization,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri
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

    @DeleteMapping(
            value = "/admin/realms/{realm}/users/{userId}"
    )
    void deleteUser(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    @GetMapping(
            value = "/admin/realms/{realm}/users/{userId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    KeycloakUserDto getUser(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    @GetMapping(
            value = "/admin/realms/{realm}/users/{userId}/credentials",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    List<KeycloakCredentialDto> getCredentials(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    @GetMapping(
            value = "/admin/realms/{realm}/users/{userId}/federated-identity",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    List<KeycloakFederatedIdentityDto> getFederatedIdentities(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    /** Removes the link between the user and an identity provider account (Google, Apple, ...). */
    @DeleteMapping(
            value = "/admin/realms/{realm}/users/{userId}/federated-identity/{provider}"
    )
    void removeFederatedIdentity(
            @PathVariable String realm,
            @PathVariable String userId,
            @PathVariable String provider,
            @RequestHeader("Authorization") String authorization
    );

    /** Online sessions of the user. */
    @GetMapping(
            value = "/admin/realms/{realm}/users/{userId}/sessions",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    List<KeycloakUserSessionDto> getUserSessions(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    /** Ends every session of the user (refresh and offline tokens stop working). */
    @PostMapping(
            value = "/admin/realms/{realm}/users/{userId}/logout"
    )
    void logoutUser(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    /** Clears the brute-force lockout of the user. */
    @DeleteMapping(
            value = "/admin/realms/{realm}/attack-detection/brute-force/users/{userId}"
    )
    void clearBruteForce(
            @PathVariable String realm,
            @PathVariable String userId,
            @RequestHeader("Authorization") String authorization
    );

    /** Revokes the user's consent and offline tokens for a client (offline sessions survive {@link #logoutUser}). */
    @DeleteMapping(
            value = "/admin/realms/{realm}/users/{userId}/consents/{clientId}"
    )
    void revokeConsent(
            @PathVariable String realm,
            @PathVariable String userId,
            @PathVariable String clientId,
            @RequestHeader("Authorization") String authorization
    );
}
