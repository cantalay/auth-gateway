package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Game Center / Play Games sign-in or account link.
 *
 * @param platform {@code gamecenter} or {@code playgames}
 * @param token    Game Center identity verification payload (JSON or base64url) or Play Games server auth code
 */
public record PlatformLoginRequest(
        @NotBlank @Pattern(regexp = "gamecenter|playgames") String platform,
        @NotBlank @Size(max = 16384) String token
) {
}
