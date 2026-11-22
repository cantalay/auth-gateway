package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.NotBlank;

/** Body of the endpoints that consume an emailed link ({@code token} is masked in request logs). */
public record ActionTokenRequest(
        @NotBlank String token
) {
}
