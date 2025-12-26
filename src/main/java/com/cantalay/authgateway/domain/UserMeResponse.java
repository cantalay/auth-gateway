package com.cantalay.authgateway.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public record UserMeResponse(

        @JsonProperty("sub")
        String id,

        @JsonProperty("email")
        String email,

        @JsonProperty("given_name")
        String firstName,

        @JsonProperty("family_name")
        String lastName

) {
}
