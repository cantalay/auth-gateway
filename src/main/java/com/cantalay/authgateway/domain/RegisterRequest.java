package com.cantalay.authgateway.domain;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(

        @Email
        @NotBlank
        String email,

        @NotBlank
        @Size(min = 8)
        String password,

        @NotBlank
        String firstName,

        @NotBlank
        String lastName,

        /* Optional email language (tr, en); stored as the user's locale where the realm's gateway emails support it. */
        @Size(max = 16)
        String locale
) {
    public RegisterRequest(String email, String password, String firstName, String lastName) {
        this(email, password, firstName, lastName, null);
    }
}
