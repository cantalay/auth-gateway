package com.cantalay.authgateway.exception;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;

@AllArgsConstructor

public final class AuthError {

    public static final Error INVALID_CREDENTIALS =
            new Error(HttpStatus.UNAUTHORIZED, "Invalid email or password.");
    public static final Error CURRENT_PASSWORD_INVALID =
            new Error(HttpStatus.BAD_REQUEST, "Current password is incorrect.");
    public static final Error USER_ALREADY_EXISTS =
            new Error(HttpStatus.CONFLICT, "User already exists.");
    public static final Error PASSWORD_POLICY_VIOLATION =
            new Error(HttpStatus.BAD_REQUEST, "Password does not meet security requirements.", "password_policy");
    public static final Error FORBIDDEN_OPERATION =
            new Error(HttpStatus.FORBIDDEN, "Operation not permitted.");
    public static final Error TOKEN_INVALID_OR_EXPIRED =
            new Error(HttpStatus.UNAUTHORIZED, "Invalid or expired token.");
    public static final Error AUTH_SERVICE_UNAVAILABLE =
            new Error(HttpStatus.SERVICE_UNAVAILABLE, "Authentication service unavailable.");
    public static final Error AUTH_DISABLED_ACCOUNT =
            new Error(HttpStatus.FORBIDDEN, "User email validation required.");
    public static final Error REALM_NOT_FOUND =
            new Error(HttpStatus.NOT_FOUND, "Unknown realm.");
    public static final Error REALM_MISMATCH =
            new Error(HttpStatus.FORBIDDEN, "Token does not belong to this realm.");
    public static final Error REGISTRATION_REJECTED =
            new Error(HttpStatus.BAD_REQUEST, "Registration data was rejected.");
    public static final Error PLATFORM_LOGIN_DISABLED =
            new Error(HttpStatus.NOT_FOUND, "Platform sign-in is not enabled for this realm.");
    public static final Error PLATFORM_TOKEN_INVALID =
            new Error(HttpStatus.UNAUTHORIZED, "Platform identity could not be verified.");
    public static final Error PLATFORM_ALREADY_LINKED =
            new Error(HttpStatus.CONFLICT, "This platform identity is linked to another account.");
    public static final Error REALM_FEATURE_DISABLED =
            new Error(HttpStatus.NOT_FOUND, "This feature is not enabled for this realm.", "realm_feature_disabled");
    public static final Error RESET_TOKEN_INVALID =
            new Error(HttpStatus.GONE, "This password reset link is invalid or has expired.", "reset_token_invalid");
    public static final Error VERIFY_TOKEN_INVALID =
            new Error(HttpStatus.GONE, "This email confirmation link is invalid or has expired.", "verify_token_invalid");
    public static final Error RATE_LIMITED =
            new Error(HttpStatus.TOO_MANY_REQUESTS, "Too many requests. Try again later.", "rate_limited");

    /* =======================
       INNER TYPE
       ======================= */
    /**
     * @param code machine-readable error code for client translations ({@code snake_case}); {@code null} for errors
     *             that predate codes (the response then has no {@code code} field, as before)
     */
    public record Error(HttpStatus status, String message, String code) {
        public Error(HttpStatus status, String message) {
            this(status, message, null);
        }
    }
}

