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
            new Error(HttpStatus.BAD_REQUEST, "Password does not meet security requirements.");
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

    /* =======================
       INNER TYPE
       ======================= */
    public record Error(HttpStatus status, String message) {
    }
}

