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
            new Error(HttpStatus.SERVICE_UNAVAILABLE, "User email validation required.");

    /* =======================
       INNER TYPE
       ======================= */
    public record Error(HttpStatus status, String message) {
    }
}

