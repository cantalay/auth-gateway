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
    public static final Error SESSIONS_REVOKE_FAILED =
            new Error(HttpStatus.SERVICE_UNAVAILABLE,
                    "Password changed, but other sessions could not be signed out. Request a new reset link to try again.",
                    "sessions_revoke_failed");
    public static final Error RATE_LIMITED =
            new Error(HttpStatus.TOO_MANY_REQUESTS, "Too many requests. Try again later.", "rate_limited");
    public static final Error LAST_METHOD =
            new Error(HttpStatus.CONFLICT, "This is the account's only sign-in method.", "last_method");
    public static final Error IDENTITY_IN_USE =
            new Error(HttpStatus.CONFLICT, "This provider account belongs to another account.", "identity_in_use");
    public static final Error IDENTITY_MISMATCH =
            new Error(HttpStatus.CONFLICT, "This provider account could not be linked to the signed-in account.",
                    "identity_mismatch");
    public static final Error ACCOUNT_EXISTS_UNVERIFIED =
            new Error(HttpStatus.CONFLICT,
                    "An account with this email exists but its email is not confirmed. Sign in with its password, or reset "
                            + "the password to prove the address; then the provider can be used.",
                    "account_exists_unverified");
    public static final Error ACCOUNT_EXISTS =
            new Error(HttpStatus.CONFLICT,
                    "An account with this email exists and this provider account cannot be linked to it. Sign in with its password.",
                    "account_exists");
    public static final Error IDENTITY_UNPROVEN =
            new Error(HttpStatus.CONFLICT,
                    "The provider sign-in could not be confirmed for linking. Start the provider sign-in again.",
                    "identity_unproven");
    public static final Error SOCIAL_CANCELLED =
            new Error(HttpStatus.BAD_REQUEST, "The provider sign-in was cancelled.", "social_cancelled");
    public static final Error SOCIAL_FAILED =
            new Error(HttpStatus.BAD_REQUEST, "The provider sign-in did not complete.", "social_failed");
    public static final Error PROVIDER_REQUIRED =
            new Error(HttpStatus.BAD_REQUEST, "provider is required to link an identity provider.", "invalid_provider");
    public static final Error SOCIAL_MODE_INVALID =
            new Error(HttpStatus.BAD_REQUEST, "mode must be 'login' or 'link'.", "invalid_mode");
    public static final Error NOT_FOUND =
            new Error(HttpStatus.NOT_FOUND, "No endpoint at this path.", "not_found");
    public static final Error METHOD_NOT_ALLOWED =
            new Error(HttpStatus.METHOD_NOT_ALLOWED, "This method is not allowed at this path.", "method_not_allowed");

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

