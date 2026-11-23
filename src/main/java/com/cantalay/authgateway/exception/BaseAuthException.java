package com.cantalay.authgateway.exception;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class BaseAuthException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final Map<String, String> details;
    private final String email;

    public BaseAuthException(AuthError.Error error) {
        this(error, null);
    }

    /** @param details optional field-level details (rendered as {@code validationErrors}) */
    public BaseAuthException(AuthError.Error error, Map<String, String> details) {
        this(error, details, null);
    }

    /** @param email optional address the client shows (rendered as {@code email}, e.g. {@code account_exists_unverified}) */
    public BaseAuthException(AuthError.Error error, Map<String, String> details, String email) {
        super(error.message());
        this.status = error.status();
        this.code = error.code();
        this.details = details;
        this.email = email;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public Map<String, String> getDetails() {
        return details;
    }

    public String getEmail() {
        return email;
    }
}
