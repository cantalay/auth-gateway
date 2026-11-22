package com.cantalay.authgateway.exception;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class BaseAuthException extends RuntimeException {

    private final HttpStatus status;
    private final String code;
    private final Map<String, String> details;

    public BaseAuthException(AuthError.Error error) {
        this(error, null);
    }

    /** @param details optional field-level details (rendered as {@code validationErrors}) */
    public BaseAuthException(AuthError.Error error, Map<String, String> details) {
        super(error.message());
        this.status = error.status();
        this.code = error.code();
        this.details = details;
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
}
