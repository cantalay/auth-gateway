package com.cantalay.authgateway.exception;

import org.springframework.http.HttpStatus;

public class BaseAuthException extends RuntimeException {

    private final HttpStatus status;

    public BaseAuthException(AuthError.Error error) {
        super(error.message());
        this.status = error.status();
    }

    public HttpStatus getStatus() {
        return status;
    }
}
