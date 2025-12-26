package com.cantalay.authgateway.exception;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class GlobalAuthExceptionHandler {

    @ExceptionHandler(BaseAuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(
            BaseAuthException ex) {

        return ResponseEntity
                .status(ex.getStatus())
                .body(Map.of(
                        "timestamp", Instant.now(),
                        "status", ex.getStatus().value(),
                        "error", ex.getStatus().getReasonPhrase(),
                        "message", ex.getMessage()
                ));
    }

    // (opsiyonel ama önerilir)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {

        return ResponseEntity
                .status(500)
                .body(Map.of(
                        "timestamp", Instant.now(),
                        "status", 500,
                        "error", "Internal Server Error",
                        "message", "Unexpected authentication error."
                ));
    }
}
