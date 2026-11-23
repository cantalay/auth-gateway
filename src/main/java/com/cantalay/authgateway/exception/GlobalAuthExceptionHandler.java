package com.cantalay.authgateway.exception;


import com.cantalay.authgateway.common.ApiResponse;
import com.cantalay.authgateway.common.ErrorDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalAuthExceptionHandler {

    @ExceptionHandler(BaseAuthException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthException(
            BaseAuthException ex,
            HttpServletRequest request) {

        log.warn("Auth exception occurred: {} - Status: {}", ex.getMessage(), ex.getStatus());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .timestamp(LocalDateTime.now())
                .status(ex.getStatus().value())
                .error(ex.getStatus().getReasonPhrase())
                .message(ex.getMessage())
                .code(ex.getCode())
                .path(request.getRequestURI())
                .validationErrors(ex.getDetails())
                .email(ex.getEmail())
                .build();

        return ResponseEntity
                .status(ex.getStatus())
                .body(ApiResponse.error(errorDetails));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        Map<String, String> validationErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            validationErrors.put(fieldName, errorMessage);
        });

        log.warn("Validation failed: {}", validationErrors);

        ErrorDetails errorDetails = ErrorDetails.builder()
                .timestamp(LocalDateTime.now())
                .status(400)
                .error("Bad Request")
                .message("Validation failed")
                .path(request.getRequestURI())
                .validationErrors(validationErrors)
                .build();

        return ResponseEntity
                .status(400)
                .body(ApiResponse.error(errorDetails));
    }

    /** Missing or malformed JSON body: a client error, not a 500. */
    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnreadableBody(
            org.springframework.http.converter.HttpMessageNotReadableException ex,
            HttpServletRequest request) {

        log.warn("Unreadable request body on {}", request.getRequestURI());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .timestamp(LocalDateTime.now())
                .status(400)
                .error("Bad Request")
                .message("Malformed request body")
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(400)
                .body(ApiResponse.error(errorDetails));
    }

    /**
     * Unknown path: 404 in the usual error body. Spring Boot hands paths without a controller to the static resource
     * handler ({@code NoResourceFoundException}); without it ({@code NoHandlerFoundException}) the outcome is the same.
     */
    @ExceptionHandler({org.springframework.web.servlet.resource.NoResourceFoundException.class,
            org.springframework.web.servlet.NoHandlerFoundException.class})
    public ResponseEntity<ApiResponse<Void>> handleUnknownPath(
            Exception ex,
            HttpServletRequest request) {

        log.info("No endpoint for {} {}", request.getMethod(), request.getRequestURI());

        ErrorDetails errorDetails = ErrorDetails.builder()
                .timestamp(LocalDateTime.now())
                .status(404)
                .error("Not Found")
                .message(AuthError.NOT_FOUND.message())
                .code(AuthError.NOT_FOUND.code())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(404)
                .body(ApiResponse.error(errorDetails));
    }

    // (opsiyonel ama önerilir)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleUnexpected(
            Exception ex,
            HttpServletRequest request) {

        log.error("Unexpected error occurred: {}", ex.getMessage(), ex);

        ErrorDetails errorDetails = ErrorDetails.builder()
                .timestamp(LocalDateTime.now())
                .status(500)
                .error("Internal Server Error")
                .message("Unexpected authentication error.")
                .path(request.getRequestURI())
                .build();

        return ResponseEntity
                .status(500)
                .body(ApiResponse.error(errorDetails));
    }
}
