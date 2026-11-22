package com.cantalay.authgateway.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorDetails {
    
    private LocalDateTime timestamp;
    private Integer status;
    private String error;
    private String message;
    /** Machine-readable code ({@code reset_token_invalid}, {@code password_policy}, ...); absent for older errors. */
    private String code;
    private String path;
    private Map<String, String> validationErrors;
    
}

