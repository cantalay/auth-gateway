package com.cantalay.authgateway.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final int MAX_PAYLOAD_LENGTH = 1000;
    private static final String[] SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"};
    private static final String[] SENSITIVE_FIELDS = {"password", "token", "secret", "apiKey"};

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Generate unique request ID
        String requestId = UUID.randomUUID().toString().substring(0, 8);
        
        // Wrap request and response to cache content
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request, MAX_PAYLOAD_LENGTH);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        long startTime = System.currentTimeMillis();

        try {
            // Log request
            logRequest(wrappedRequest, requestId);
            
            // Process request
            filterChain.doFilter(wrappedRequest, wrappedResponse);
            
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            
            // Log response
            logResponse(wrappedRequest, wrappedResponse, duration, requestId);
            
            // Copy cached response content to actual response
            wrappedResponse.copyBodyToResponse();
        }
    }

    private void logRequest(ContentCachingRequestWrapper request, String requestId) {
        StringBuilder logMessage = new StringBuilder();
        
        logMessage.append("\n========== REQUEST [").append(requestId).append("] ==========\n");
        logMessage.append("Method: ").append(request.getMethod()).append("\n");
        logMessage.append("URI: ").append(request.getRequestURI()).append("\n");
        
        // Query parameters
        String queryString = request.getQueryString();
        if (queryString != null) {
            logMessage.append("Query: ").append(queryString).append("\n");
        }
        
        // Headers
        logMessage.append("Headers: ").append(getHeaders(request)).append("\n");
        
        // Client info
        logMessage.append("Remote Address: ").append(request.getRemoteAddr()).append("\n");
        
        // Request body (if applicable)
        String payload = getRequestPayload(request);
        if (payload != null && !payload.isEmpty()) {
            logMessage.append("Body: ").append(maskSensitiveData(payload)).append("\n");
        }
        
        log.info(logMessage.toString());
    }

    private void logResponse(
            ContentCachingRequestWrapper request,
            ContentCachingResponseWrapper response,
            long duration,
            String requestId) {
        
        StringBuilder logMessage = new StringBuilder();
        
        logMessage.append("\n========== RESPONSE [").append(requestId).append("] ==========\n");
        logMessage.append("Method: ").append(request.getMethod()).append("\n");
        logMessage.append("URI: ").append(request.getRequestURI()).append("\n");
        logMessage.append("Status: ").append(response.getStatus()).append("\n");
        logMessage.append("Duration: ").append(duration).append("ms\n");
        
        // Response headers
        logMessage.append("Headers: ").append(getResponseHeaders(response)).append("\n");
        
        // Response body
        String responsePayload = getResponsePayload(response);
        if (responsePayload != null && !responsePayload.isEmpty()) {
            logMessage.append("Body: ").append(maskSensitiveData(responsePayload)).append("\n");
        }
        
        // Log level based on status code
        if (response.getStatus() >= 500) {
            log.error(logMessage.toString());
        } else if (response.getStatus() >= 400) {
            log.warn(logMessage.toString());
        } else {
            log.info(logMessage.toString());
        }
    }

    private Map<String, String> getHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            
            // Mask sensitive headers
            if (isSensitiveHeader(headerName)) {
                headerValue = "***MASKED***";
            }
            
            headers.put(headerName, headerValue);
        }
        
        return headers;
    }

    private Map<String, String> getResponseHeaders(HttpServletResponse response) {
        Map<String, String> headers = new HashMap<>();
        
        for (String headerName : response.getHeaderNames()) {
            String headerValue = response.getHeader(headerName);
            
            // Mask sensitive headers
            if (isSensitiveHeader(headerName)) {
                headerValue = "***MASKED***";
            }
            
            headers.put(headerName, headerValue);
        }
        
        return headers;
    }

    private String getRequestPayload(ContentCachingRequestWrapper request) {
        byte[] content = request.getContentAsByteArray();
        if (content.length > 0) {
            try {
                String payload = new String(content, 0, 
                        Math.min(content.length, MAX_PAYLOAD_LENGTH), 
                        request.getCharacterEncoding());
                
                if (content.length > MAX_PAYLOAD_LENGTH) {
                    payload += "... (truncated)";
                }
                
                return payload;
            } catch (UnsupportedEncodingException e) {
                return "[Unable to parse request body]";
            }
        }
        return null;
    }

    private String getResponsePayload(ContentCachingResponseWrapper response) {
        byte[] content = response.getContentAsByteArray();
        if (content.length > 0) {
            try {
                String payload = new String(content, 0,
                        Math.min(content.length, MAX_PAYLOAD_LENGTH),
                        response.getCharacterEncoding());
                
                if (content.length > MAX_PAYLOAD_LENGTH) {
                    payload += "... (truncated)";
                }
                
                return payload;
            } catch (UnsupportedEncodingException e) {
                return "[Unable to parse response body]";
            }
        }
        return null;
    }

    private boolean isSensitiveHeader(String headerName) {
        for (String sensitive : SENSITIVE_HEADERS) {
            if (sensitive.equalsIgnoreCase(headerName)) {
                return true;
            }
        }
        return false;
    }

    private String maskSensitiveData(String data) {
        if (data == null) {
            return null;
        }
        
        String masked = data;
        for (String field : SENSITIVE_FIELDS) {
            // Mask password, token, etc. in JSON
            masked = masked.replaceAll(
                    "\"" + field + "\"\\s*:\\s*\"[^\"]*\"",
                    "\"" + field + "\":\"***MASKED***\""
            );
        }
        
        return masked;
    }
}
