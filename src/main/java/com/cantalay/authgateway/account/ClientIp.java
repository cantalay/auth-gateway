package com.cantalay.authgateway.account;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Client address for rate limits. The gateway is reached only through Traefik (externalTrafficPolicy Local), which
 * appends the peer address to {@code X-Forwarded-For}; the last entry is the one Traefik saw, earlier entries are
 * client-supplied and ignored.
 */
public final class ClientIp {

    private ClientIp() {
    }

    public static String of(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] parts = forwarded.split(",");
            for (int i = parts.length - 1; i >= 0; i--) {
                String candidate = parts[i].trim();
                if (!candidate.isEmpty()) {
                    return candidate;
                }
            }
        }
        return request.getRemoteAddr();
    }
}
