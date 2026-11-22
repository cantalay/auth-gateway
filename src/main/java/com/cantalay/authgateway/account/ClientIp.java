package com.cantalay.authgateway.account;

import jakarta.servlet.http.HttpServletRequest;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.regex.Pattern;

/**
 * Client address for rate limits. The gateway is reached only through Traefik (externalTrafficPolicy Local), which
 * appends the peer address to {@code X-Forwarded-For}; the last entry is the one Traefik saw, earlier entries are
 * client-supplied and ignored.
 */
public final class ClientIp {

    private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9A-Fa-f:.]+");

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

    /**
     * Rate-limit key of an address: IPv4 as is, IPv6 reduced to its /64 prefix (one subscriber usually owns a whole /64,
     * so per-address limits would be trivial to rotate around). Only literals are parsed; nothing is resolved.
     */
    public static String rateKey(String address) {
        if (address == null || address.isBlank()) {
            return "unknown";
        }
        String a = address.trim();
        if (a.startsWith("[")) {
            int end = a.indexOf(']');
            a = end > 0 ? a.substring(1, end) : a.substring(1);
        }
        int zone = a.indexOf('%');
        if (zone > 0) {
            a = a.substring(0, zone);
        }
        if (a.indexOf(':') < 0 || !IPV6_LITERAL.matcher(a).matches()) {
            return a;
        }
        try {
            InetAddress parsed = InetAddress.getByName(a); // a literal containing ':' is never looked up
            if (!(parsed instanceof Inet6Address)) {
                return parsed.getHostAddress(); // IPv4-mapped
            }
            byte[] b = parsed.getAddress();
            StringBuilder prefix = new StringBuilder();
            for (int i = 0; i < 8; i += 2) {
                prefix.append(Integer.toHexString(((b[i] & 0xff) << 8) | (b[i + 1] & 0xff))).append(':');
            }
            return prefix.append(":/64").toString();
        } catch (Exception e) {
            return a;
        }
    }
}
