package com.cantalay.authgateway.realm;

import feign.FeignException;

import java.util.Locale;

/** Classifies Keycloak token/admin endpoint errors from their OAuth error payloads. */
public final class KeycloakErrors {

    private KeycloakErrors() {
    }

    public static String body(FeignException e) {
        String body = e.contentUTF8();
        return body == null ? "" : body.toLowerCase(Locale.ROOT);
    }

    /** {@code invalid_grant} for disabled users or users with pending required actions (e.g. email verification). */
    public static boolean isAccountNotUsable(FeignException e) {
        String body = body(e);
        return body.contains("account disabled") || body.contains("not fully set up")
                || body.contains("account is temporarily disabled");
    }

    /** The client is not allowed to use the requested grant — a configuration problem, not a user error. */
    public static boolean isClientMisconfigured(FeignException e) {
        String body = body(e);
        return body.contains("unauthorized_client") || body.contains("invalid_client");
    }

    public static boolean isPasswordPolicyViolation(FeignException e) {
        String body = body(e);
        return body.contains("password") && (body.contains("policy") || body.contains("invalidpassword"));
    }

    /** Masks an email address for logs: {@code j***@example.com}. */
    public static String maskEmail(String email) {
        if (email == null) {
            return null;
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        return email.charAt(0) + "***" + email.substring(at);
    }
}
