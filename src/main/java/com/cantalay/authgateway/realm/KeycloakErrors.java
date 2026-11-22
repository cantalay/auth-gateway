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

    /**
     * Which password policy rule Keycloak rejected ({@code invalidPasswordMinLengthMessage} → {@code length}), for
     * clients that explain the rule; {@code null} when the body names none.
     */
    public static String passwordPolicyRule(FeignException e) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("invalidpassword([a-z]+)message").matcher(body(e));
        if (!m.find()) {
            return null;
        }
        return switch (m.group(1)) {
            case "minlength", "maxlength" -> "length";
            case "mindigits" -> "digits";
            case "minlowercasechars" -> "lowerCase";
            case "minuppercasechars" -> "upperCase";
            case "minspecialchars" -> "specialChars";
            case "history" -> "passwordHistory";
            case "notusername" -> "notUsername";
            case "notemail" -> "notEmail";
            case "blacklisted" -> "passwordBlacklist";
            case "regexpattern" -> "regexPattern";
            default -> "policy";
        };
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
