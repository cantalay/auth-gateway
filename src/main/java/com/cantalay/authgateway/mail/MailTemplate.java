package com.cantalay.authgateway.mail;

import java.util.List;

/** Emails the gateway sends; each has a heading, paragraphs, at most one button and a closing note. */
public enum MailTemplate {
    WELCOME("welcome", "welcome", List.of("body")),
    VERIFY("verify", "verify", List.of("body")),
    RESET("reset", "reset", List.of("body")),
    RESET_SOCIAL("reset-social", "resetSocial", List.of("body", "howto")),
    PASSWORD_CHANGED("password-changed", "passwordChanged", List.of("body", "warning"));

    private final String id;
    private final String prefix;
    private final List<String> paragraphs;

    MailTemplate(String id, String prefix, List<String> paragraphs) {
        this.id = id;
        this.prefix = prefix;
        this.paragraphs = paragraphs;
    }

    /** Metric label and log name. */
    public String id() {
        return id;
    }

    String prefix() {
        return prefix;
    }

    List<String> paragraphs() {
        return paragraphs;
    }
}
