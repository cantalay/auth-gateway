package com.cantalay.authgateway.support;

import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.internet.MimeMessage;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads gateway emails in tests. */
public final class Mails {

    private static final Pattern TOKEN = Pattern.compile("#t=([A-Za-z0-9_\\-.]+)");

    private Mails() {
    }

    public static String plainText(MimeMessage message) {
        try {
            String text = find(message, "text/plain");
            if (text == null) {
                throw new AssertionError("no text/plain part");
            }
            return text;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    public static String html(MimeMessage message) {
        try {
            return find(message, "text/html");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    /** The action token of the first {@code <url>#t=<token>} link. */
    public static String token(MimeMessage message) {
        Matcher m = TOKEN.matcher(plainText(message));
        if (!m.find()) {
            throw new AssertionError("no #t= link in email");
        }
        return m.group(1);
    }

    public static String subject(MimeMessage message) {
        try {
            return message.getSubject();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static String find(Part part, String type) throws Exception {
        if (part instanceof MimeMessage message) {
            message.saveChanges();
        }
        Object content = part.getContent();
        if (!(content instanceof Multipart) && part.isMimeType(type) && !Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())) {
            return content.toString();
        }
        if (content instanceof Multipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                String found = find(multipart.getBodyPart(i), type);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
