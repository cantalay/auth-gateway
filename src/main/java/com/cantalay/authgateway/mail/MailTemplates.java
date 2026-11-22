package com.cantalay.authgateway.mail;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Renders gateway emails from {@code mail/messages_<locale>.properties}: plain text plus a simple HTML version (no
 * images, one action button). Values are HTML-escaped; message texts are trusted. A missing key falls back to English,
 * then Turkish.
 */
@Component
public class MailTemplates {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([a-zA-Z]+)}");
    private static final List<String> FALLBACKS = List.of("en", "tr");

    private final Map<String, Properties> bundles = new ConcurrentHashMap<>();

    /**
     * @param vars      placeholder values ({@code app}, {@code name}, {@code email}, {@code duration}, {@code providers},
     *                  {@code support}); a blank {@code name} selects the plain greeting
     * @param buttonUrl target of the action button; {@code null} for no button
     * @param extra     additional paragraph keys of the template to include after its own (e.g. {@code verify} in the
     *                  welcome email)
     */
    public RenderedMail render(MailTemplate template, String locale, Map<String, String> vars, String buttonUrl,
                               List<String> extra) {
        String p = template.prefix() + ".";
        String greeting = StringUtils.hasText(vars.get("name")) ? "greeting.named" : "greeting.plain";
        List<String> paragraphs = new ArrayList<>();
        for (String key : template.paragraphs()) {
            paragraphs.add(p + key);
        }
        for (String key : extra) {
            paragraphs.add(p + key);
        }

        String subject = fill(message(locale, p + "subject"), vars, false);
        StringBuilder text = new StringBuilder();
        StringBuilder html = new StringBuilder();

        text.append(fill(message(locale, greeting), vars, false)).append("\n\n");
        for (String key : paragraphs) {
            text.append(fill(message(locale, key), vars, false)).append("\n\n");
        }
        String button = buttonUrl == null ? null : fill(message(locale, p + "button"), vars, false);
        if (button != null) {
            text.append(button).append(":\n").append(buttonUrl).append("\n\n");
        }
        text.append(fill(message(locale, p + "note"), vars, false)).append("\n\n");
        text.append("— ").append(vars.getOrDefault("app", "")).append("\n");
        text.append(message(locale, "footer.automated")).append("\n");
        if (StringUtils.hasText(vars.get("support"))) {
            text.append(fill(message(locale, "footer.help"), vars, false)).append("\n");
        }

        html.append("<!doctype html>\n<html lang=\"").append(esc(locale)).append("\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>").append(esc(subject)).append("</title></head>")
                .append("<body style=\"margin:0;padding:0;background:#F3F4F6;color:#151C26;")
                .append("font-family:Figtree,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.5\">")
                .append("<div style=\"max-width:520px;margin:0 auto;padding:24px 16px\">")
                .append("<div style=\"background:#FFFFFF;border:1px solid #E1E2E4;border-radius:18px;padding:24px\">")
                .append("<h1 style=\"margin:0 0 16px;font-size:22px;line-height:1.2;letter-spacing:-0.01em\">")
                .append(fill(message(locale, p + "heading"), vars, true)).append("</h1>")
                .append("<p style=\"margin:0 0 8px;font-weight:600\">").append(fill(message(locale, greeting), vars, true)).append("</p>");
        for (String key : paragraphs) {
            html.append("<p style=\"margin:0 0 12px;color:#545B66\">").append(fill(message(locale, key), vars, true)).append("</p>");
        }
        if (button != null) {
            String href = esc(buttonUrl);
            html.append("<p style=\"margin:24px 0\"><a href=\"").append(href)
                    .append("\" style=\"display:inline-block;background:#151C26;color:#FFFFFF;padding:12px 22px;")
                    .append("border-radius:12px;text-decoration:none;font-weight:600\">").append(esc(button)).append("</a></p>")
                    .append("<p style=\"margin:0 0 12px;color:#747B85;font-size:13px\">")
                    .append(esc(message(locale, "button.fallback"))).append("<br><a href=\"").append(href)
                    .append("\" style=\"color:#545B66;word-break:break-all\">").append(href).append("</a></p>");
        }
        html.append("<p style=\"margin:16px 0 0;color:#747B85;font-size:13px\">").append(fill(message(locale, p + "note"), vars, true)).append("</p>")
                .append("</div>")
                .append("<p style=\"margin:16px 8px 0;color:#747B85;font-size:12px\">").append(esc(vars.getOrDefault("app", ""))).append(" · ")
                .append(esc(message(locale, "footer.automated")));
        if (StringUtils.hasText(vars.get("support"))) {
            html.append("<br>").append(fill(message(locale, "footer.help"), vars, true));
        }
        html.append("</p></div></body></html>\n");

        return new RenderedMail(subject, text.toString(), html.toString());
    }

    /** {@code 60m} → "1 saat" / "1 hour"; whole hours as hours, otherwise minutes. */
    public String duration(String locale, Duration duration) {
        long minutes = Math.max(1, duration.toMinutes());
        boolean hours = minutes % 60 == 0;
        long n = hours ? minutes / 60 : minutes;
        String key = "duration." + (hours ? "hour" : "minute") + (n == 1 ? ".one" : ".other");
        return message(locale, key).replace("{n}", Long.toString(n));
    }

    /** "Google", "Google ya da Apple", "Google, Apple or X". */
    public String joinProviders(String locale, List<String> names) {
        if (names.isEmpty()) {
            return "";
        }
        if (names.size() == 1) {
            return names.get(0);
        }
        return String.join(", ", names.subList(0, names.size() - 1)) + " " + message(locale, "providers.or") + " "
                + names.get(names.size() - 1);
    }

    /** Whether a bundle exists for the language. */
    public boolean supports(String locale) {
        return !bundle(locale).isEmpty();
    }

    String message(String locale, String key) {
        String value = bundle(locale).getProperty(key);
        for (int i = 0; value == null && i < FALLBACKS.size(); i++) {
            value = bundle(FALLBACKS.get(i)).getProperty(key);
        }
        if (value == null) {
            throw new IllegalStateException("Missing mail message " + key);
        }
        return value;
    }

    Properties bundle(String locale) {
        return bundles.computeIfAbsent(locale == null ? "" : locale, l -> {
            Properties properties = new Properties();
            if (!l.matches("[a-z]{2,3}")) {
                return properties;
            }
            try (InputStream in = MailTemplates.class.getResourceAsStream("/mail/messages_" + l + ".properties")) {
                if (in != null) {
                    properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return properties;
        });
    }

    private static String fill(String message, Map<String, String> vars, boolean html) {
        String source = html ? esc(message) : message;
        Matcher m = PLACEHOLDER.matcher(source);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String value = vars.getOrDefault(m.group(1), "");
            m.appendReplacement(out, Matcher.quoteReplacement(html ? esc(value) : value));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String esc(String value) {
        return value == null ? "" : HtmlUtils.htmlEscape(value);
    }
}
