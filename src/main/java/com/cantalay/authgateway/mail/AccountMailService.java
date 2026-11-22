package com.cantalay.authgateway.mail;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

/**
 * Sends the gateway's account emails over SMTP ({@code spring.mail.*}; {@code SMTP_HOST} empty = no email). Sending is
 * synchronous; callers run it off the request thread. Failures are logged and counted, never thrown.
 * Metric: {@code auth_gateway_mail_sent_total{realm, template, result=ok|error|disabled}}.
 */
@Service
public class AccountMailService {

    private static final Logger log = LoggerFactory.getLogger(AccountMailService.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final MailProperties properties;
    private final MailTemplates templates;
    private final MeterRegistry meters;
    private final String smtpHost;

    public AccountMailService(ObjectProvider<JavaMailSender> mailSender,
                              MailProperties properties,
                              MailTemplates templates,
                              MeterRegistry meters,
                              @Value("${spring.mail.host:}") String smtpHost) {
        this.mailSender = mailSender;
        this.properties = properties;
        this.templates = templates;
        this.meters = meters;
        this.smtpHost = smtpHost;
    }

    /** SMTP is configured and the realm has a sender address. */
    public boolean isEnabled(String realm) {
        MailProperties.Realm config = properties.realm(realm);
        return StringUtils.hasText(smtpHost) && config != null && StringUtils.hasText(config.getFrom())
                && mailSender.getIfAvailable() != null;
    }

    public MailTemplates templates() {
        return templates;
    }

    /**
     * @param vars placeholder values; {@code app} and {@code support} are filled from the realm settings when absent
     * @return whether the message was handed to the SMTP server
     */
    public boolean send(String realm, MailTemplate template, String to, String locale, Map<String, String> vars,
                        String buttonUrl, List<String> extraParagraphs) {
        if (!isEnabled(realm)) {
            count(realm, template, "disabled");
            log.debug("Email {} disabled for realm {}", template.id(), realm);
            return false;
        }
        MailProperties.Realm config = properties.realm(realm);
        Map<String, String> values = new HashMap<>(vars);
        values.putIfAbsent("app", appName(realm));
        if (StringUtils.hasText(config.getSupportEmail())) {
            values.putIfAbsent("support", config.getSupportEmail());
        }
        try {
            RenderedMail mail = templates.render(template, locale, values, buttonUrl, extraParagraphs);
            JavaMailSender sender = mailSender.getObject();
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(new InternetAddress(config.getFrom(),
                    StringUtils.hasText(config.getFromName()) ? config.getFromName() : values.get("app"),
                    StandardCharsets.UTF_8.name()));
            helper.setTo(to);
            helper.setSubject(mail.subject());
            helper.setText(mail.text(), mail.html());
            message.setHeader("Auto-Submitted", "auto-generated");
            message.setHeader("Content-Language", locale);
            sender.send(message);
            count(realm, template, "ok");
            log.info("Email {} sent in realm {} to {}", template.id(), realm, maskEmail(to));
            return true;
        } catch (Exception e) {
            count(realm, template, "error");
            // The exception message of the mail stack may contain addresses; log only its type.
            log.error("Email {} failed in realm {} to {}: {}", template.id(), realm, maskEmail(to), e.getClass().getSimpleName());
            return false;
        }
    }

    public String appName(String realm) {
        MailProperties.Realm config = properties.realm(realm);
        return config != null && StringUtils.hasText(config.getAppName()) ? config.getAppName() : realm;
    }

    private void count(String realm, MailTemplate template, String result) {
        Counter.builder("auth.gateway.mail.sent")
                .description("Account emails sent by the gateway")
                .tag("realm", realm).tag("template", template.id()).tag("result", result)
                .register(meters).increment();
    }
}
