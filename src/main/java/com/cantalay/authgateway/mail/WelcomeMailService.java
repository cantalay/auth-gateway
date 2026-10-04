package com.cantalay.authgateway.mail;

import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

import static com.cantalay.authgateway.realm.KeycloakErrors.maskEmail;

/** Sends the welcome email after registration; failures are logged and never fail the registration. */
@Service
public class WelcomeMailService {

    private static final Logger log = LoggerFactory.getLogger(WelcomeMailService.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final MailProperties properties;
    private final String smtpHost;

    public WelcomeMailService(ObjectProvider<JavaMailSender> mailSender,
                              MailProperties properties,
                              @Value("${spring.mail.host:}") String smtpHost) {
        this.mailSender = mailSender;
        this.properties = properties;
        this.smtpHost = smtpHost;
    }

    public boolean isEnabled(String realm) {
        MailProperties.Realm config = properties.realm(realm);
        return StringUtils.hasText(smtpHost) && config != null && StringUtils.hasText(config.getFrom())
                && mailSender.getIfAvailable() != null;
    }

    @Async
    public void sendWelcome(String realm, String email, String firstName) {
        if (!isEnabled(realm)) {
            log.debug("Welcome email disabled for realm {}", realm);
            return;
        }
        MailProperties.Realm config = properties.realm(realm);
        String appName = StringUtils.hasText(config.getAppName()) ? config.getAppName() : realm;
        try {
            JavaMailSender sender = mailSender.getObject();
            MimeMessage message = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(new InternetAddress(config.getFrom(),
                    StringUtils.hasText(config.getFromName()) ? config.getFromName() : appName, StandardCharsets.UTF_8.name()));
            helper.setTo(email);
            helper.setSubject(WelcomeMail.subject(appName));
            helper.setText(WelcomeMail.text(firstName, appName, config.getAppUrl()),
                    WelcomeMail.html(firstName, appName, config.getAppUrl()));
            sender.send(message);
            log.info("Welcome email sent in realm {} to {}", realm, maskEmail(email));
        } catch (Exception e) {
            log.error("Welcome email failed in realm {} to {}: {}", realm, maskEmail(email), e.getMessage());
        }
    }
}
