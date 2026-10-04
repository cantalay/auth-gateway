package com.cantalay.authgateway.mail;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class WelcomeMailServiceTest {

    private static MailProperties bind(Map<String, Object> env) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, env));
        return new Binder(ConfigurationPropertySources.get(environment)).bind("gateway.mail", MailProperties.class)
                .orElseGet(MailProperties::new);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<JavaMailSender> provider(JavaMailSender sender) {
        ObjectProvider<JavaMailSender> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(sender);
        when(provider.getObject()).thenReturn(sender);
        return provider;
    }

    private final MailProperties properties = bind(Map.of(
            "GATEWAY_MAIL_REALMS_TODOGI_FROM", "todogi@singlestranger.com",
            "GATEWAY_MAIL_REALMS_TODOGI_FROMNAME", "Todogi",
            "GATEWAY_MAIL_REALMS_TODOGI_APPNAME", "Todogi",
            "GATEWAY_MAIL_REALMS_TODOGI_APPURL", "https://todogi.singlestranger.com"
    ));

    @Test
    void bindsRealmMailSettingsFromEnvironment() {
        assertThat(properties.realm("todogi").getFromName()).isEqualTo("Todogi");
        assertThat(properties.realm("TODOGI").getAppUrl()).isEqualTo("https://todogi.singlestranger.com");
        assertThat(properties.realm("vitafinder")).isNull();
    }

    @Test
    void disabledWithoutSmtpHostOrSender() {
        JavaMailSender sender = mock(JavaMailSender.class);
        assertThat(new WelcomeMailService(provider(sender), properties, "").isEnabled("todogi")).isFalse();
        assertThat(new WelcomeMailService(provider(sender), properties, "smtp.example").isEnabled("vitafinder")).isFalse();

        new WelcomeMailService(provider(sender), properties, "").sendWelcome("todogi", "a@b.co", "Ayşe");
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test
    void sendsWelcomeEmail() throws Exception {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenAnswer(i -> new MimeMessage(Session.getInstance(new Properties())));
        WelcomeMailService service = new WelcomeMailService(provider(sender), properties, "smtp.example");

        service.sendWelcome("todogi", "ayse@example.com", "Ayşe");

        ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(captor.capture());
        MimeMessage message = captor.getValue();
        message.saveChanges();
        assertThat(message.getSubject()).isEqualTo("Hoş geldin — Todogi");
        assertThat(message.getFrom()[0].toString()).contains("todogi@singlestranger.com");
        assertThat(message.getAllRecipients()[0].toString()).isEqualTo("ayse@example.com");
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        message.writeTo(raw);
        assertThat(raw.toString()).contains("multipart/");
        assertThat(message.getContent()).isInstanceOf(MimeMultipart.class);
    }

    @Test
    void mailFailureDoesNotPropagate() {
        JavaMailSender sender = mock(JavaMailSender.class);
        when(sender.createMimeMessage()).thenAnswer(i -> new MimeMessage(Session.getInstance(new Properties())));
        doThrow(new org.springframework.mail.MailSendException("down")).when(sender).send(any(MimeMessage.class));

        new WelcomeMailService(provider(sender), properties, "smtp.example").sendWelcome("todogi", "a@b.co", "A");
    }

    @Test
    void escapesHtml() {
        String html = WelcomeMail.html("<script>x</script>", "App", "https://app.example/?a=1&b=2");
        assertThat(html).doesNotContain("<script>x").contains("&lt;script&gt;").contains("a=1&amp;b=2");
    }
}
