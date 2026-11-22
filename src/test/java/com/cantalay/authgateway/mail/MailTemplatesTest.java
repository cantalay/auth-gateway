package com.cantalay.authgateway.mail;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MailTemplatesTest {

    private final MailTemplates templates = new MailTemplates();

    @Test
    void everyLanguageHasTheSameKeys() {
        assertThat(templates.bundle("en").stringPropertyNames()).isEqualTo(templates.bundle("tr").stringPropertyNames());
        for (MailTemplate template : MailTemplate.values()) {
            for (String locale : List.of("tr", "en")) {
                RenderedMail mail = templates.render(template, locale, Map.of("app", "ToDoGi", "email", "can@ornek.com",
                        "name", "Can", "duration", "1 saat", "providers", "Google"), "https://todogi.net/x#t=abc", List.of());
                assertThat(mail.subject()).isNotBlank().doesNotContain("{");
                assertThat(mail.text()).doesNotContain("{").contains("https://todogi.net/x#t=abc");
                assertThat(mail.html()).doesNotContain("{").contains("href=\"https://todogi.net/x#t=abc\"");
            }
        }
    }

    @Test
    void verifyEmailMatchesThePrototype() {
        RenderedMail mail = templates.render(MailTemplate.VERIFY, "tr", Map.of("app", "ToDoGi", "email", "can@ornek.com",
                "name", "Can", "duration", templates.duration("tr", Duration.ofHours(24))), "https://todogi.net/eposta-onay#t=abc", List.of());

        assertThat(mail.subject()).isEqualTo("ToDoGi için e-postanı onayla");
        assertThat(mail.text()).startsWith("Merhaba Can,")
                .contains("can@ornek.com adresini onaylamak için düğmeye dokun. Bağlantı 24 saat geçerli.")
                .contains("E-postayı onayla");
        assertThat(mail.html()).contains("lang=\"tr\"");

        RenderedMail en = templates.render(MailTemplate.VERIFY, "en", Map.of("app", "ToDoGi", "email", "can@ornek.com",
                "name", "Can", "duration", templates.duration("en", Duration.ofHours(24))), "https://x", List.of());
        assertThat(en.subject()).isEqualTo("Confirm your email for ToDoGi");
        assertThat(en.text()).contains("Tap the button to confirm can@ornek.com. The link works for 24 hours.");
    }

    @Test
    void durationsAndProviderLists() {
        assertThat(templates.duration("tr", Duration.ofMinutes(60))).isEqualTo("1 saat");
        assertThat(templates.duration("en", Duration.ofMinutes(60))).isEqualTo("1 hour");
        assertThat(templates.duration("en", Duration.ofMinutes(90))).isEqualTo("90 minutes");
        assertThat(templates.joinProviders("tr", List.of("Google", "Apple"))).isEqualTo("Google ya da Apple");
        assertThat(templates.joinProviders("en", List.of("Google"))).isEqualTo("Google");
    }

    @Test
    void escapesValuesAndFallsBackForUnknownLanguages() {
        RenderedMail mail = templates.render(MailTemplate.WELCOME, "de", Map.of("app", "A&B", "name", "<script>x</script>"),
                "https://app.example/?a=1&b=2", List.of("verify"));

        assertThat(mail.html()).doesNotContain("<script>x").contains("&lt;script&gt;").contains("a=1&amp;b=2").contains("A&amp;B");
        assertThat(mail.subject()).isEqualTo("Welcome to A&B"); // English fallback
        assertThat(mail.text()).contains("separate email to confirm");
        assertThat(templates.supports("de")).isFalse();
        assertThat(templates.supports("../x")).isFalse();
    }

    @Test
    void plainGreetingWithoutAName() {
        RenderedMail mail = templates.render(MailTemplate.RESET, "tr", Map.of("app", "ToDoGi", "email", "a@b.co", "duration", "1 saat"),
                "https://x", List.of());
        assertThat(mail.text()).startsWith("Merhaba,\n");
    }
}
