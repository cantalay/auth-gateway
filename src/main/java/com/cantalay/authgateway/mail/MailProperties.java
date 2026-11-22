package com.cantalay.authgateway.mail;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Per-realm email settings, e.g.
 * <pre>
 * GATEWAY_MAIL_REALMS_TODOGI_FROM=noreply@todogi.net
 * GATEWAY_MAIL_REALMS_TODOGI_FROMNAME=ToDoGi
 * GATEWAY_MAIL_REALMS_TODOGI_APPNAME=ToDoGi
 * GATEWAY_MAIL_REALMS_TODOGI_APPURL=https://todogi.net
 * GATEWAY_MAIL_REALMS_TODOGI_RESETURL=https://todogi.net/sifre-sifirla   (forgot/reset password through the gateway)
 * GATEWAY_MAIL_REALMS_TODOGI_VERIFYURL=https://todogi.net/eposta-onay    (email confirmation through the gateway)
 * GATEWAY_MAIL_REALMS_TODOGI_LOCALES=tr,en
 * GATEWAY_MAIL_REALMS_TODOGI_DEFAULTLOCALE=tr
 * GATEWAY_MAIL_REALMS_TODOGI_SUPPORTEMAIL=destek@todogi.net             (optional footer line)
 * GATEWAY_MAIL_REALMS_VITAFINDER_RESENDVERIFICATION=true                (opt-in resend of Keycloak's email; on with VERIFYURL)
 * GATEWAY_MAIL_REALMS_TODOGI_VERIFYCLIENTID=...      (Keycloak verification only: return to the app afterwards)
 * GATEWAY_MAIL_REALMS_TODOGI_VERIFYREDIRECTURI=...
 * </pre>
 * A realm without {@code from} gets no email from the gateway. Links carry the token in the fragment
 * ({@code <url>#t=<token>}) so it never reaches access logs or {@code Referer} headers.
 */
@ConfigurationProperties(prefix = "gateway.mail")
public class MailProperties {

    private Map<String, Realm> realms = new LinkedHashMap<>();

    public Map<String, Realm> getRealms() { return realms; }
    public void setRealms(Map<String, Realm> realms) { this.realms = realms; }

    public Realm realm(String name) {
        return realms.get(name.toLowerCase(Locale.ROOT));
    }

    /** {@code "tr-TR"} / {@code "tr_TR"} → {@code "tr"}; {@code null} for anything that is not a language code. */
    public static String normalizeLocale(String locale) {
        if (!StringUtils.hasText(locale)) {
            return null;
        }
        String l = locale.trim().replace('_', '-').toLowerCase(Locale.ROOT);
        int dash = l.indexOf('-');
        String language = dash > 0 ? l.substring(0, dash) : l;
        return language.matches("[a-z]{2,3}") ? language : null;
    }

    public static class Realm {
        private String from;
        private String fromName;
        private String appName;
        private String appUrl;
        private String verifyClientId;
        private String verifyRedirectUri;
        private String resetUrl;
        private String verifyUrl;
        private List<String> locales = new ArrayList<>();
        private String defaultLocale;
        private String supportEmail;
        private Boolean resendVerification;

        public String getFrom() { return from; }
        public void setFrom(String from) { this.from = from; }
        public String getFromName() { return fromName; }
        public void setFromName(String fromName) { this.fromName = fromName; }
        public String getAppName() { return appName; }
        public void setAppName(String appName) { this.appName = appName; }
        public String getAppUrl() { return appUrl; }
        public void setAppUrl(String appUrl) { this.appUrl = appUrl; }
        public String getVerifyClientId() { return verifyClientId; }
        public void setVerifyClientId(String verifyClientId) { this.verifyClientId = verifyClientId; }
        public String getVerifyRedirectUri() { return verifyRedirectUri; }
        public void setVerifyRedirectUri(String verifyRedirectUri) { this.verifyRedirectUri = verifyRedirectUri; }
        public String getResetUrl() { return resetUrl; }
        public void setResetUrl(String resetUrl) { this.resetUrl = resetUrl; }
        public String getVerifyUrl() { return verifyUrl; }
        public void setVerifyUrl(String verifyUrl) { this.verifyUrl = verifyUrl; }
        public List<String> getLocales() { return locales; }
        public void setLocales(List<String> locales) { this.locales = locales; }
        public String getDefaultLocale() { return defaultLocale; }
        public void setDefaultLocale(String defaultLocale) { this.defaultLocale = defaultLocale; }
        public String getSupportEmail() { return supportEmail; }
        public void setSupportEmail(String supportEmail) { this.supportEmail = supportEmail; }
        public Boolean getResendVerification() { return resendVerification; }
        public void setResendVerification(Boolean resendVerification) { this.resendVerification = resendVerification; }

        /** Default email language: {@code defaultLocale}, else the first configured locale, else Turkish. */
        public String effectiveDefaultLocale() {
            String normalized = normalizeLocale(defaultLocale);
            return normalized != null ? normalized : supportedLocales().get(0);
        }

        /** Languages the realm's emails may use, normalized ({@code "tr-TR"} → {@code "tr"}). */
        public List<String> supportedLocales() {
            List<String> result = new ArrayList<>();
            if (locales != null) {
                for (String locale : locales) {
                    String n = normalizeLocale(locale);
                    if (n != null && !result.contains(n)) {
                        result.add(n);
                    }
                }
            }
            String normalizedDefault = normalizeLocale(defaultLocale);
            if (normalizedDefault != null && !result.contains(normalizedDefault)) {
                result.add(normalizedDefault);
            }
            if (result.isEmpty()) {
                result.add("tr");
            }
            return result;
        }
    }
}
