package com.cantalay.authgateway.mail;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-realm email settings, e.g.
 * <pre>
 * GATEWAY_MAIL_REALMS_TODOGI_FROM=todogi@singlestranger.com
 * GATEWAY_MAIL_REALMS_TODOGI_FROMNAME=Todogi
 * GATEWAY_MAIL_REALMS_TODOGI_APPNAME=Todogi
 * GATEWAY_MAIL_REALMS_TODOGI_APPURL=https://todogi.singlestranger.com
 * GATEWAY_MAIL_REALMS_TODOGI_VERIFYCLIENTID=...      (opsiyonel: doğrulama sonrası uygulamaya dönüş)
 * GATEWAY_MAIL_REALMS_TODOGI_VERIFYREDIRECTURI=...
 * </pre>
 * A realm without {@code from} gets no welcome email.
 */
@ConfigurationProperties(prefix = "gateway.mail")
public class MailProperties {

    private Map<String, Realm> realms = new LinkedHashMap<>();

    public Map<String, Realm> getRealms() { return realms; }
    public void setRealms(Map<String, Realm> realms) { this.realms = realms; }

    public Realm realm(String name) {
        return realms.get(name.toLowerCase());
    }

    public static class Realm {
        private String from;
        private String fromName;
        private String appName;
        private String appUrl;
        private String verifyClientId;
        private String verifyRedirectUri;

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
    }
}
