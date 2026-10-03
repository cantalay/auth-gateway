package com.cantalay.authgateway.realm;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Additional realms beyond the default {@code keycloak.realm}.
 * <p>
 * Configured through environment variables, one group per realm (realm names must not contain '-' or '_'):
 * <pre>
 * GATEWAY_REALMS_HELLO_CLIENTID=hello-gateway                 (default: &lt;realm&gt;-gateway)
 * GATEWAY_REALMS_HELLO_ADMINCLIENTID=hello-gateway-admin      (default: &lt;realm&gt;-gateway-admin)
 * GATEWAY_REALMS_HELLO_ADMINCLIENTSECRET=...                  (required)
 * GATEWAY_REALMS_HELLO_ISSUERURI=...                          (default: &lt;base-url&gt;/realms/&lt;realm&gt;)
 * </pre>
 */
@ConfigurationProperties(prefix = "gateway")
public class GatewayProperties {

    private Map<String, Realm> realms = new LinkedHashMap<>();

    public Map<String, Realm> getRealms() {
        return realms;
    }

    public void setRealms(Map<String, Realm> realms) {
        this.realms = realms;
    }

    public static class Realm {
        private String clientId;
        private String adminClientId;
        private String adminClientSecret;
        private String issuerUri;

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getAdminClientId() { return adminClientId; }
        public void setAdminClientId(String adminClientId) { this.adminClientId = adminClientId; }
        public String getAdminClientSecret() { return adminClientSecret; }
        public void setAdminClientSecret(String adminClientSecret) { this.adminClientSecret = adminClientSecret; }
        public String getIssuerUri() { return issuerUri; }
        public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
    }
}
