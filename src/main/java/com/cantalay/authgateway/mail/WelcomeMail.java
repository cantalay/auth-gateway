package com.cantalay.authgateway.mail;

import org.springframework.web.util.HtmlUtils;

/** Renders the welcome email (Turkish). */
public final class WelcomeMail {

    private WelcomeMail() {
    }

    public static String subject(String appName) {
        return "Hoş geldin — " + appName;
    }

    public static String text(String firstName, String appName, String appUrl) {
        return """
                Merhaba %s,

                %s hesabın oluşturuldu, aramıza hoş geldin!

                Giriş yapabilmek için sana ayrıca gönderdiğimiz e-postadaki bağlantıyla e-posta adresini doğrula.
                Doğrulama e-postası gelmediyse uygulamadaki "Doğrulama e-postasını tekrar gönder" seçeneğini kullanabilirsin.

                %s

                Bu hesabı sen oluşturmadıysan bu e-postayı yok sayabilirsin.
                """.formatted(firstName, appName, appUrl == null ? "" : appUrl);
    }

    public static String html(String firstName, String appName, String appUrl) {
        String name = HtmlUtils.htmlEscape(firstName);
        String app = HtmlUtils.htmlEscape(appName);
        String link = appUrl == null ? "" : """
                <p style="margin:24px 0"><a href="%1$s" style="background:#111827;color:#ffffff;padding:12px 20px;border-radius:6px;text-decoration:none">%2$s'i aç</a></p>
                """.formatted(HtmlUtils.htmlEscape(appUrl), app);
        return """
                <!doctype html>
                <html lang="tr"><body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827;line-height:1.5">
                <div style="max-width:520px;margin:0 auto;padding:24px">
                <h2 style="margin-top:0">Hoş geldin, %1$s!</h2>
                <p><strong>%2$s</strong> hesabın oluşturuldu.</p>
                <p>Giriş yapabilmek için sana ayrıca gönderdiğimiz e-postadaki bağlantıyla e-posta adresini doğrula.
                Doğrulama e-postası gelmediyse uygulamadaki <em>Doğrulama e-postasını tekrar gönder</em> seçeneğini kullanabilirsin.</p>
                %3$s
                <p style="color:#6b7280;font-size:13px">Bu hesabı sen oluşturmadıysan bu e-postayı yok sayabilirsin.</p>
                </div></body></html>
                """.formatted(name, app, link);
    }
}
