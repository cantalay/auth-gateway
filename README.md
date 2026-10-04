# auth-gateway

Uygulamaların Keycloak sayfası göstermeden kendi ekranlarından login/kayıt yapmasını sağlayan API.
`https://auth.cantalay.com/auth/*` adresinde çalışır ve birden çok Keycloak realm'ine hizmet eder.

## Endpoint'ler

Her endpoint realm'li (`/auth/{realm}/...`) ve varsayılan realm için eski (`/auth/...`) yoldan sunulur.

| Method | Path | Auth | Açıklama |
| --- | --- | --- | --- |
| POST | `/auth/{realm}/login` | — | `{email, password}` → Keycloak token yanıtı |
| POST | `/auth/{realm}/refresh` | — | `{refreshToken}` → yeni token |
| POST | `/auth/{realm}/register` | — | `{email, password, firstName, lastName}` → 201; Keycloak doğrulama maili + hoşgeldin maili |
| POST | `/auth/{realm}/resend-verification` | — | `{email}` → her zaman 202 (adresin kayıtlı olup olmadığını açığa vurmaz) |
| POST | `/auth/{realm}/social` | — | `{code, redirectUri}` → token (kc_idp_hint ile alınan code) |
| POST | `/auth/{realm}/logout` | Bearer | `{refreshToken}` |
| GET | `/auth/{realm}/me` | Bearer | Kullanıcı bilgisi |
| PATCH | `/auth/{realm}/me` | Bearer | `{firstName, lastName}` |
| POST | `/auth/{realm}/change-password` | Bearer | `{currentPassword, newPassword}` |

Bearer gerektiren çağrılarda token'ın `iss` değeri path'teki realm'e ait olmalıdır; aksi halde 403.
Bilinmeyen realm 404 döner. Hatalar: 401 hatalı kimlik bilgisi/token, 403 doğrulanmamış veya devre dışı hesap,
400 parola politikası/geçersiz veri, 409 kullanıcı zaten var, 503 Keycloak erişilemiyor veya client yapılandırması hatalı.

## Yapılandırma

Varsayılan realm (geriye uyumlu):

| Değişken | Açıklama |
| --- | --- |
| `KEYCLOAK_BASE_URL` | `https://auth.cantalay.com` |
| `KEYCLOAK_REALM` | Varsayılan realm (`todogi`) |
| `KEYCLOAK_ISSUER_URI` | Opsiyonel; varsayılan `<base>/realms/<realm>` |
| `KEYCLOAK_CLIENT_ID` | Login client'ı; varsayılan `auth` |
| `KEYCLOAK_ADMIN_CLIENT_ID`, `KEYCLOAK_ADMIN_CLIENT_SECRET` | Kullanıcı yönetimi service account'u |
| `CORS_ALLOWED_ORIGINS` | Virgülle ayrılmış izinli origin'ler |

Ek realm'ler, realm başına (realm adında `-`/`_` olmamalı):

| Değişken | Varsayılan |
| --- | --- |
| `GATEWAY_REALMS_<REALM>_ADMINCLIENTSECRET` | **zorunlu** |
| `GATEWAY_REALMS_<REALM>_CLIENTID` | `<realm>-gateway` |
| `GATEWAY_REALMS_<REALM>_ADMINCLIENTID` | `<realm>-gateway-admin` |
| `GATEWAY_REALMS_<REALM>_ISSUERURI` | `<base>/realms/<realm>` |

Keycloak client'ları `talay-identity` modülünde `gateway_client_enabled = true` ile oluşturulur. Secret'lar
Vault `kv/apps/todogi/keycloak` path'indedir ve ExternalSecret ile env olarak gelir.

## E-posta

Doğrulama mailini Keycloak gönderir (realm SMTP ayarı; `talay-identity/scripts/configure-realm-email.sh`). E-postası
doğrulanmamış kullanıcı login olamaz (403 "User email validation required."). Hoşgeldin mailini gateway kayıttan hemen
sonra gönderir; gönderim hatası kaydı bozmaz.

| Değişken | Açıklama |
| --- | --- |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_SSL`, `SMTP_STARTTLS` | Vault'tan; `SMTP_HOST` boşsa hoşgeldin maili kapalı |
| `GATEWAY_MAIL_REALMS_<REALM>_FROM` | Gönderen adres (SMTP sağlayıcısında doğrulanmış domain); yoksa o realm'e hoşgeldin maili gitmez |
| `GATEWAY_MAIL_REALMS_<REALM>_FROMNAME`, `_APPNAME`, `_APPURL` | Görünen ad, uygulama adı ve bağlantısı |
| `GATEWAY_MAIL_REALMS_<REALM>_VERIFYCLIENTID`, `_VERIFYREDIRECTURI` | Doğrulama bağlantısından sonra uygulamaya dönüş (client'ın izinli redirect'i olmalı) |

Request/response logları parola, token, secret ve API key alanlarını maskeler; e-posta adreslerini kısaltır.
