# auth-gateway

Uygulamaların Keycloak sayfası göstermeden kendi ekranlarından login/kayıt yapmasını sağlayan API.
`https://auth.cantalay.com/auth/*` adresinde çalışır ve birden çok Keycloak realm'ine hizmet eder.

## Endpoint'ler

Her endpoint realm'li (`/auth/{realm}/...`) ve varsayılan realm için eski (`/auth/...`) yoldan sunulur.

| Method | Path | Auth | Açıklama |
| --- | --- | --- | --- |
| POST | `/auth/{realm}/login` | — | `{email, password}` → Keycloak token yanıtı |
| POST | `/auth/{realm}/refresh` | — | `{refreshToken}` → yeni token |
| POST | `/auth/{realm}/register` | — | `{email, password, firstName, lastName, locale?}` → 201; doğrulama e-postası (gateway bağlantısı ya da Keycloak'ınki, bkz. E-posta) + hoş geldin e-postası |
| POST | `/auth/{realm}/resend-verification` | — | `{email, locale?}` → her zaman 202 (adresin kayıtlı olup olmadığını açığa vurmaz); e-posta başına dakikada 1, saatte 5 |
| POST | `/auth/{realm}/verify-email` | — | `{token}` → 204 (zaten onaylıysa da 204) / 410 `verify_token_invalid`; sonra istemci `/refresh` ile `email_verified` claim'ini tazeler |
| POST | `/auth/{realm}/forgot-password` | — | `{email, locale?}` → her zaman 202; parolalı hesaba sıfırlama bağlantısı, parolasız (Google/Apple) hesaba "sağlayıcınla giriş yap" e-postası |
| POST | `/auth/{realm}/reset-password/check` | — | `{token}` → 204 / 410 `reset_token_invalid` (form açılmadan "bağlantının süresi doldu" ekranı) |
| POST | `/auth/{realm}/reset-password` | — | `{token, newPassword}` → 200 token yanıtı (bu cihazda yeni oturum) / 204 (parola değişti, giriş yapılamadı) / 400 `password_policy` / 410 `reset_token_invalid` |
| POST | `/auth/{realm}/social` | — | `{code, redirectUri}` → token (kc_idp_hint ile alınan code) |
| POST | `/auth/{realm}/logout` | Bearer | `{refreshToken}` |
| GET | `/auth/{realm}/me` | Bearer | Kullanıcı bilgisi |
| PATCH | `/auth/{realm}/me` | Bearer | `{firstName, lastName}` |
| POST | `/auth/{realm}/change-password` | Bearer | `{currentPassword, newPassword}` |

Bearer gerektiren çağrılarda token'ın `iss` değeri path'teki realm'e ait olmalıdır; aksi halde 403.
Bilinmeyen realm 404 döner. Hatalar: 401 hatalı kimlik bilgisi/token, 403 doğrulanmamış veya devre dışı hesap,
400 parola politikası/geçersiz veri, 409 kullanıcı zaten var, 503 Keycloak erişilemiyor veya client yapılandırması hatalı.

Hata gövdesi `{success:false, error:{timestamp, status, error, message, path, code?, validationErrors?}}`. `code` istemci
çevirisi içindir ve yalnız kodu olan hatalarda bulunur (eski hatalarda alan yoktur):

| `code` | Durum | Anlam |
| --- | --- | --- |
| `password_policy` | 400 | Parola realm politikasına uymuyor; `validationErrors.newPassword` reddedilen kural (`length`, `digits`, `lowerCase`, `upperCase`, `specialChars`, `passwordHistory`, `notUsername`, `notEmail`, `policy`) |
| `reset_token_invalid` | 410 | Sıfırlama bağlantısı süresi dolmuş, kullanılmış (parola değişti), değiştirilmiş ya da başka realm'in/amacın |
| `verify_token_invalid` | 410 | Onay bağlantısı geçersiz ya da hesabın e-postası değişmiş |
| `rate_limited` | 429 | Belirteç uçlarında (`reset-password`, `reset-password/check`, `verify-email`) IP başına saatte 20 aşıldı |
| `realm_feature_disabled` | 404 | Realm'de bu özellik açık değil (`RESETURL` / `VERIFYURL` tanımsız) |

E-posta alan uçlar (`forgot-password`, `resend-verification`) sınır aşılsa da 202 döner, yalnız e-posta gitmez:
`forgot-password` e-posta başına saatte 3, IP başına saatte 10; `resend-verification` IP başına saatte 20. Kullanıcı
araması ve gönderim arka planda yapılır; yanıt (ve süresi) adresin kayıtlı olup olmadığını göstermez. Sınırlar pod
belleğindedir (tek replika); IP, Traefik'in `X-Forwarded-For`'a eklediği son değerdir.

## Yapılandırma

Varsayılan realm (geriye uyumlu):

| Değişken | Açıklama |
| --- | --- |
| `KEYCLOAK_BASE_URL` | `https://auth.cantalay.com` |
| `KEYCLOAK_REALM` | Varsayılan realm (`todogi`) |
| `KEYCLOAK_ISSUER_URI` | Opsiyonel; varsayılan `<base>/realms/<realm>` |
| `KEYCLOAK_CLIENT_ID` | Login client'ı; varsayılan `auth` |
| `KEYCLOAK_ADMIN_CLIENT_ID`, `KEYCLOAK_ADMIN_CLIENT_SECRET` | Kullanıcı yönetimi service account'u |
| `KEYCLOAK_OFFLINE_ACCESS` | `false` — `true`: varsayılan realm'de giriş `offline_access` ister (ek realm'lerdeki `GATEWAY_REALMS_<REALM>_OFFLINEACCESS` gibi) |
| `CORS_ALLOWED_ORIGINS` | Virgülle ayrılmış izinli origin'ler |

Ek realm'ler, realm başına (realm adında `-`/`_` olmamalı):

| Değişken | Varsayılan |
| --- | --- |
| `GATEWAY_REALMS_<REALM>_ADMINCLIENTSECRET` | **zorunlu** |
| `GATEWAY_REALMS_<REALM>_CLIENTID` | `<realm>-gateway` |
| `GATEWAY_REALMS_<REALM>_ADMINCLIENTID` | `<realm>-gateway-admin` |
| `GATEWAY_REALMS_<REALM>_ISSUERURI` | `<base>/realms/<realm>` |
| `GATEWAY_REALMS_<REALM>_OFFLINEACCESS` | `false` — `true`: giriş `offline_access` ister (mobil uygulama oturumu, kullanıldıkça düşmez; realm `offline_access` rolünü vermeli) |
| `GATEWAY_REALMS_<REALM>_PLATFORMLOGIN` | `false` — `true`: `POST /auth/<realm>/platform` (Game Center / Play Games; talay-keycloak-providers `platform-identity` akışı) ve `POST /auth/<realm>/platform/link`, `GET /auth/<realm>/platform/links` |
| `GATEWAY_REALMS_<REALM>_PLATFORMCLIENTID` | `<realm>-platform` |

Keycloak client'ları `talay-identity` modülünde `gateway_client_enabled = true` ile oluşturulur. Secret'lar
Vault `kv/apps/todogi/keycloak` path'indedir ve ExternalSecret ile env olarak gelir.

## E-posta

Gateway e-postaları (hoş geldin, doğrulama, parola sıfırlama, "parolan değişti") SMTP ile gider; şablonlar
`src/main/resources/mail/messages_<dil>.properties` (TR/EN; yeni dil = aynı anahtarlarla yeni dosya), düz metin + basit
HTML, tek eylem düğmesi. Dil: istekteki `locale` → kullanıcının `locale` özniteliği → realm'in `DEFAULTLOCALE`'u.
Kayıtta gelen `locale`, realm'in dilleri arasındaysa kullanıcı özniteliği olarak yazılır.

Her şey realm başına açılır; ayar yoksa davranış eskisi gibidir:

| Realm ayarı | Davranış |
| --- | --- |
| `VERIFYURL` yok | Kayıt ve `resend-verification` Keycloak'ın doğrulama e-postasını ister (realm SMTP'si; bağlantı Keycloak sayfası açar). `verify-email` 404 |
| `VERIFYURL` var | Doğrulama e-postasını gateway gönderir: `<VERIFYURL>#t=<belirteç>` (24 saat; e-posta değişince geçersiz). Keycloak'ın e-postası gitmez |
| `RESETURL` yok | `forgot-password`, `reset-password`, `reset-password/check` 404 `realm_feature_disabled` |
| `RESETURL` var | Sıfırlama bağlantısı `<RESETURL>#t=<belirteç>` (60 dk, tek kullanım). Başarılı sıfırlama: tüm oturumlar ve offline token'lar kapanır, brute-force kilidi kalkar, "parolan değişti" e-postası gider, bu cihazda yeni parolayla giriş yapılır |
| `FROM` yok | O realm'e gateway e-postası gitmez (hoş geldin dahil); `RESETURL`/`VERIFYURL` tanımlı olsa da özellikler kapalı kalır (açılışta hata logu) |

Belirteç bağlantının parçasındadır (`#t=`): erişim loglarına ve `Referer`'a düşmez. Uygulama `location.hash`'ten okur,
adres çubuğundan siler ve gövdede `token` alanıyla gönderir.

| Değişken | Açıklama |
| --- | --- |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_SSL`, `SMTP_STARTTLS` | Vault'tan; `SMTP_HOST` boşsa gateway e-posta göndermez (varsayılan port 465, SSL) |
| `GATEWAY_ACTION_TOKEN_SECRETS` | Vault'tan; `k2:<base64 32+ bayt>,k1:<...>` — ilk anahtar imzalar, hepsi doğrular. Boş/geçersizse belirteçli özellikler kapalı (gateway yine açılır) |
| `GATEWAY_MAIL_REALMS_<REALM>_FROM` | Gönderen adres (SMTP sağlayıcısında doğrulanmış alan) |
| `GATEWAY_MAIL_REALMS_<REALM>_FROMNAME`, `_APPNAME`, `_APPURL` | Görünen ad, uygulama adı, "uygulamayı aç" bağlantısı |
| `GATEWAY_MAIL_REALMS_<REALM>_RESETURL` | Parola sıfırlama sayfası (ör. `https://todogi.net/sifre-sifirla`); şifremi unuttum özelliğini açar |
| `GATEWAY_MAIL_REALMS_<REALM>_VERIFYURL` | E-posta onay sayfası (ör. `https://todogi.net/eposta-onay`); gateway doğrulamasını açar |
| `GATEWAY_MAIL_REALMS_<REALM>_LOCALES`, `_DEFAULTLOCALE` | E-posta dilleri (`tr,en`) ve varsayılan (`tr`) |
| `GATEWAY_MAIL_REALMS_<REALM>_SUPPORTEMAIL` | Opsiyonel; altbilgide "Yardım için … adresine yaz" |
| `GATEWAY_MAIL_REALMS_<REALM>_VERIFYCLIENTID`, `_VERIFYREDIRECTURI` | Yalnız Keycloak doğrulamasında: bağlantıdan sonra uygulamaya dönüş (client'ın izinli redirect'i olmalı) |

### Eylem belirteci anahtarını döndürme

Biçim `base64url(JSON) + "." + base64url(HMAC-SHA256)`; yükte `kid`, realm, amaç (`reset`/`verify`), kullanıcı, bitiş ve
hesap parmak izi var (parola kimlik bilgisi ya da e-posta değişince belirteç geçersiz olur; sunucuda durum tutulmaz).

1. Yeni anahtar üret ve **başa** ekle (eski kalır): `GATEWAY_ACTION_TOKEN_SECRETS="k2:<yeni>,k1:<eski>"`
   (`openssl rand -base64 32` çıktısı dosyadan, `vault kv patch -mount=kv apps/todogi/keycloak GATEWAY_ACTION_TOKEN_SECRETS=@dosya`).
2. ExternalSecret'ı tazele, gateway'i yeniden başlat: yeni bağlantılar `k2` ile imzalanır, açıktaki `k1` bağlantıları çalışır.
3. En uzun ömür (24 saat) geçince `k1`'i listeden çıkar.

Anahtar sızdıysa 1'de eskiyi hemen çıkar: açıktaki bağlantılar geçersizleşir, kullanıcı yenisini ister.

## Metrikler

`/actuator/prometheus`: `auth_gateway_action_requests_total{realm, action=forgot|reset|reset_check|verify|resend,
result=ok|invalid|expired|policy|rate_limited|disabled}`, `auth_gateway_mail_sent_total{realm, template, result=ok|error|disabled}`.

## Testler

`./mvnw test` birim ve bileşen testleri; `./mvnw verify` ek olarak `*IT` entegrasyon testlerini koşar (Testcontainers ile
gerçek Keycloak `quay.io/keycloak/keycloak:26.7.3` + GreenMail SMTP; Docker yoksa atlanır, imaj `-Dit.keycloak.image=` ile
değişir).

Request/response logları parola, token, secret ve API key alanlarını maskeler; e-posta adreslerini kısaltır.
