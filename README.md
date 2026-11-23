# auth-gateway

Uygulamaların Keycloak sayfası göstermeden kendi ekranlarından login/kayıt yapmasını sağlayan API.
`https://auth.cantalay.com/auth/*` adresinde çalışır ve birden çok Keycloak realm'ine hizmet eder.

## Endpoint'ler

Her endpoint realm'li (`/auth/{realm}/...`) ve varsayılan realm için eski (`/auth/...`) yoldan sunulur.

| Method | Path | Auth | Açıklama |
| --- | --- | --- | --- |
| POST | `/auth/{realm}/login` | — | `{email, password}` → Keycloak token yanıtı |
| POST | `/auth/{realm}/refresh` | — | `{refreshToken}` → yeni token |
| POST | `/auth/{realm}/register` | — | `{email, password, firstName, lastName, locale?}` → 201; doğrulama e-postası (gateway bağlantısı ya da Keycloak'ınki, bkz. E-posta) + hoş geldin e-postası. IP başına saatte 20, e-posta başına saatte 5 (aşımda 429 `rate_limited`; `GATEWAY_REGISTER_LIMIT_PER_IP`, `_PER_EMAIL`) |
| POST | `/auth/{realm}/resend-verification` | — | **realm başına açılır** (`VERIFYURL` ya da `RESENDVERIFICATION=true`; değilse 404 `realm_feature_disabled`). `{email, locale?}` → her zaman 202 (adresin kayıtlı olup olmadığını açığa vurmaz); e-posta başına dakikada 1, saatte 5 |
| POST | `/auth/{realm}/verify-email` | — | `{token}` → 204 (zaten onaylıysa da 204) / 410 `verify_token_invalid`; sonra istemci `/refresh` ile `email_verified` claim'ini tazeler |
| POST | `/auth/{realm}/forgot-password` | — | `{email, locale?}` → her zaman 202; parolalı hesaba sıfırlama bağlantısı, parolasız (Google/Apple) hesaba "sağlayıcınla giriş yap" e-postası |
| POST | `/auth/{realm}/reset-password/check` | — | `{token}` → 204 / 410 `reset_token_invalid` (form açılmadan "bağlantının süresi doldu" ekranı) |
| POST | `/auth/{realm}/reset-password` | — | `{token, newPassword}` → 200 token yanıtı (bu cihazda yeni oturum) / 204 (parola değişti, giriş yapılamadı) / 400 `password_policy` / 410 `reset_token_invalid` / 503 `sessions_revoke_failed` |
| POST | `/auth/{realm}/social` | — / Bearer | `{code, redirectUri, mode?}` → token (kc_idp_hint ile alınan code). `mode` yok ya da `login`: giriş. `mode: "link"` (Bearer zorunlu, **realm başına açılır**, bkz. Giriş yöntemleri): sağlayıcıyı oturumdaki hesaba bağlar |
| POST | `/auth/{realm}/logout` | Bearer | `{refreshToken}` |
| GET | `/auth/{realm}/me` | Bearer | Kullanıcı bilgisi |
| PATCH | `/auth/{realm}/me` | Bearer | `{firstName, lastName}` |
| POST | `/auth/{realm}/change-password` | Bearer | `{currentPassword, newPassword}` |
| GET | `/auth/{realm}/identities` | Bearer | **realm başına açılır** (`IDENTITYMETHODS=true`; değilse 404 `realm_feature_disabled`). → `{password: boolean, providers: [{alias, email}]}` (`alias`: `google`/`apple`; `email` sağlayıcı hesabının adresi, paylaşmadıysa `null`) |
| DELETE | `/auth/{realm}/identities/{alias}` | Bearer | **realm başına açılır**. Sağlayıcı bağını kaldırır → 204 (bağlı değilse de 204); başka giriş yolu kalmıyorsa (parola yok, tek sağlayıcı) 409 `last_method` |

Bearer gerektiren çağrılarda token'ın `iss` değeri path'teki realm'e ait olmalıdır; aksi halde 403.
Bilinmeyen realm 404 döner; bilinmeyen yol 404 `not_found` (Bearer'sız istekte önce 401). Hatalar: 401 hatalı kimlik bilgisi/token, 403 doğrulanmamış veya devre dışı hesap,
400 parola politikası/geçersiz veri, 409 kullanıcı zaten var, 503 Keycloak erişilemiyor veya client yapılandırması hatalı.

Hata gövdesi `{success:false, error:{timestamp, status, error, message, path, code?, validationErrors?, email?}}`. `code`
istemci çevirisi içindir ve yalnız kodu olan hatalarda bulunur (eski hatalarda alan yoktur); `email` yalnız
`account_exists_unverified`'da:

| `code` | Durum | Anlam |
| --- | --- | --- |
| `password_policy` | 400 | Parola realm politikasına uymuyor; `validationErrors.newPassword` reddedilen kural (`length`, `digits`, `lowerCase`, `upperCase`, `specialChars`, `passwordHistory`, `notUsername`, `notEmail`, `policy`) |
| `reset_token_invalid` | 410 | Sıfırlama bağlantısı süresi dolmuş, kullanılmış (parola değişti), değiştirilmiş ya da başka realm'in/amacın |
| `verify_token_invalid` | 410 | Onay bağlantısı geçersiz ya da hesabın e-postası değişmiş |
| `rate_limited` | 429 | Belirteç uçlarında (`reset-password`, `reset-password/check`, `verify-email`) IP başına saatte 20 ya da kayıt sınırı aşıldı |
| `sessions_revoke_failed` | 503 | Parola **değişti** ama diğer oturumlar/offline token'lar kapatılamadı (iki deneme); yeni oturum açılmaz. İstemci: "Parolan değişti ama diğer cihazlardaki oturumlar kapatılamadı. Yeni bağlantı isteyip tekrar dene ya da destekle iletişime geç." Yeniden deneme yolu: `forgot-password` → yeni bağlantı → yeni parolayla `reset-password` (eski bağlantı parola değiştiği için 410; sıfırlama oturum kapatmayı yeniden yapar) |
| `realm_feature_disabled` | 404 | Realm'de bu özellik açık değil (`RESETURL` / `VERIFYURL` tanımsız; giriş yöntemi uçlarında `IDENTITYMETHODS` kapalı) |
| `last_method` | 409 | `DELETE identities/{alias}`: kalan tek giriş yöntemi (parola yok, başka sağlayıcı yok) |
| `identity_in_use` | 409 | `social` `mode=link`: sağlayıcı hesabı başka bir mevcut kullanıcıya ait; oturumdaki kullanıcıya dokunulmaz |
| `identity_mismatch` | 409 | `social` `mode=link`: kod başka bir kullanıcıya çözüldü ve Keycloak onu bu girişte açmıştı (farklı e-postalı sağlayıcı hesabı); o kullanıcı silinir |
| `account_exists_unverified` | 409 | `social` girişi: bu e-postayla parolalı ama e-postası onaylanmamış hesap var; gövdede `email`. İstemci: "Bu e-postayla bir hesap var" → parolayla giriş, sonra Profil › Giriş yöntemi'nden bağlama |
| `invalid_mode` | 400 | `social` `mode` `login`/`link` değil (yalnız giriş yöntemleri açık realm'de; kapalı realm'de `mode` eskisi gibi yok sayılır) |
| `not_found` | 404 | Bu yolda uç yok |

E-posta alan uçlar (`forgot-password`, `resend-verification`) sınır aşılsa da 202 döner, yalnız e-posta gitmez:
`forgot-password` e-posta başına saatte 3, IP başına saatte 10; `resend-verification` IP başına saatte 20. Kullanıcı
araması ve gönderim arka planda yapılır; yanıt (ve süresi) adresin kayıtlı olup olmadığını göstermez. Sınırlar pod
belleğindedir (tek replika; en çok 50 000 anahtar, LRU); IP, Traefik'in `X-Forwarded-For`'a eklediği son değerdir, IPv6
adresleri /64 önekiyle sayılır.

Aynı bağlantıyla eşzamanlı istekler kullanıcı başına kilitle sıraya girer ve parmak izi kilit içinde yeniden denetlenir:
parola bir kez değişir, diğerleri 410 alır (`verify-email` de aynı). Yönetim istemcisinin token'ı realm başına, süresi
dolmadan 30 sn öncesine kadar önbellekte tutulur.

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
| `KEYCLOAK_IDENTITY_METHODS` | `false` — `true`: varsayılan realm'de giriş yöntemi uçları (ek realm'lerdeki `GATEWAY_REALMS_<REALM>_IDENTITYMETHODS` gibi) |
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
| `GATEWAY_REALMS_<REALM>_IDENTITYMETHODS` | `false` — `true`: `GET/DELETE /auth/<realm>/identities`, `/social` `mode=link` ve sosyal girişte onaysız hesap denetimi (bkz. Giriş yöntemleri) |

Keycloak client'ları `talay-identity` modülünde `gateway_client_enabled = true` ile oluşturulur. Secret'lar
Vault `kv/apps/todogi/keycloak` path'indedir ve ExternalSecret ile env olarak gelir.

## Giriş yöntemleri

Realm başına açılır (`KEYCLOAK_IDENTITY_METHODS` / `GATEWAY_REALMS_<REALM>_IDENTITYMETHODS`). Kapalıyken `identities` uçları
ve `/social` `mode: "link"` 404 `realm_feature_disabled`; `/social` `mode`suz ya da `mode: "login"` (başka değer de) aynen
eski davranış — Keycloak admin API'sine hiç gidilmez.

Açıkken:

- **Liste / kaldırma:** admin API `users/{sub}/credentials` (`password` türü) ve `users/{sub}/federated-identity`. Kaldırma
  kullanıcı başına kilitle sıralanır (iki paralel kaldırma son iki yöntemi birden götüremez).
- **Bağlama (`mode: "link"`, Bearer):** istemci kodu, girişteki gibi `kc_idp_hint=<alias>` ile alır. Kodun açtığı oturumun
  `sub`'ı Bearer'daki kullanıcıysa 200 + yeni oturumun token'ları (Keycloak'ın ilk aracı girişi aynı e-postalı hesaba
  kendisi bağlar). Başka kullanıcıysa yeni oturum kapatılır, token'ları istemciye verilmez ve oturumdaki kullanıcıya
  dokunulmaz: o kullanıcıyı Keycloak bu girişte açmışsa (≤ 60 sn, tek oturum, parolasız, tek sağlayıcı) silinir →
  409 `identity_mismatch`; değilse 409 `identity_in_use`. Sağlayıcının adresi hesabın adresiyse hesabın e-postası onaylı
  sayılır (`emailVerified=true`; realm sağlayıcının e-postasına güvenir).
- **Sosyal girişte onaysız hesap:** talay-identity'nin ilk aracı giriş akışı (`social-first-login`: e-posta benzersizse
  kullanıcı aç, değilse aynı e-postalı hesaba otomatik bağla) e-postası **onaylanmamış** parolalı hesaba da bağlar ve
  istemciye kod döner (Keycloak 26.7.3'te IT ile gözlendi; yönlendirmede `error=` yok). Gateway kodu değiştirdikten sonra
  hesaba bakar: parolası var, e-postası onaysız ve sağlayıcı bağı varsa bağlar kaldırılır, yeni oturum kapatılır, 409
  `account_exists_unverified` + `email`. İkinci kullanıcı açılmaz; parolayla giriş ve sonra `mode=link` yolu açık kalır.
  Denetim yapılamazsa (admin API hatası) oturum yine kapatılır, 503.
- **Keycloak gereksinimi:** yönetim istemcisinin service account'unda `realm-management` `view-users` (liste, oturumlar)
  ve `manage-users` (bağ kaldırma, kullanıcı silme/güncelleme) — talay-identity `gateway_client_enabled` bunları zaten
  verir. Sağlayıcı takma adları (`google`, `apple`) ve `trust_email` talay-identity'dedir.

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
| `FROM` yok | O realm'e gateway e-postası gitmez (hoş geldin dahil). `RESETURL` tanımlıysa şifremi unuttum kapalı kalır; `VERIFYURL` tanımlıysa doğrulama Keycloak e-postasına düşer (eski davranış). İkisi de açılışta hata logu ve `auth_gateway_feature_degraded{realm, feature}=1` |
| SMTP / `GATEWAY_ACTION_TOKEN_SECRETS` yok | `FROM` yokmuş gibi |
| `RESENDVERIFICATION=true` | `VERIFYURL`'siz realm'de `resend-verification` Keycloak e-postasıyla açılır |

E-postalarda ad yalnız e-postası doğrulanmış hesapta kullanılır ("Merhaba Can,"); hoş geldin ve doğrulama e-postaları
"Merhaba," ile başlar (adı kaydı yapan yazar, e-posta henüz kimsenin onaylamadığı adrese gider).

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
| `GATEWAY_MAIL_REALMS_<REALM>_RESENDVERIFICATION` | `resend-verification`'ı açar/kapatır; varsayılan: `VERIFYURL` varsa açık, yoksa kapalı |
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
result=ok|invalid|expired|policy|rate_limited|disabled|sessions_failed}` (`action` ayrıca `register` için
`rate_limited`), `auth_gateway_mail_sent_total{realm, template, result=ok|error|disabled}`,
`auth_gateway_account_tasks_rejected_total` (kuyruk dolu, e-posta düştü), `auth_gateway_feature_degraded{realm, feature}`,
`auth_gateway_identity_requests_total{realm, action=list|unlink|link|login, result=ok|disabled|invalid|not_linked|last_method|
mismatch|in_use|unverified|unauthenticated|error}` (`login`: giriş yöntemleri açık realm'de `/social` girişi).

## Testler

`./mvnw test` birim ve bileşen testleri; `./mvnw verify` ek olarak `*IT` entegrasyon testlerini koşar (Testcontainers ile
gerçek Keycloak `quay.io/keycloak/keycloak:26.7.3` + GreenMail SMTP; Docker yoksa atlanır, imaj `-Dit.keycloak.image=` ile
değişir). `IdentityMethodsIT` Google yerine ikinci bir realm'i (`fakegoogle`) `google` takma adlı OIDC sağlayıcısı olarak
bağlar ve kod akışını HTTP istemcisiyle sürer.

Request/response logları parola, token, secret ve API key alanlarını maskeler; e-posta adreslerini kısaltır.
