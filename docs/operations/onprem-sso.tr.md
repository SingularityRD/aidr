# Kurum içi tek oturum açma: Keycloak, ADFS, Active Directory / LDAP

English: [onprem-sso.md](onprem-sso.md)

Bu runbook, kurum içinde çalışan AIDR kontrol sunucusunu (`scripts/deployment-prepare.mjs`
ile hazırlanan Docker Compose kurulumu ya da Helm chart) müşterinin kendi ağındaki
kimlik sağlayıcıya bağlar. Kapsadığı konular:

- Keycloak, ADFS ya da standartlara uyan herhangi bir OpenID Connect sağlayıcısıyla
  çalışma alanı (tenant) **OIDC** oturum açma; TLS sertifikası iç CA tarafından
  verilmiş ve özel (private) IP adresinde çalışan sağlayıcılar dahil;
- **anında hesap oluşturma (JIT)**: AIDR, kullanıcı ilk kez oturum açtığında
  çalışma alanı üyeliğini oluşturur ve rolü kullanıcının kimlik sağlayıcıdaki
  gruplarıyla uyumlu tutar; SCIM istemcisi gerekmez;
- Keycloak kullanıcı federasyonu üzerinden **Active Directory / LDAP**
  (AIDR'ın kendi LDAP istemcisi yoktur ve bilinçli olarak eklenmemiştir);
- kurum içi GoTrue (`auth` servisi) üzerinde **SAML**.

OIDC oturum açmanın protokol ve güvenlik tasarımı
[oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md) belgesindedir. Orada
listelenen güvenlik özelliklerinin hepsi (PKCE, tek kullanımlık state, imza ve
claim denetimleri, DNS ile doğrulanmış alan adları, sağlayıcıya bağlı kimlikler,
zorunlu kılma ve acil durum erişimi) aşağıdaki sağlayıcılar için de aynen geçerlidir.

## Yol seçimi

| Elinizde olan | Kullanın | Kullanıcı ve roller şuradan gelir |
| --- | --- | --- |
| AD / LDAP var, kimlik sağlayıcı yok | LDAP federasyonlu Keycloak, sonra OIDC + JIT | Keycloak grup eşleyicisi üzerinden AD grupları |
| Keycloak | OIDC + JIT | Keycloak grupları ya da realm rolleri |
| ADFS 2016 ya da daha yenisi | OIDC + JIT (önerilen) | ADFS claim kurallarıyla AD grupları |
| SCIM istemcisi olan bir sağlayıcı (Entra ID, Okta) | OIDC ya da SAML + SCIM | SCIM grupları ([scim-directory-admin.md](../production-readiness/scim-directory-admin.md)) |
| Yalnızca SAML | GoTrue SAML + SCIM | SCIM grupları; SAML oturumu tek başına üyelik vermez |

JIT yalnızca OIDC ile çalışır. SAML ile oturum açan kullanıcının üyeliğini yine SCIM oluşturur.

## 1. Kontrol sunucusunu hazırlama

Üç ayarın üçü de isteğe bağlıdır. Verilmezlerse kurulum öncekiyle birebir aynı
hazırlanır ve OIDC istekleri yalnızca 443 numaralı porttaki herkese açık HTTPS
uç noktalarına gidebilir.

### Docker Compose (`deployment-prepare`)

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr ... \
  --idp-ca-file /secure-delivery/corp-root-ca.pem \
  --oidc-internal-idp-hosts sso.corp.example:8443 \
  [--with-saml]
```

- `--idp-ca-file`, kimlik sağlayıcının TLS sertifikasını imzalayan CA
  sertifikalarını (kök ve gerekirse ara CA) içeren bir PEM dosyası alır. Hazırlama;
  özel anahtar, sertifika dışı PEM blokları ve süresi dolmuş sertifikaları reddeder,
  paketi `functions-trust/idp-ca.pem` olarak yazar (izin 0644), `functions`
  kapsayıcısına salt okunur bağlar ve `DENO_TLS_CA_STORE=mozilla,system` ile
  `SSL_CERT_FILE=/etc/aidr/idp-ca.pem` ayarlarını yapar. Sabitlenmiş Edge çalışma
  ortamı böylece herkese açık Mozilla köklerine **ek olarak** sizin CA'nıza güvenir;
  hiçbir şey değiştirilmez. Paketin SHA-256 özeti ve konuları `deployment.json`
  içinde (`identity.idp_ca`) kaydedilir.
- `--oidc-internal-idp-hosts`, virgülle ayrılmış tam nitelikli `host[:port]`
  adlarının listesidir (en fazla 16, IP adresi ve joker karakter yok).
  `.env.functions` içindeki `AIDR_OIDC_INTERNAL_IDP_HOSTS` değişkenine yazılır.
  Özel adreslere (10/8, 172.16/12, 192.168/16, 100.64/10, IPv6 ULA) yalnızca bu
  adlar ve yalnızca listelenen porttan (port yazılmazsa 443) gidilebilir. Loopback,
  link-local ve metadata adresleri, düz HTTP ve yönlendirmeler hiçbir ad için kabul
  edilmez. Hatalı bir değer yazılırsa `oidc-sso` fonksiyonu her isteğe
  `server_misconfigured` yanıtı verir; böylece yazım hatası politikayı sessizce
  değiştirmek yerine hemen fark edilir.
- `--with-saml`, GoTrue'da SAML'ı açar ve RSA-2048 imzalama anahtarını **bu
  makinede** üretir (`.env` içinde `GOTRUE_SAML_PRIVATE_KEY`, izin 0600).
  Bkz. [bölüm 6](#6-kurum-içi-gotrueda-saml).

Oturum açma sayfasında iş e-postasıyla SSO formunu göstermek için `/srv/aidr/.env`
dosyasına `AIDR_OIDC_SSO=true` yazın ve paneli yeniden başlatın
(`docker compose ... up -d dashboard`).

`functions` kapsayıcısı kimlik sağlayıcıya erişebilmeli ve adını çözebilmelidir.
Compose, sunucunun DNS çözücülerini kullanır. Sunucudan şu komutla deneyin:
`curl --cacert corp-root-ca.pem https://sso.corp.example:8443/realms/corp/.well-known/openid-configuration`.

Ayarları sonradan değiştirmek için `functions-trust/idp-ca.pem` dosyasını ya da
`.env.functions` içindeki `AIDR_OIDC_INTERNAL_IDP_HOSTS` değerini düzenleyip
`docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d functions`
komutunu çalıştırın.

### Kubernetes (Helm)

```yaml
functions:
  identityProvider:
    caBundle:
      existingConfigMap: corp-idp-ca   # kubectl create configmap corp-idp-ca --from-file=ca.crt=corp-root-ca.pem
      key: ca.crt
    internalHosts: ["sso.corp.example:8443"]
networkPolicy:
  identityProviderEgress:
    - { cidr: 10.20.30.40/32, port: 8443 }
dashboard:
  oidcSso: true
```

`identityProviderEgress`, functions pod'ları için yalnızca listelenen adresi ve
portu açar; `functionsEgressCIDRs` yine yalnızca 443 numaralı portu kapsar.

## 2. Çalışma alanını panelden yapılandırma

MFA (AAL2) ile oturum açmış bir çalışma alanı sahibi olarak **Tek oturum açma**
sayfasını açın:

1. **Sağlayıcı**: tür olarak *Genel OpenID Connect*, aşağıdaki runbook'taki issuer,
   istemci kimliği, istemci doğrulama yöntemi ve gizli anahtar referansı. İstemci
   gizli anahtarını `.env.functions` içine `AIDR_OIDC_CLIENT_SECRET_<REF>` olarak
   yazın; operatör `<REF>` değerini `AIDR_OIDC_CLIENT_SECRET_BINDINGS` içinde bu
   çalışma alanına ve issuer'a bağlamalıdır (bkz.
   [oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md#deployment-configuration)).
   Grup claim'i: `groups` (ya da sizin belirlediğiniz ad). Grup şartı:
   **Grupları yok say**. Ek kapsamlar: ADFS için `allatclaims`, Keycloak için boş.
   **Kaydet ve doğrula** dediğinizde keşif belgesi o anda alınıp denetlenir; CA ve
   adres ayarları bu adımda sınanmış olur.
2. **Alan adları**: kullanıcıların e-posta alan adını ekleyin, iç DNS'inizde
   `_aidr-sso.<alan-adı>` TXT kaydını yayınlayın ve **Doğrula**'ya basın. JIT,
   doğrulanmış alan adı dışındaki bir adres için asla hesap oluşturmaz.
3. **Anında hesap oluşturma (JIT)**: *Oturum açılırken üye oluştur* kutusunu
   işaretleyin, izin verilen e-posta alan adlarını yazın (her biri doğrulanmış
   olmalı), grupları hiçbir eşlemeye uymayan kullanıcılar için rolü seçin (en
   güvenlisi *Erişim yok*) ve grup değerlerini her satıra bir tane olacak şekilde
   rollere eşleyin: `/aidr/admins=admin`, `/aidr/users=member`. Eşleşme tam ve
   büyük-küçük harfe duyarlıdır, en yüksek rol geçerlidir ve `owner` (sahip) rolü
   asla verilmez.
4. Gizli bir tarayıcı penceresinden bir deneme kullanıcısıyla oturum açın, üyeliği
   **Üyeler** sayfasında kontrol edin, ardından
   [oidc-sso-admin.md](../production-readiness/oidc-sso-admin.md) belgesindeki
   sahip hesabı bağlama ve zorunlu kılma adımlarını izleyin.

### JIT nasıl davranır

- **İlk oturum açma**: eşlenen rol (ya da varsayılan rol) ile üyelik oluşturulur.
  Denetim kaydı: `identity.oidc.jit_provisioned`.
- **Sonraki oturumlar**: rol, kullanıcının o anki gruplarına göre güncellenir
  (`identity.oidc.jit_role_changed`). Grupları artık hiçbir eşlemeye uymayan ve
  varsayılan rolü olmayan kullanıcı o oturum açışta üyeliğini kaybeder
  (`identity.oidc.jit_membership_revoked`) ve içeri alınmaz.
- **AIDR'da çıkarma**: bir yönetici Üyeler sayfasında bir JIT üyesini çıkarırsa
  kullanıcı dışarıda kalır; bir sahip **Yeniden kabul et** düğmesine basana kadar
  sonraki oturum açma girişimleri reddedilir (`not_provisioned`)
  (`identity.oidc.jit_readmitted`).
- **JIT'in dokunmadıkları**: sahipler, davetle ya da elle eklenmiş üyeler ve
  SCIM'in bildiği her kullanıcı. SCIM daha sonra bir JIT kullanıcısını
  oluşturursa üyelik SCIM'e devredilir (`identity.oidc.jit_handed_to_scim`).
  Dizin yetkili üyelik modu açıkken JIT açılamaz.
- **Güvenli tarafta kalan durumlar**: grup claim'inin hiç gelmemesi ya da taşması
  (overage), izin verilmeyen ya da doğrulanmamış alan adı, JIT ayarı kaydedildikten
  sonra issuer değerinin değişmesi ya da ayarın okunamaması durumlarında oturum
  açma reddedilir ve hiçbir şey değişmez; kesin neden
  `identity.oidc.login_failed` denetim kaydının ayrıntısındadır.
- **JIT'in yapmadıkları**: bir daha oturum açmayan kullanıcıyı görmez. AD'de bir
  kullanıcıyı devre dışı bırakmak yeni oturumları hemen durdurur; ancak açık bir
  AIDR oturumu `session_max_seconds` süresi (varsayılan 12 saat) dolana kadar
  sürer ve üyelik kaldırılana kadar kalır. Ayrılan çalışanları Üyeler sayfasından
  çıkarın; anında erişim kapatma gerekiyorsa SCIM kullanın.

## 3. Keycloak runbook'u

Keycloak 24 ve sonrası için geçerli ayarlar; adları kendi realm'inize göre uyarlayın.

1. **Realm**: kullanıcıların oturum açtığı realm, örneğin `corp`. Issuer
   `https://sso.corp.example:8443/realms/corp` olur
   (`/.well-known/openid-configuration` içindeki `issuer` değeriyle birebir aynı).
2. **İstemci**: *Clients → Create client*, tür **OpenID Connect**, istemci kimliği
   `aidr`. *Client authentication* **On** (gizli istemci), yalnızca *Standard flow*
   (implicit, direct access grants ve service accounts kapalı). *Valid redirect
   URIs*: `https://<panel>/auth/oidc/callback`; *Web origins*: panelin origin'i.
   *Advanced → Proof Key for Code Exchange* için **S256** seçin.
3. **Gizli anahtar**: *Credentials* sekmesindeki istemci gizli anahtarını
   `AIDR_OIDC_CLIENT_SECRET_<REF>` değişkenine yazın ve referansı yukarıda
   anlatıldığı gibi bağlayın.
4. **E-posta**: kullanıcıların doğrulanmış e-postası olmalıdır. LDAP federasyonunda
   `mail` özniteliğini eşleyin (bölüm 4); AIDR `email_verified=false` değerini
   reddeder.
5. **Grup claim'i**: *Client scopes → aidr-dedicated → Add mapper → By
   configuration → Group Membership*. Token claim adı `groups`, *Full group path*
   **On** (değerler `/aidr/admins` gibi görünür), *Add to ID token* **On**. Bu
   yolları AIDR'daki JIT bölümünde eşleyin.
6. **Grup yerine rol** (isteğe bağlı): token claim adı `roles` (nokta içermeyen,
   düz bir ad) olan bir *User Realm Role* eşleyicisi ekleyin, *Add to ID token*
   açık olsun; AIDR'daki grup claim adını `roles` yapın.
7. **İmza algoritması**: realm varsayılanı RS256, AIDR'ın varsayılanıyla aynıdır.
8. **Subject**: Keycloak'taki `sub`, kullanıcının değişmeyen Keycloak kimliğidir;
   AIDR'da subject claim'i `sub` olarak bırakın.

## 4. Keycloak üzerinden Active Directory / LDAP

AIDR doğrudan LDAP'a bağlanmaz. Keycloak AD'yi federasyonla bağlar, AIDR de
Keycloak'a güvenir.

1. *User federation → Add LDAP provider*. Vendor **Active Directory**, bağlantı
   adresi `ldaps://dc01.corp.example:636` (etki alanı denetleyicilerinin CA'sını
   Keycloak'ın truststore'una ekleyin), salt okunur bir servis hesabının bind DN
   değeri, kullanıcı DN'i örneğin `OU=Users,DC=corp,DC=example`.
2. *Edit mode* **READ_ONLY**; *Import users* açık; *Sync registrations* kapalı.
   Kullanıcı adı LDAP özniteliği `sAMAccountName` (ya da `userPrincipalName`),
   RDN `cn`, UUID `objectGUID`. İsteğe bağlı: masaüstü SSO için *Kerberos
   integration*.
3. Eşleyiciler: `email` → `mail`, `first name` → `givenName`, `last name` → `sn`.
   AD adreslerinin doğrulanmış sayılması için sağlayıcıda *Trust email* **On**
   olsun.
4. Bir **group-ldap-mapper** ekleyin: LDAP grupları DN'i
   `OU=Groups,DC=corp,DC=example`, mod **READ_ONLY**, *Membership attribute*
   `member`, iç içe gruplar için kullanıcı grupları alma stratejisi
   *LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY*. AD grupları böylece
   `/AIDR-Admins` gibi Keycloak grupları olarak görünür.
5. *Synchronize all users* çalıştırın ve değişen kullanıcılar için düzenli eşitleme
   ayarlayın (örneğin 15 dakikada bir). AD'de devre dışı bırakılan hesaplar artık
   Keycloak'ta oturum açamaz.
6. İçe aktarılan grup yollarını AIDR'daki JIT bölümünde eşleyin, örneğin
   `/AIDR-Admins=admin`, `/AIDR-Users=member`.

## 5. ADFS runbook'u (Windows Server 2016 ve sonrası)

1. *AD FS Management → Application Groups → Add*. Şablon: **Server application
   accessing a web API**. İstemci tanımlayıcısını (örneğin bir GUID) not alın.
   Yönlendirme URI'si `https://<panel>/auth/oidc/callback`.
2. *Configure application credentials*: **Generate a shared secret**; değeri
   `AIDR_OIDC_CLIENT_SECRET_<REF>` olarak saklayıp bağlayın (bölüm 2).
3. *Configure Web API*: tanımlayıcı, 1. adımdaki **istemci tanımlayıcısının
   aynısı** olmalıdır; böylece kimlik belirtecinin audience değeri AIDR istemci
   kimliği olur.
4. *Access control policy*: örneğin *Permit specific group* ile `AIDR-Users`.
5. *Configure application permissions*: `openid`, `email`, `profile` ve
   **`allatclaims`** kapsamları. ADFS özel claim'leri kimlik belirtecine yalnızca
   `allatclaims` istendiğinde koyar; AIDR sağlayıcısında *Ek kapsamlar:
   allatclaims* ayarı bu yüzden vardır.
6. *Web API → Issuance Transform Rules*:
   - *Send LDAP Attributes as Claims*: `E-Mail-Addresses` → `E-Mail Address`
     (belirteçte `email` olarak gelir).
   - Her AIDR grubu için *Send Group Membership as a Claim*, giden claim türü
     `Group`, değer örneğin `AIDR-Admins`; ya da tüm
     `Token-Groups - Unqualified Names` değerlerini `group` olarak gönderen özel
     bir kural. AIDR'daki grup claim adını ADFS'in ürettiği kısa ada ayarlayın
     (genellikle `group`; doğrulamak için bir deneme kimlik belirtecini çözün).
     Tek grup metin (string) olarak gelir; AIDR bunu kabul eder.
7. Issuer: `https://adfs.corp.example/adfs`
   (`https://adfs.corp.example/adfs/.well-known/openid-configuration` içindeki
   `issuer` değerini kontrol edin). ADFS kimlik belirteçlerini RS256 ile imzalar.
8. Subject: ADFS `sub` değeri istemci başına değişmeyen bir tanımlayıcıdır. AIDR'da
   subject claim'ini `sub` bırakın ve kullanıcılar oturum açtıktan sonra istemci
   tanımlayıcısını değiştirmeyin (kimlikler oluştuktan sonra kimlik alanı kilitlenir).
9. ADFS iç CA'dan alınmış bir sertifika kullanıyorsa hazırlamayı
   `--idp-ca-file` ve `--oidc-internal-idp-hosts adfs.corp.example` ile yapın.

## 6. Kurum içi GoTrue'da SAML

SAML'ı yalnızca SCIM ile birlikte kullanın: SAML oturumu kimliği kanıtlar, ancak
AIDR SAML kullanıcılarına üyeliği yalnızca SCIM üzerinden verir.

1. Compose için `--with-saml` ile hazırlayın; Helm için `auth.saml.enabled=true`
   ve `auth.saml.privateKeyKey` ayarlayın (anahtarı bir yönetici makinesinde
   `openssl genrsa 2048 | openssl rsa -outform DER | base64 -w0` ile üretip
   platform Secret'ına koyun).
2. Kimlik sağlayıcıya servis sağlayıcı metadata adresini verin:
   `https://<api>/auth/v1/sso/saml/metadata` (ACS:
   `https://<api>/auth/v1/sso/saml/acs`).
3. Kimlik sağlayıcıyı kurulum sunucusundan, loopback ağ geçidi üzerindeki GoTrue
   yönetim API'si ile kaydedin; servis rolü anahtarını `/srv/aidr/.env`
   dosyasından alın. GoTrue'nun kimlik sağlayıcıya erişmesi gerekmesin diye
   metadata'yı `metadata_xml` olarak satır içinde verin:

   ```sh
   curl -sS -X POST http://127.0.0.1:8000/auth/v1/admin/sso/providers \
     -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY" \
     -H "Content-Type: application/json" \
     --data "$(jq -n --rawfile xml FederationMetadata.xml \
       '{type:"saml", metadata_xml:$xml, domains:["corp.example"]}')"
   ```

   Dönen sağlayıcı `id` değerini not alın.
4. `/srv/aidr/.env` içine `AIDR_SAML_PROVIDER_ID=<id>` (birden fazlası için
   `AIDR_SAML_PROVIDERS`) yazın ve paneli yeniden başlatın. Kimlik sağlayıcıyı,
   SCIM `externalId` ile aynı olan kalıcı ve opak bir `NameID` gönderecek şekilde
   ayarlayın; ardından
   [scim-directory-admin.md](../production-readiness/scim-directory-admin.md)
   belgesini izleyin.

## 7. Sorun giderme

| Belirti (`oidc-sso` yanıt nedeni ya da `identity.oidc.login_failed` denetim ayrıntısı) | Neden ve çözüm |
| --- | --- |
| Kaydetme reddedildi, neden `discovery_private_address` | Kimlik sağlayıcı özel bir adrese çözülüyor ve `AIDR_OIDC_INTERNAL_IDP_HOSTS` içinde yok. |
| `discovery_blocked_host` | İç ad uzantısı (`.local`, `.corp`, `.lan`, tek etiketli ad) `AIDR_OIDC_INTERNAL_IDP_HOSTS` içinde yok. |
| `discovery_port_not_allowed` | Issuer listelenmemiş bir port kullanıyor (`host:8443`). |
| `discovery_network_error` | Çoğunlukla TLS: kimlik sağlayıcının sertifikası `--idp-ca-file` içindeki bir CA tarafından imzalanmamış; ya da DNS/güvenlik duvarı. |
| `discovery_issuer_mismatch` | AIDR'a yazılan issuer, belgedeki `issuer` değerinden farklı (sondaki eğik çizgi, port, realm). |
| Her `oidc-sso` çağrısı `server_misconfigured` yanıtı veriyor | `AIDR_OIDC_INTERNAL_IDP_HOSTS` hatalı yazılmış. |
| Oturum reddedildi, denetimde `jit_no_role` | Grup claim'i yok ya da hiçbir grup eşleşmiyor; eşleyicinin grupları **kimlik belirtecine** eklediğini ve ADFS'te `allatclaims` kapsamını kontrol edin. |
| Oturum reddedildi, denetimde `jit_domain_not_allowed` | E-posta alan adı JIT izin listesinde değil ya da doğrulanmamış. |
| Oturum reddedildi, denetimde `jit_removed_by_admin` | Kullanıcı AIDR'da çıkarılmış; bir sahibin yeniden kabul etmesi gerekir. |
| JIT açıkken oturum reddedildi, denetimde `jit_disabled` | JIT ayarı kaydedildikten sonra sağlayıcının issuer değeri değişmiş: JIT bölümünü yeniden kaydedin. |

## Müşteride canlıya almadan önce kabul

Yerel test takımları mantığı kanıtlar (`supabase/functions/__tests__/oidc-sso-jit.test.ts`,
`scripts/oidc-jit-provisioning-postgres.test.mjs`, `scripts/lib/onprem-sso.test.mjs`,
`deploy/helm/chart.test.mjs`). Bunlar canlı ortam kabulü değildir. Üretimde
güvenmeden önce, kurulmuş sürüm adayına karşı her kimlik sağlayıcı için (AD
federasyonlu Keycloak, ADFS) iç CA sertifikasıyla birer oturum açma denemesi yapın
ve maskelenmiş kanıtları saklayın: keşif belgesinin kaydedilmesi, ilk oturumda
hesap oluşturma, grup değişikliği, çıkarma ve yeniden kabul ile yukarıdaki denetim
kayıtları.
