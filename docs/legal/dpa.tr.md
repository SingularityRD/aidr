# Veri İşleme Sözleşmesi (DPA)

> **TASLAK — hukuk/iş onayı gerekir.** Bu metin hukuk danışmanı, veri koruma
> sorumlusu ve iş sahibi tarafından onaylanmamıştır; imzaya açılmadan önce
> gözden geçirilmelidir. Alt işleyen listesi ve barındırma bölgeleri aday
> bilgidir; onaylı bir sunucu yerleşimi beyanı değildir
> ([veri yerleşimi](../deployment/data-residency.md)). İngilizce sürüm:
> [dpa.en.md](dpa.en.md). Sürüm: taslak 0.1, 14.10.2026.

## 1. Taraflar ve roller

Bu Veri İşleme Sözleşmesi ("DPA"), [Müşteri tam unvanı] ("Veri Sorumlusu") ile
SingularityRD [tam unvan, MERSİS — hukuk dolduracak] ("Veri İşleyen")
arasında, taraflar arasındaki Singularity AIDR Son Kullanıcı Lisans Sözleşmesi
ve Sipariş Formu ("Ana Sözleşme") kapsamında yapılır.

6698 sayılı Kişisel Verilerin Korunması Kanunu ("KVKK") bakımından Müşteri
veri sorumlusu, SingularityRD veri işleyendir. Müşteri AB'de yerleşik ya da AB
ilgili kişilerine hizmet veriyorsa Genel Veri Koruma Tüzüğü ("GDPR") madde 28
yükümlülükleri de bu DPA ile karşılanır.

## 2. Bu DPA'nın uygulandığı durumlar

Singularity AIDR, varsayılan olarak uç noktalarda yerel çalışır ve veri
göndermez. Veri İşleyen yalnız aşağıdaki durumlarda Müşteri adına kişisel veri
işler:

| Durum | Veri İşleyen ne işler | Ne zaman |
|---|---|---|
| A. Barındırılan kontrol sunucusu | Ek-1'deki kategoriler, barındırılan hizmetin süresi boyunca | Müşteri barındırılan hizmeti seçtiğinde |
| B. Destek | Müşterinin açıkça onayladığı destek paketi ve destek görüşmelerinde görülen bilgiler | Bir destek talebi süresince |
| C. Profesyonel hizmet | Kurulum ya da POC sırasında Müşteri ortamında görülen bilgiler | Hizmet süresince, Müşteri gözetiminde |

Kontrol sunucusunu Müşteri kendi sunucusunda (şirket içi ya da internetsiz)
işletiyorsa Veri İşleyen Müşterinin telemetrisine erişmez; bu durumda yalnız B
ve C uygulanır.

## 3. İşleme talimatları

Veri İşleyen kişisel verileri yalnız Ana Sözleşmenin ifası için ve Müşterinin
belgelenmiş talimatlarıyla işler. Ürün yapılandırması (mod, telemetri ayarları,
`redact_mode`, saklama süreleri, isteğe bağlı özellikler) ve destek talebindeki
yazılı onaylar talimat sayılır. Veri İşleyen, bir talimatın KVKK ya da GDPR'a
aykırı olduğunu düşünürse Müşteriyi gecikmeden bilgilendirir.

## 4. Gizlilik

Veri İşleyen, kişisel verilere erişen çalışan ve yüklenicilerinin yazılı
gizlilik yükümlülüğü altında olmasını ve erişimin görev gereğiyle sınırlı
kalmasını sağlar.

## 5. Güvenlik önlemleri

Veri İşleyen, KVKK madde 12 ve GDPR madde 32 uyarınca Ek-2'deki teknik ve idari
tedbirleri uygular. Tedbirler ürünün gelişimine göre güncellenebilir; koruma
düzeyi düşürülmez. Ek-2'de "planlanan" olarak işaretli tedbirler henüz
uygulanmamıştır ve uygulanmış gibi sunulmaz.

## 6. Alt işleyenler

Müşteri, Ek-3'teki alt işleyenlerin kullanımına bu DPA ile genel izin verir.
Veri İşleyen yeni bir alt işleyen eklemeden ya da değiştirmeden en az 30 gün
önce Müşteriyi yazılı olarak bilgilendirir; Müşteri bu sürede makul gerekçeyle
itiraz edebilir. İtiraz çözülemezse Müşteri etkilenen hizmeti kıst iade ile
sonlandırabilir. Veri İşleyen, alt işleyenlerine bu DPA'dakilerle eşdeğer
yükümlülükler yükler ve onların fiillerinden Müşteriye karşı sorumludur.

## 7. Yurt dışına aktarım

Kişisel veriler yalnız KVKK madde 9 (ve gerektiğinde GDPR Bölüm V) uyarınca
aktarılır: yeterlilik kararı, Kurulca ilan edilen standart sözleşme (imzadan
itibaren 5 iş günü içinde Kurula bildirimi yapılarak), bağlayıcı şirket
kuralları ya da Kurul izni. Hangi akışın hangi araca dayandığı Ek-3'te yazılır.
Yurt dışına aktarım istemeyen Müşteriler için önerilen çözüm, kontrol
sunucusunu Türkiye'deki kendi altyapılarında işletmektir
([veri yerleşimi](../deployment/data-residency.md)).

## 8. İlgili kişi talepleri

Veri İşleyen, ilgili kişilerin KVKK madde 11 ve GDPR haklarına ilişkin
başvurularını Müşteriye iletir ve kendisi yanıtlamaz. Müşterinin bu taleplere
yanıt vermesine, ürünün dışa aktarma, silme ve kiracı kapatma araçlarıyla makul
ölçüde yardım eder.

## 9. Veri ihlali bildirimi

Veri İşleyen, kişisel verileri etkileyen bir güvenlik ihlalini öğrendiğinde
Müşteriyi gecikmeksizin ve en geç **[24] saat** içinde bilgilendirir. Bildirim
en az şunları içerir (bilindiği ölçüde): ihlalin niteliği, etkilenen veri ve
kişi kategorileri ile yaklaşık sayıları, olası sonuçlar, alınan ve önerilen
tedbirler, irtibat kişisi. Müşterinin KVKK uyarınca Kurula 72 saat içinde ve
ilgili kişilere bildirim yükümlülüğünü yerine getirmesine yardım eder. Bildirim
ihlalin kabulü anlamına gelmez.

## 10. Denetim

Veri İşleyen, bu DPA'ya uyumu göstermek için gerekli bilgileri (bu DPA'nın
ekleri, güvenlik beyaz kağıdı, varsa bağımsız denetim ya da sızma testi
raporları) Müşteriye verir. Bugün itibarıyla bağımsız bir denetim raporu,
sertifika ya da tamamlanmış sızma testi **yoktur**. Müşteri, 30 gün önceden
yazılı bildirimle, yılda en fazla bir kez, iş saatlerinde ve gizlilik
taahhüdüyle denetim yapabilir ya da bağımsız bir denetçi atayabilir; masrafları
Müşteriye aittir, ihlal tespit edilirse Veri İşleyene aittir.

## 11. Süre, iade ve silme

Bu DPA, Ana Sözleşme süresince ve Veri İşleyen Müşteri adına kişisel veri
işlediği sürece yürürlüktedir. Barındırılan hizmetin sona ermesinde Veri İşleyen,
Müşterinin seçimine göre verileri [30] gün içinde dışa aktarma araçlarıyla iade
eder ve ardından kiracı kapatma (offboarding) süreciyle siler; yedeklerden
silme, yedeklerin olağan saklama süresi sonunda gerçekleşir. Hukuken saklanması
zorunlu kayıtlar ve Müşterinin koyduğu yasal saklama (legal hold) kayıtları
süresi dolana kadar saklanır. Destek paketleri talebin kapanmasından sonra
[30] gün içinde silinir ve silme talepte kayıt altına alınır.

## 12. Sorumluluk ve öncelik

Sorumluluk Ana Sözleşmedeki sınırlamalara tabidir; hukuken sınırlandırılamayan
sorumluluk saklıdır. Bu DPA ile Ana Sözleşme arasında veri koruma konusunda
çelişki olursa bu DPA uygulanır.

---

## Ek-1: İşlemenin ayrıntıları

| Konu | Barındırılan kontrol sunucusu (A) | Destek (B) |
|---|---|---|
| İşleme amacı | Uç noktaların merkezi yönetimi: cihaz kaydı, politika dağıtımı, olay ve karar görünürlüğü, onay iş akışı, denetim kaydı, uyum raporu | Müşterinin bildirdiği bir sorunun teşhisi ve çözümü |
| İşleme faaliyetleri | Toplama (uç noktadan ve panelden), saklama, görüntüleme, dışa aktarma, silme | Müşterinin onayladığı paketi alma, inceleme, silme |
| İlgili kişi grupları | Müşterinin çalışanları ve yüklenicileri (geliştiriciler, yöneticiler, SOC analistleri, onaylayıcılar) | Aynı; destek talebini açan kişi |
| Kişisel veri kategorileri | Kimlik/iletişim: e-posta, ad, IdP kullanıcı ve grup kimlikleri. İşlem güvenliği: kurulum ve cihaz kimlikleri, oturum ve faktör kayıtları, denetim kayıtları. Kullanım: AI aracındaki karar olayları (araç adı, karar, eşleşen kural, zaman damgası; araç özeti ve eserler varsayılan `hash` modunda SHA-256 özeti olarak), Browser Guard sayaçları (site, eylem, tür başına sayı; istem metni yok). | Destek paketindeki izin listeli tanılama özeti (sürümler, sağlık denetimleri, kural özetleri); destek yazışmasındaki iletişim bilgileri |
| Özel nitelikli veriler | Amaçlanmaz. Ürün bunları toplamak için tasarlanmamıştır; Müşteri, araç girdilerinde bulunabilecek özel nitelikli verilerin karma (hash) modunda kalmasından ve `redact_mode: none` kullanmamaktan sorumludur. | Amaçlanmaz; destek paketi bunları dışlayacak şekilde tasarlanmıştır |
| Gönderilmeyenler | Kaynak kod, dosya içerikleri, tam istemler, Browser Guard'ın maskelediği değerler ([privacy.md](../privacy.md)) | Ortam dosyaları, günlükler, istemler, kimlik bilgileri ([destek paketi](../runbooks/support-bundle.md)) |
| Saklama süresi | Kiracının saklama politikası (edisyona göre 7/90/365 gün ya da sözleşmeye bağlı); yasal saklama korunur | Talebin kapanmasından sonra [30] gün |
| Süre | Ana Sözleşme süresi | Talep süresi |

## Ek-2: Teknik ve idari tedbirler (TOMs)

Durum sütunu: **Uygulanıyor** = ürün kaynak kodunda var ve testleri depoda;
**Müşteri** = Müşterinin kendi ortamında uygulaması gerekir; **Planlanan** =
henüz yok. "Uygulanıyor", bağımsız bir doğrulama anlamına gelmez.

| # | Alan | Tedbir | Durum |
|---|---|---|---|
| 1 | Veri en aza indirme | Varsayılan yerel mod: tespit ağ erişimi olmadan uç noktada yapılır | Uygulanıyor |
| 2 | Veri en aza indirme | Uç noktadan çıkan olaylarda zorunlu kimlik bilgisi temizliği; varsayılan `redact_mode: hash` araç özetlerini ve eserleri SHA-256 özeti ile değiştirir; sunucu tarafında izin listeli alan projeksiyonu | Uygulanıyor |
| 3 | Veri en aza indirme | Browser Guard yalnız sayaç gönderir; istem metni, maskelenmiş metin, değerler ve sayfa adresleri gönderilmez | Uygulanıyor |
| 4 | Erişim denetimi | Her kiracı tablosunda satır düzeyinde güvenlik (RLS); kiracı üyeliği ve rol denetimi | Uygulanıyor |
| 5 | Erişim denetimi | Roller (sahip, yönetici, üye, görüntüleyici), denetimli rol değişiklikleri | Uygulanıyor |
| 6 | Kimlik doğrulama | SAML / OIDC tek oturum açma, SCIM ile kullanıcı yaşam döngüsü, yerel hesaplarda MFA ve kurtarma kodları | Uygulanıyor (Müşteri IdP kabulü gerekir) |
| 7 | Kimlik bilgisi saklama | Kiracı API anahtarları yalnız özet (hash) olarak saklanır; uç noktada kimlik bilgisi işletim sistemi kasasında | Uygulanıyor |
| 8 | Bütünlük | Ed25519 imzalı sürüm bildirimleri, politika, algılayıcı paketleri, kural/istihbarat paketleri ve çevrimdışı lisans; imza anahtarları uç noktalara dağıtılmaz | Uygulanıyor (üretim anahtarlarının oluşturulması ve saklanması insan işi, açık) |
| 9 | Bütünlük | Uç noktada isteğe bağlı, SHA-256 zincirli ve Ed25519 imzalı denetim kaydı | Uygulanıyor (isteğe bağlı) |
| 10 | Aktarım güvenliği | Kontrol sunucusuna HTTPS/TLS; şirket içinde servisler yalnız loopback'e bağlanır, TLS Müşterinin girişinde sonlanır | Uygulanıyor / Müşteri |
| 11 | Saklama güvenliği | Barındırma ortamının disk şifrelemesi | Barındırılan: sağlayıcı (onaylanacak) / Şirket içi: Müşteri |
| 12 | Yedekleme | Şifreli yedek, ayrı hedefe kopya, geri yükleme tatbikatı araçları | Uygulanıyor (araç) / tatbikat kanıtı Müşteri ya da işletmeci |
| 13 | Saklama ve silme | Kiracı başına saklama süresi, yasal saklama, kiracı kapatmada kayıtlı silme | Uygulanıyor |
| 14 | Kayıt ve izleme | Yönetici işlemleri, kayıt, davet, rol ve politika değişikliklerinin denetim kaydı; denetim dışa aktarımı; SIEM iletimi | Uygulanıyor |
| 15 | Hizmet sürekliliği | Kontrol sunucusuna ulaşılamadığında uç noktalar yerel tespite devam eder | Uygulanıyor |
| 16 | Ayrım | Kiracılar arası negatif testler (Postgres üzerinde) | Uygulanıyor (canlı iki kiracı testi açık) |
| 17 | Güvenli geliştirme | Kod incelemesi, otomatik testler, gizli bilgi taraması, bağımlılık denetimi | Uygulanıyor |
| 18 | Bağımsız güvenlik değerlendirmesi | Sızma testi ([kapsam/RFP](../security/pentest-scope-rfp.md)) | **Planlanan — yapılmadı** |
| 19 | Personel | Gizlilik taahhüdü, görev gereği erişim, işten çıkışta erişim kaldırma | Planlanan (yazılı politika gerekir) |
| 20 | Olay yönetimi | Olay müdahale runbook'u, nöbet ve bildirim süreci | Runbook var; nöbet listesi planlanan ([destek süreci](../runbooks/support-process.md)) |
| 21 | Destek erişimi | Müşteri onaylı, izin listeli destek paketi; tam zamanında, süreli destek erişimi | Uygulanıyor (araç) / süreç planlanan |
| 22 | Fiziksel güvenlik | Barındırılan hizmette veri merkezi sağlayıcısının fiziksel güvenliği | Sağlayıcı (onaylanacak) |

## Ek-3: Alt işleyenler (aday — onaylanmadı)

Yalnız barındırılan kontrol sunucusu (Durum A) için geçerlidir. Şirket içi
kurulumda Veri İşleyenin alt işleyeni yoktur; Müşterinin kendi seçtiği
sağlayıcılar (SMTP, IdP, SIEM, yedek hedefi) Müşterinin işleyenleridir.

| Alt işleyen | Amaç | Konum (bilinen) | Aktarım aracı | Durum |
|---|---|---|---|---|
| Supabase Inc. | Veritabanı, kimlik doğrulama, depolama, sunucu fonksiyonları | Pilot projesi `eu-central-1` (Frankfurt); fonksiyonlar istek yapana yakın çalışabilir | [standart sözleşme / Kurul bildirimi — hukuk] | Aday |
| Cloudflare, Inc. | İstek iletimi (pilot Worker, `workers.dev`) | Küresel; bölgesel kısıtlama yok | [hukuk] | Aday (pilot) |
| Resend ya da onaylanacak başka bir e-posta sağlayıcısı | Davet, kurtarma ve uyarı e-postaları | ABD (sağlayıcı teyidi gerekir) | [hukuk] | Aday |
| Functional Software, Inc. (Sentry) | Hata tanılama | Yalnız açıkça etkinleştirilirse | [hukuk] | Varsayılan kapalı |

Bu liste, barındırılan hizmetin üretim hücresi kurulup bölgesi doğrulandığında
kesinleşir. Bugün bilinen tek olgu, pilot projesinin birincil bölgesinin
`eu-central-1` olduğudur.
