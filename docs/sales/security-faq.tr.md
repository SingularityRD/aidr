# Singularity AIDR — Güvenlik SSS

[English](security-faq.md) · Bu sayfa İngilizce [security-faq.md](security-faq.md)
belgesinin Türkçesidir; iki metin ayrışırsa önce İngilizce sürüm güncellenir.

Güvenlik değerlendiricileri ve satın alma anketleri için yanıtlar. Her yanıt
dayandığı kaynağı ya da belgeyi gösterir. Bir şey yerinde değilse yanıt bunu
söyler. Singularity AIDR henüz müşteri kullanımı için yayımlanmamıştır
([first-customer-ready.md](../production-readiness/first-customer-ready.md));
bu yanıtlar uygulanmış tasarımı anlatır, kabul edilmiş bir üretim hizmetini
değil. Ayrıntılı tasarım: [güvenlik beyaz kağıdı](../security/whitepaper.md)
(taslak, İngilizce).

---

## Veri akışları

### Varsayılan olarak cihazdan ne çıkar?

Varsayılan `local` modda **tespit ağ erişimi gerektirmez**. Ajan bağlayıcıları
araç çağrılarını süreç içinde, paketle gelen kurallara göre değerlendirir;
Browser Guard tarayıcıda tarar ve maskeler. Dışa giden akışlar yalnız
açıldıklarında vardır:

| Akış | Varsayılan | Ne gönderilir | Kaynak |
| --- | --- | --- | --- |
| URL itibarı | Kapalı | URL (sunucu ve yol; sorgu yalnız açılırsa) | [privacy.tr.md](../privacy.tr.md) |
| Paket / dosya itibarı | Kapalı | Paket adları, sürümler, kayıt üst verisi; SHA-256 dosya özetleri | [privacy.tr.md](../privacy.tr.md) |
| Sürüm denetimi | Kapalı | Sürüm, çalışma ortamı, işletim sistemi/mimari, rastgele kurulum kimliği | [privacy.tr.md](../privacy.tr.md) |
| Yönetilen ajan telemetrisi | Kapalı (yönetilen mod + anahtar) | Kimlik bilgisi temizliğinden geçmiş karar olayları; araç özetleri ve eserler varsayılan olarak özetlenir (hash) | [privacy.tr.md](../privacy.tr.md) |
| Browser Guard telemetrisi | Kapalı (kontrol sunucusu adresi + anahtar gerekir) | Site, eylem, kanal ve tür başına sayılar | [privacy-telemetry.md](../contracts/privacy-telemetry.md) |
| AI güvenlik duruşu yüklemesi | Kapalı (`aidr scan` / `aidr discover` üzerinde açık `--upload`, kayıtlı API anahtarı) | Yalnız kimlikler ve özetler: CVE/GHSA kimliği, önem, CVSS, bileşen ve sürüm, MCP risk kategori kodları, beceri kural kimlikleri ve T01–T09 kodları, SHA-256 özetleri. Hedef URL, sunucu adı, dosya yolu, eşleşen metin, MCP komutu ya da kimlik bilgisi asla | [ai-security-posture.md](../ai-security-posture.md) |
| AI güvenlik duruşu derin tarama | Açık komut | Hedef ve seçenekler yapılandırılmış derin tarama köprüsüne (varsayılan loopback) | [privacy.tr.md](../privacy.tr.md) |
| Tanılama (Sentry) | Kapalı | Temizlenmiş hata olayları; yalnız açık seçim ve DSN ile | [privacy.tr.md](../privacy.tr.md) |

### İstemler, kaynak kod ya da dosyalar SingularityRD'ye yüklenir mi?

Hayır. Yerel sezgisel denetimler kaynak dosyaları, dosya içeriklerini ya da tam
istemleri yüklemez. Browser Guard telemetride istem metnini, maskelenmiş metni,
tespit edilen değerleri ya da sayfa adreslerini asla göndermez. Kontrol sunucusu
şirket içinde çalışıyorsa telemetri SingularityRD'ye değil müşterinin
sunucusuna gider.

### Browser Guard açıkken AI sağlayıcısı (ChatGPT, Gemini, Claude…) ne alır?

Tespit edilen değerleri `[EMAIL_1]` ya da `[TCKN_1]` gibi yer tutucularla
değiştirilmiş istemi. Yer tutucu–değer eşleştirmesi yalnız sayfanın içerik
betiği belleğinde yaşar. Eklenti deposuna yazılmaz, hiçbir yere gönderilmez ve
sayfa yenilenince unutulur. Tespit edilemeyen veri yazıldığı gibi gider; tespit
kusursuz değildir ve müşteri verisi üzerinde ölçülmemiştir. İkili dosyalar (PDF,
DOCX, görseller) tarayıcıda incelenemez: `block` modu onları durdurur, diğer
modlar uyarıyla geçirir.

### İsteğe bağlı yerel sunucu (native host) ne alır?

Yönetici açarsa Browser Guard, NER için istem metnini aynı uç noktadaki bir süreç
olan AIDR Privacy yerel sunucusuna gönderir. Bu yoldan cihazdan çıkmaz. Yerel
sunucu modelsiz gelir ve NER ilk sürüm kapsamında değildir. Bkz.
[native-host.md](../../packages/browser-guard/docs/native-host.md).

---

## Zorlama ve hata davranışı

### AIDR hata durumunda açık mı geçer, kapalı mı kalır?

Katmana bağlıdır ve her birini ayrı söylüyoruz:

- **Bağlayıcı giriş noktaları hata durumunda kapalı kalır.** Claude Code,
  Cursor/VS Code, OpenClaw, OpenCode ve Codex, iç bir hatada reddetme (deny)
  döndürür. Eklenti başlatma hataları, aracı korumasız bırakmak yerine her şeyi
  reddeden bir işleyici kaydeder. Bu bağlayıcının yanıtıdır; aracın devre dışı
  bıraktığı, güvenmediği, sonlandırdığı ya da zaman aşımına uğrattığı bir kanca
  hiç yanıt vermez (son maddeye bakın). Cursor ve VS Code önizlemedir — henüz
  gerçek ortam kabul kanıtı yok.
- **Browser Guard'ın içerik betiği de bir hata durumunda gönderimi durdurur.**
  Eksik politika, okunamayan düzenleyici, tarama hatası ya da eksik tarama
  gönderimi engeller (`monitor` modu hariç).
- **Tespit iç bileşenleri** hata veren bir sinyali atlar, kaydeder ve devam eder.
  Atlanan bir sinyal asla temiz sonuç olarak bildirilmez.
- **Güvenlik denetimleri** (kimlik doğrulama, kiracı yalıtımı, hız sınırları,
  webhook imzaları, onaylar) hata durumunda reddeder.
- **Son sözü araç söyler.** Bir araç kancayı çağırmazsa (devre dışı,
  güvenilmeyen, sonlandırılan) işlem devam eder. Codex bunu güvenilmeyen ya da
  çöken kancalar için belgeler. Araç bazında sonuçlar:
  [uyumluluk matrisi](../compatibility-matrix.md#host-failure-behaviour).
  AIDR kanca sınırında bir korkuluktur, uç nokta yalıtımı değildir.

### Ele geçirilmiş ya da istem enjeksiyonuna uğramış bir ajan kendi engelini onaylayabilir mi?

Hayır. `ask`, bant dışı insan onayını bekleyen bir engellemedir. Hiçbir
bağlayıcı ajana bir onay aracı sunmaz; MCP Gateway onayları ayrı bir operatör
komutudur, asla bir MCP aracı ya da HTTP uç noktası değildir.

---

## Şifreleme ve imzalama

- **Aktarımda:** kontrol sunucusuna HTTPS/TLS. Şirket içinde TLS müşterinin
  giriş (ingress) katmanında sonlanır; üretilen yığın servisleri loopback'e
  bağlar.
- **Durağan veride:** barındırma ortamının depolama şifrelemesine dayanır:
  bulutta yönetilen veritabanı sağlayıcısı, şirket içinde müşterinin
  birimleri. Onaylanan bölge için teyit edin.
- **İmzalama:** sürüm eser bildirimleri, çalışma zamanı politikası, kiracı
  algılayıcı paketleri, kural/istihbarat paketleri, çevrimdışı lisans ve
  (isteğe bağlı) yerel denetim kayıtları üzerinde Ed25519 imzaları. İmza özel
  anahtarları uç noktalara asla dağıtılmaz.
- **Kimlik bilgileri:** kiracı API anahtarları yalnız özet (hash) olarak
  saklanır. CLI kimlik bilgisini varsayılan olarak işletim sistemi kasasında
  tutar; daha az korumalı dosya seçeneği açıkça seçilmelidir.

---

## Kiracılık ve erişim denetimi

- Tenant tablolarında **satır düzeyinde güvenlik** olan, Postgres üzerinde çok
  kiracılı kontrol sunucusu. Politikalar `app.is_tenant_member(tenant_id)` ve
  role duyarlı türevlerini kullanır; anonim kullanıcıların yazma erişimi yoktur.
- Roller (sahip, yönetici, üye, görüntüleyici), rol değişiklikleri denetim
  kaydında.
- Cihaz kaydı kısa ömürlü cihaz kodlarıyla (başlat, doğrula, sorgula) yapılır;
  cihaz kiracısına bağlı imzalı bir yapılandırma alır.
- Kiracılar arası negatif testler depoda Postgres'e karşı çalışır (örneğin
  `scripts/tenant-lifecycle-rls-postgres.test.mjs`). Kabul edilmiş bir kurulumda
  canlı iki kiracı testi hâlâ açıktır (FCR-05).

## Kimlik: SSO ve SCIM

- **SSO:** OAuth ile Microsoft Entra ID ve SAML 2.0 kimlik sağlayıcıları; yerel
  hesaplar için MFA ve kurtarma kodları.
- **SCIM:** kullanıcı ve grup sağlama uç noktaları (`supabase/functions/scim`).
- Müşterinin IdP'siyle (Entra ID, Okta ya da diğer) canlı kabul her kurulumda
  gereklidir.

## Denetim kaydı

- **Uç nokta:** boyuta göre dönen JSONL denetim kaydı; isteğe bağlı,
  değişikliği belli eden modda SHA-256 özetleri zincirlenir ve kayıtlar Ed25519
  ile imzalanır.
- **Kontrol sunucusu:** kiracı olayları, olaylar (incident) ve yönetim işlemleri
  (kayıt, davetler, rol değişiklikleri, politika yayımlama) kaydedilir. Denetim
  dışa aktarımı, imzalı sayfalama imleçleriyle kısa ömürlü özel indirmeler
  üzerinden JSONL/CSV üretir.
- **SIEM:** Splunk, Microsoft Sentinel ve Elastic için taşınabilir
  `aidr.siem.event/v1` şemasında iletim.

## Saklama ve silme

- Telemetri her kiracı için kiracının saklama politikasına göre budanır.
- Yasal saklama (legal hold), saklanan kiracı için olağan saklama silmesini ve
  kiracı kapatma silmesini durdurur.
- Kiracı kapatma, kiracı verisini kayıtlı yetkilerle siler; dışa aktarma
  nesneleri doğrudan silinemez.
- Uç nokta denetim kayıtları yerelde boyuta göre tutulur (varsayılan 5 MiB
  etkin dosya, üç dönmüş yedek).
- Barındırılan bir kiracının saklama süreleri müşteri sözleşmesinde belirlenir.
- Kurumlar için saklama ön ayarları ve VERBİS: [KVKK rehberi](../operations/kvkk.md).

## Şirket içi ve internetsiz kurulum

Kontrol sunucusunun tamamı müşterinin ortamında Docker Compose ya da Kubernetes
(Helm) üzerinde, imzalı çevrimdışı lisans ve imzalı çevrimdışı paketlerle
internetsiz olarak da çalışabilir. Kontrol sunucusu şirket içindeyken
SingularityRD'ye telemetri gönderilmez. Bkz. [onprem.md](../deployment/onprem.md)
ve [veri yerleşimi](../deployment/data-residency.md).

## Gizlilik mevzuatı (KVKK, GDPR)

AIDR, KVKK ve GDPR yükümlülüklerini **desteklemek üzere tasarlanmıştır**: veri en
aza indirme (yerel tespit, yalnız sayaç telemetrisi, özetlenmiş eserler),
üçüncü taraf AI sağlayıcılarına ulaşmadan önce kişisel verinin maskelenmesi,
kiracı kapsamlı saklama ve yasal saklama, kiracı kapatmada silme ve veri
yerleşimi için şirket içi seçenek. AIDR'ı kullanmak bir kurumu kendiliğinden
uyumlu yapmaz. DPA, alt işleyen listesi ve bölgesel barındırma koşulları
taslak hâlindedir ve onay beklemektedir ([DPA taslağı](../legal/dpa.tr.md)).

Sahipler ve yöneticiler panelden (**Uyum**) 366 güne kadar bir dönem için
**uyum kanıt raporu** oluşturabilir: kapsam, yalnız sayaç içeren veri koruma
etkinliği, politika sürümleri ve özetleri, erişim ve kimlik, olaylar, AI
güvenlik duruşu, veri akışı envanteri ve saklama/silme kanıtı; SHA-256 ile ve
isteğe bağlı olarak `aidr compliance verify` komutunun çevrimdışı denetlediği
bir Ed25519 imzasıyla mühürlenir. DPO'nuz ve denetçileriniz için kanıttır,
sertifika değildir. Her bölümün neyi kanıtlayıp neyi kanıtlamadığı için bkz.
[compliance-report.tr.md](../compliance-report.tr.md).

## Sertifikalar ve değerlendirmeler

**Yok.** AIDR'ın SOC 2 raporu, ISO 27001 sertifikası ve tamamlanmış bağımsız
sızma testi yoktur. Bağımsız güvenlik incelemesi bir sürüm kapısıdır
(SEC-EXT-001) ve yapılmamıştır; yaptırmak için kapsam ve teklif isteği hazırdır
([pentest kapsamı/RFP](../security/pentest-scope-rfp.md)). Başlanmamış
sertifikalar için tarih vermiyoruz.

## Güvenlik açığı bildirimi ve destek

Panelin herkese açık `/security` sayfası güvenlik irtibatının yayımlandığı
yerdir; hedefi henüz yapılandırılmamıştır. Açık bildirim politikası taslaktır ve
yürürlükte değildir ([politika taslağı](../security/vulnerability-disclosure-policy.md)).
Adlandırılmış sorumluları ve yanıt hedefleri olan izlenen bir destek kanalı bir
sürüm ön koşuludur (FCR-06/08) ve henüz yoktur ([destek süreci](../runbooks/support-process.md),
[SLA taslağı](../legal/sla.tr.md)).

## İlgili belgeler

- [Gizlilik ve telemetri veri akışı](../privacy.tr.md)
- [Uyum kanıt raporu](../compliance-report.tr.md)
- [Ürün genel bakışı (EN)](../product/overview.md)
- [SaaS kurulumu (EN)](../deployment/saas.md) · [Şirket içi kurulum (EN)](../deployment/onprem.md)
