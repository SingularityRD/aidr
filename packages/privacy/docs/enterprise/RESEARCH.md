# AIDR Enterprise Controls — Ürün araştırması ve özellik matrisi

**Sürüm:** 0.4.0-rc.1 · **Araştırma tarihi:** 24 Eylül 2026

Bu çalışma, 0.3.0 tarayıcı/metin/görsel modülünün üzerine eklenecek kontrolleri seçmek için hazırlanmıştır. “Piyasadaki en iyi” ifadesini bağımsız laboratuvar sonucu veya Gartner sıralaması gibi kullanmıyoruz. Aşağıdaki ürünler farklı ihtiyaçlarda karşılaştırmaya alınan bir referans grubudur. Üreticinin bir özelliği belgelemesi, bu çalışmada doğruluğunun, gecikmesinin veya saha kapsamının ölçüldüğü anlamına gelmez.

## Araştırmanın ana sonucu

AIDR'nin yalnız bir PII maskeleyicisi olması yerine üç ayrı karar sınırına sahip olması öneriliyor: çalışanın AI uygulamasına veri gönderimi, kurumsal uygulamanın modele/veri kaynağına erişimi ve ajanın gerçek araç çağrısı. Eklenti kullanıcı deneyimini sağlar; doğrulanmış kimlik, veri sınıfı, onay ve denetim kararı güvenilir AIDR katmanında uygulanır. Bu mimari seçimi bu projenin tasarım kararıdır; herhangi bir kurumun onayı değildir.

Gartner'ın 18 Ekim 2025 tarihli *Top Strategic Technology Trends for 2026: AI Security Platforms* yayınının açık özeti, AI'ya özgü kontrollerin merkezileştirilmesini ele alıyor. 18 Şubat 2025 tarihli AI TRiSM Market Guide açık özeti de katmanlı kontrol yaklaşımına işaret ediyor. Yalnız erişilebilir özetler incelendi; ücretli tam raporlar okunmuş veya bir Magic Quadrant sıralaması çıkarılmış gibi davranılmadı. [S01, S02]

SANS'ın 31 Mart 2025 tarihli yazısı, Draft Critical AI Security Guidelines v1.1 çerçevesinde en az yetki, etkileşim doğrulama, API kullanım izleme, veri koruma, çıkarım güvenliği ve yönetişimi birlikte ele alıyor. Buradaki kontroller taslak rehberden alınmış bir sertifikasyon veya “SANS uyumlu ürün” beyanı değildir. [S03]

## Karşılaştırma için seçilen ürünler

| Ürün | Birincil kaynakta görülen yetenek | AIDR için çıkarılan ihtiyaç | Bu sürümün dürüst karşılığı |
|---|---|---|---|
| Microsoft Purview | Kuruma özgü kayıtlar için Exact Data Match, hassas bilgi türleri, eğitilebilir sınıflandırıcılar ve belge parmak izi. [S04, S05] | Yalnız genel regex değil, gerçek kurumsal kayıt ve içerik eşleştirmesi. | Tenant anahtarlı, normalleştirilmiş aynı-kayıt eşleştirmesi ve kelime parçası parmak izi uygulandı. Purview ölçeği veya ML sınıflandırıcısı değil. |
| Netskope One | Kullanıcı/uygulama/eylem/veri bağlamı, kişisel uygulama kısıtları, Instance Awareness, veri hareketi ve DLP'nin ortak yönetimi. [S06] | Aynı uygulamada kişisel hesap ile onaylı kurumsal hesabı ayırmak; kullanıcıya anlaşılır geri bildirim. | Güvenilir hesap/cihaz/grup bağlamına göre politika SDK'sı ve eklentide statik Türkçe açıklamalar. Gerçek SaaS hesap attestasyonu ayrıca bağlanmalı. |
| Zscaler | Web, SaaS, endpoint, e-posta ve bulutta ortak DLP yaklaşımı; veri keşfi/sınıflandırması ve AI kullanım kontrolü. [S07] | Kanallarda tutarlı politika ve mevcut altyapıyla merkezi olay akışı. | Aynı kurumsal karar SDK'sı ve imzalı metadata zarfı. Tam SASE, TLS denetimi, e-posta/endpoint ajanı geliştirilmedi. |
| Cyberhaven | Verinin kaynağının yanında kopyalama, dönüşüm ve hedef boyunca veri hareketinin izlenmesi. [S08] | PII'yi kaldırmak, içeriğin gizlilik sınıfını kendiliğinden düşürmemeli. | Açıkça kaydedilmiş kaynak ve türetme makbuzlarında sınıf/taint mirası. Sistem genelinde otomatik lineage değil. |
| SentinelOne Prompt Security | Çalışan AI araçları, kod asistanları, kurum içi uygulamalar ve ajanlar; shadow AI, sızıntı ve ajan eylemleri. [S09] | Çalışan koruması ve ajan çalıştırma yetkilendirmesi ayrı ama ilişkili olmalı. | Eklentiye yeni sinyaller, sunucuda ToolCallGuard, onay SDK'sı ve gözlem girdisi alan envanter. Otomatik tam keşif yok. |
| Palo Alto Networks Prisma AIRS | AI gateway, runtime/agent security, model/posture güvenliği ve AI red teaming ürün alanları. [S10] | Tool tanımı değişikliği, parametre, yetki, hedef ve onay kontrolü; devamlı regresyon. | Tanım hash sabitlemesi, dar şema, scope/URL kontrolü ve tek kullanımlı dört-göz onayı. Tam MCP proxy, model tarama ve saldırı üretim platformu değil. |

Bu tablo bir satın alma sıralaması değildir. Ürün paketleri, lisansları ve dağıtım seçenekleri değişebilir; sözleşme veya müşteri PoC'si olmadan paket kapsamı/performans garantisi çıkarılmamalıdır.

## Gerçekten uygulananlar

### Kuruma özel verinin korunması

`SensitiveDataIndex`, bir kayıt içindeki en az iki alanın aynı metinde bulunmasını varsayılan eşik olarak kullanır. Örneğin bir parça kimliği ile belirli tesis kimliğinin beraber geçmesi, bu iki alan genel PII formatında olmasa da `restricted` sınıfını tetikleyebilir. Bir kayıt satırından gelen parça ile başka satırdan gelen tesis tek kayıt eşleşmesi sayılmaz. İstenirse eşik açıkça 1 yapılabilir.

Kaynak değerler kayıt sırasında yerelde işlenir; indeks kendi içinde HMAC değerleri saklar. Normalleştirme Türkçe harf varyantlarını ve seçili görünmez/kodlanmış biçimleri ele alır. Bu byte-birebir veri eşitliği, şifreleme, anonimleştirme veya özel küme kesişimi değildir. Anahtarı ele geçiren saldırgana karşı düşük entropili değerler için mutlak gizlilik iddiası yoktur.

Belge parmak izi beş kelimelik parçaları karşılaştırır; asgari farklı parça sayısı ve kaynak kapsamı birlikte sağlanmalıdır. Parafraz, semantik benzerlik, OCR hataları ve görüntüye gömülü anlam aynı teknikle çözülmüş değildir. Varsayılan toplam parmak izi sınırı 100.000, en fazla 250.000; kayıt/belge sayısı sınırı 10.000; bir tarama 65.536 aday hash işlemini aşarsa hata ile kapanır. Milyon satırlık dağıtık EDM için depolama/arama tasarımı gereklidir.

### İçerik + kimlik + hedef kararı

`EnterprisePrivacyGate`, imzalı politikadaki izinli HTTPS kökenini, hesabın türünü ve doğrulanmış olmasını, yönetilen cihaz durumunu, grup üyeliğini ve verinin sınıfını beraber değerlendirir. Bu alanları sağlayıcı sayfasındaki yazılardan çıkarmıyoruz. AIDR'nin kimlik/cihaz/kurumsal sağlayıcı oturumu katmanı tarafından doğrulanmış bağlam gerekir. Bilinmeyen hedef ve eksik bağlam için hiçbir ham metin geri dönüşü yoktur.

`ProvenanceLedger` kaynak kaydı ve türetilen metnin ilişkisinin entegrasyon tarafından bildirilmesini sağlar. Türetilmiş çıktının sınıfı düşmez; ömrü ebeveynin ömrünü aşmaz. Taint biti de korunur fakat bu bitin mevcut bütün araç çağrılarına otomatik uygulanması veya RAG poisoning'in tamamen önlenmesi tamamlanmış özellik değildir. Politika kaynak makbuzunu zorunlu kılabilir. Aktarma noktalarından biri makbuz üretmezse SDK görülmeyen veri hareketini kendiliğinden keşfedemez.

### Ajan eylemi kontrolü

Tool açıklaması ve annotations dahil incelenmiş tanımın SHA-256 değeri sabitlenir. Aynı isimle farklı tanım gelmesi reddedilir. Onaylı tanımın gerçekten güvenli davranacağı veya arkasındaki sunucunun ele geçirilmediği garanti edilmez.

Dar argüman şeması bilinmeyen alanları, tür değiştirmeyi, fazla elemanı ve belirsiz JSON'u reddeder. Araç argümanında hassas veri bulunması sessizce parametre maskelemek yerine çağrıyı durdurur; bir hesap numarasını değiştirmek işleme başka anlam verebilir. URL izin listesi köken bazlıdır; DNS/IP/redirect denetimi gerçek taşıma katmanına aittir.

Yazma, silme ve çalıştırma etkileri her zaman farklı bir yetkili kişinin onayını ister. Onay tenant, kullanıcı, oturum, politika sürümü, tanım ve tam argümanlara bağlıdır. Süresi biter, bir kez kullanılır; başarısız deneme veya executor hatası tüketilmiş onayı geri getirmez. Onaylı gerçek işlem yalnız `execute()` sarmalayıcısından çağrılmalıdır. Callback dışında yürütülen bir işlem bu SDK tarafından korunmaz.

### Politika ve olay bütünlüğü

Ed25519 politikaları, sabitlenmiş güven kökleri, sürüm düşürme denetimi, zaman sınırları ve hata durumunda karantina eklendi. `installDurable()` yeni politikayı, güvenilir checkpoint yazıcısı başarılı olmadan etkinleştirmez. Kalıcı checkpoint'in başlangıçta geri yüklenmesi ve bağımsız depoda korunması AIDR dağıtımının görevidir.

`AuditJournal`, ham içeriksiz, sıralı hash/HMAC bağlantılı olayları yazar. `createFileAuditSink()` yeni segmenti özel izinle açar, eski dosyayı ezmez ve her kaydı fsync sonrası onaylar. Disk yazımı veya kontrol sonucu belirsiz olduğunda çıktı verilmez. Zincirin sonunun silinmesini fark etmek için bağımsız checkpoint gerekir; bu WORM/immutable depolama değildir.

Webhook işlevleri metadata zarfını imzalar ve doğrular. Otomatik Slack/Splunk/Sentinel bağlayıcısı, teslim kuyruğu, ağ üzerinden gönderim ve bütün alıcılar arasında atomik tekrar engelleme bu sürüme dahil değildir.

### Eklenti ve operasyon

Eklenti varsayılan olarak TR/EN bilinen talimat değiştirme, sistem istemi çıkarma, rol işaretleri ve aktif içerik kalıplarını incelemeye durdurur. Kaynak kodu kalıbı için ayrıca yönetici kuralı eklendi. Bu tarama ML modeli değildir; güvenlik araştırmasını anlatan masum alıntıları da durdurabilir. Türkçe kullanıcı açıklaması, “yine de gönder” geçişi açmaz.

`ActivityBudget`, süre penceresinde kullanıcı başına çağrı ve byte sınırı uygular. Bu ML tabanlı davranış analizi veya çok mesaj arasında semantik sızıntı korelasyonu değildir. `ApplicationInventory`, güvenilir gözlemlerden yalnız köken, sayaç ve onaylı durum tutar; bütün çalışan trafiğini kendisi toplayan sensör değildir.

## Bundan sonraki özellik öncelikleri

Aşağıdaki öncelikler bizim ürün tasarım önerimizdir, Gartner/SANS sıralaması değildir.

| Öncelik | Özellik | Bu pakette durum | AIDR'de tamamlanma ölçütü |
|---|---|---|---|
| P0 | Güvenilir kullanıcı/cihaz/sağlayıcı hesap bağlamı | SDK girdisi ve reddetme kontrolü var | Kişisel hesap/unknown/çıkış yapılmış oturumda doğru karar; kullanıcı girdisinden bağlam üretilememesi |
| P0 | Kurumsal gerçek metin/görsel doğruluk değerlendirmesi | Sentetik kurallar/OCR testleri var | Ayrı TR/EN test kümelerinde tür bazlı precision/recall, kararsız örneklerde insan inceleme |
| P0 | Kalıcı çok kiracılı durum ve yetkilendirme | Yerel adapterlar ve fsync denetimi var | Atomik paylaşılan onay/kota/checkpoint, tenant izolasyonu ve geri yükleme testleri |
| P0 | Son ağ çıkış noktasına bağlama | Örnek ve SDK var | İlk upload, provider çağrısı ve tool etkisi koruma dışına çıkamamalı |
| P0 | Zorunlu kurulum ve kurcalama dayanımı | MV3 kaynak/bundle var | İmzalı/MDM kurulum, canlı sağlayıcı PoC ve native binary dağıtım testi |
| P1 | İnceleme, istisna ve olay yönetimi | Dört-göz onay primitive'i var | SSO/RBAC ekranı, onay gerekçesi, itiraz, süreli istisna, immutable karar geçmişi |
| P1 | Otomatik Shadow AI / MCP keşfi | Gözlem alan envanter var | Açıkça yetkilendirilmiş endpoint/gateway/IdP telemetrisi, risk kataloğu, güncelleme |
| P1 | Öğrenilmiş TR/EN anlamsal sınıflandırıcı | Önceki NER bağlantısı var; gerçek model doğrulanmadı | Sabit model/ağırlık, lisans, kötü niyetli ve masum test kümesi, kaynak bütçesi |
| P1 | PDF/Office, mail, arşiv, kaynak kodu yapıları | Desteklenmeyen dosyalar engellenir | İzole parser/CDR, makro/parola/embedded nesne politikası, ZIP bomb testleri |
| P1 | Kurumsal veri kaynakları/DSPM | Elle/SDK kayıt ve örnek indeks var | Kaynak yetkileri, senkronizasyon, silme/anahtar rotasyonu ve veri sınıflama akışı |
| P2 | Model tedarik zinciri ve AI red teaming | Hash pin ve regresyon var | Model format/bağımlılık tarayıcıları, öğrenilmiş saldırı değerlendirmesi, drift |
| P2 | Görsel olmayan modaliteler | Yok | Ses, video, yüz, el yazısı, imza, CAD ve steganografi için ayrı tehdit modeli |

## Kaynaklar

Kaynakların erişim tarihi 24 Eylül 2026. Üretici sayfaları bağımsız performans raporu değildir. Sayfaların tamamı bu pakete kopyalanmadı.

- **S01:** Gartner, *Top Strategic Technology Trends for 2026: AI Security Platforms*, 18 Ekim 2025, açık özet: https://www.gartner.com/en/documents/7014998
- **S02:** Gartner, *Market Guide for AI Trust, Risk and Security Management*, 18 Şubat 2025, açık özet: https://www.gartner.com/en/documents/6185655
- **S03:** SANS, *Securing AI in 2025: A Risk-Based Approach to AI Security Risk Assessment, Controls, and Governance*, 31 Mart 2025: https://www.sans.org/blog/securing-ai-in-2025-a-risk-based-approach-to-ai-controls-and-governance
- **S04:** Microsoft Learn, *Security guidance — Protect data*: https://learn.microsoft.com/en-us/purview/zero-trust-purview-protect-data
- **S05:** Microsoft Learn, *Get started understanding and using Microsoft Purview solutions*: https://learn.microsoft.com/en-us/purview/purview-where-to-start
- **S06:** Netskope One, *Data Security*: https://www.netskope.com/products/data-security
- **S07:** Zscaler, *Unified Data Security*: https://www.zscaler.com/datasecurity
- **S08:** Cyberhaven, *Data Lineage vs. Data Provenance*, 15 Temmuz 2026: https://www.cyberhaven.com/blog/data-lineage-vs-provenance
- **S09:** SentinelOne, *Prompt Security*: https://www.sentinelone.com/platform/securing-ai-prompt/
- **S10:** Palo Alto Networks, *Prisma AIRS*: https://www.paloaltonetworks.com/ai-security/prisma-airs
- **S11:** OWASP, *LLM Prompt Injection Prevention Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- **S12:** MCP, *Security Best Practices*, erişilen draft: https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices

Paylaşılan Blacksight metni, önceki sürümün yerel tarama, özel politika, kullanıcı/grup ve içeriksiz metadata akışı hedeflerine girdi oluşturdu. Bu belgedeki dış ürünlerle karşılaştırma yeni web araştırmasıdır; Blacksight'ın pazarlama beyanlarının denetimi değildir.
