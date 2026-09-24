# 0.4.0-rc.1 — Üretim kabul kapıları ve tehdit modeli

## Teslimin statüsü

Çalışan ve test edilmiş bir entegrasyon adayıdır. Bu sürümdeki test sayısı, bağımsız güvenlik denetimi, Türkçe/İngilizce NER doğruluğu, saldırganlara karşı tam prompt-injection koruması, sınıflandırılmış savunma verisi için akreditasyon veya kurumsal mevzuat sertifikası yerine geçmez. BMC ya da başka bir kurumda fiili dağıtım yapılmadı.

## Korunan sınırlar

Metin/görsel temizleme kendi çıktı byte'larını üretir. Enterprise gate'in engel/inceleme kararı ham çıktı vermez. Tool onayı yalnız belirli tenant, kullanıcı, oturum, tanım ve parametreler için bir kez geçerlidir. Politika belirsizliği, model/worker/disk hatası, kaynak veya sıra sınırı durumunda orijinale dönülmez. Güvenilir AIDR entegrasyonu bu kararların dışından provider/tool çağrısı yapmamalıdır.

## Üretim öncesi zorunlu doğrulamalar

**Kimlik ve hesap bağlamı.** Tenant kimliği, rol/grup, cihaz yönetim durumu ve hedef hesabın kurumsallığı IdP/MDM/onaylı sağlayıcı oturumundan gelmelidir. Aynı tarayıcıdaki kişisel/kurumsal hesap değişimi, logout, ayrı profil ve gizli pencere test edilmelidir. Bu pakette gerçek IdP/MDM bağlayıcısı yoktur.

**Son byte sınırı.** Metin, tüm konuşma geçmişi, tool argümanları, görüntü, thumbnail, dosya adı, upload öncesi CDN akışı, retry, streaming ve telemetri çıkışları envantere alınmalıdır. Site editörünün ortak DOM'unda önceden bulunan ham metin site tarafından okunabilir. MV3 event handler'ı cihaz genelinde ağ filtresi değildir. Eklentinin görmediği masaüstü/CLI/mobil/başka sağlayıcı kanalları ayrı endpoint veya gateway katmanında kapatılmalıdır.

**Gerçek model değerlendirmesi.** Öğrenilmiş TR/EN NER ağırlıkları/tokenizer'ları çalıştırılmadı. Kurallı tanıma, özellikle etiketsiz serbest kişi/adres için eksik kalabilir. OCR okunabilirlik ve kalıp kuralları adversarial görsel tamlığı sağlamaz; aynı motorla ikinci tarama ortak hata yapabilir. Fotoğraf, el yazısı, yüz, imza, CAD ve steganografi ayrı kapsamdır. Ölçümde tür başına kaçırma/yanlış alarm, cihaz/tema/çözünürlük varyantı ve insan inceleme oranı takip edilmelidir.

**Süreç ve taşıma izolasyonu.** Python/native decoder/OCR süreçleri ağ çıkışı kapalı, dosya erişimi daraltılmış, düşük yetkili ve kaynak limitli çalışmalıdır. Child process kullanımı sandbox değildir. `allowedOrigins` DNS rebinding, özel IP'ye çözülen alan adı veya redirect güvenliğini kendiliğinden çözmez. HTTP istemcisi gerçek bağlanan IP'yi ve her redirect'i doğrulamalıdır. Model/tool sunucusu ile bağlantı kimlik doğrulaması bu SDK'nın dışında yapılır.

**Onay ve kota atomikliği.** ApprovalLedger, ProvenanceLedger, ApplicationInventory ve ActivityBudget bu sürümde bellektedir. Süreç yeniden başlatılınca eski onaylar geçersiz kalır; bu güvenli kapanmadır, dayanıklı iş akışı değildir. Dağıtık kurulumda aynı onayın iki replika tarafından kabul edilememesi, limitin replika sayısıyla aşılmaması ve kayıt kaybının korumayı gevşetmemesi atomik paylaşılan depoda doğrulanmalıdır. Kullanıcı onay ekranı ve SSO yetkilendirmesi ayrıca geliştirilmelidir.

**Politika yaşam döngüsü.** İmza özel anahtarları merkezi yönetici sınırında tutulmalıdır. `installDurable` yazıcısı gerçekten kalıcı olmalıdır. Checkpoint eski disk snapshot'ıyla geri alınamamalıdır. Anahtar rotasyonu, eski anahtar iptali, süresi dolmuş politika, saat kayması ve yarım dağıtım test edilmelidir. Browser PolicyJSON ile enterprise politika şemaları aynı değildir; dağıtıcı uyuşmazlıkta kanalı kapatmalıdır.

**Denetim ve gizlilik.** Fsync'li yerel dosya adaptörü yeni segment yazar, otomatik restart append veya rotation yapmaz. İndeks/audit HMAC anahtarları farklı tutulmalı; hash değerleri kişisel veri bağlantısını tamamen yok etmiş kabul edilmemelidir. Metadata kullanıcı davranışı hakkında bilgi verebilir; yetki, tutma süresi ve çalışan bilgilendirmesi kurum sürecinde değerlendirilmelidir. Ham içerik toplamak bu sürümün varsayılanı değildir. Audit zinciri bağımsız checkpoint olmadan rollback/suffix silmeye karşı yeterli değildir. Dosya yazıldıktan sonraki fiziksel bozulma veya başarılı karar sonrası provider hatası ayrıca işletilmelidir.

**Tool etkisi.** Tanım hash sabitlemesi değişikliği algılar, kötü niyetli ama aynı kalan sunucu davranışını kanıtlamaz. Dar argüman şeması bütün JSON Schema anahtarlarını desteklemez. Secret içeren tool parametresini bloklamak bazı meşru çağrıları da durdurabilir; connector kimlik bilgilerini modelin argüman alanı yerine güvenilir yürütme sınırında yerleştirin. Side-effect sınıfı yönetici tarafından doğrulanmalı; “read” etiketini model veya tool açıklaması belirlememelidir. Yürütme süresi, idempotency, yetki iptali ve gerçek işlem audit'i executor sınırında uygulanır.

**Güvenli çıktı işleme.** Aktif içerik kalıpları bazı markup'u durdurur; tam HTML/Markdown sanitizer değildir. İşaretlemeyi güvenilir olmayan HTML olarak render etmeyin. Genel prompt-injection savunması için yalnız bu kalıplara güvenmeyin. Katmanlı savunma, en az yetki ve gerçek tool kontrol sınırı gerekir. OWASP kaynak bağlantısı RESEARCH.md'dedir; ürün uyumluluk sertifikası değildir.

**Bağımlılık ve yayın.** Güncel CVE/tedarik zinciri incelemesi, gerçek binary/image digesti, ilgili üçüncü taraf lisansları, SBOM, imzalı extension/native dağıtımı ve güncelleme/geri alma kanalı kurumda doğrulanmalıdır. Bu paketin hash manifest'i yayın imzası değildir. Node, Python, Pillow, Tesseract, libzbar ve transitive kütüphaneler onaylı imajda sabitlenmelidir. Test ortamının sürümü üretim için güncel güvenlik onayı anlamına gelmez.

## Bu çalışmada özellikle doğrulanmayanlar

Kurulu MV3/live oturum açılmış ChatGPT, Gemini ve Claude; Windows/macOS native kurulum; kurumsal mağaza/MDM politikaları; kalıcı çok replikalı veri tabanı; gerçek SSO/SCIM; merkezi inceleme ekranı; tam MCP OAuth/proxy; cloud storage/DSPM tarayıcıları; PDF/Office/arşiv parser'ları; gerçek öğrenilmiş NER/PII sınıflandırıcısı; bağımsız adversarial recall; müşteri yükü altında p95/p99; donanım güç kesintisi testi; bağımsız pentest.

## Kaynak bütçeleri

Enterprise gate aynı anda en fazla sekiz kontrol kabul eder. Dosya denetim kuyruğu 64 bekleyen yazıyla sınırlıdır; yazı onayı varsayılan 10 saniyede gelmezse journal kalıcı olarak durur. Native OCR ve eski metin motorunun kendi limitleri korunur. Hassas veri indeksi 10.000 kayıt/belge, varsayılan 100.000 parmak izi, 65.536 aday hash işlemi sınırında reddeder. Bunlar servis kapasite garantisi değil, yerel kaynak tüketiminin sınırlanmasıdır. CPU-bound kod üretimde ayrı worker/cgroup içinde çalıştırılmalı ve eşzamanlı trafik altında ayrıca ölçülmelidir.

## Kabul için önerilen somut çıkış kriterleri

Kontrollü testte hiçbir block/review örneğinin ham byte'ı dış sağlayıcıya ulaşmamalı; tek onay, paralel çağrılarda bir kez yürütülmeli; onaysız/kişisel/unknown hesaplar tanımlı politikaya göre durmalı; kiracılar veri, anahtar veya checkpoint paylaşmamalı; disk/worker/policy hatası sessizce allow'a dönmemeli. Bu kriterler müşteri altyapısında saldırgan ve başarısızlık senaryolarıyla kanıtlanmadan otomatik geniş dağıtıma geçilmemelidir.
