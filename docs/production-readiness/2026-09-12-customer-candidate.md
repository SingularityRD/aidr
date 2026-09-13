# İlk müşteri kurulum adayı — 12 Eylül 2026 (v3 tarihçesi)

Güncel birleşik doğrulama ve v4 teslimi [v4 aday kaydında](2026-09-12-customer-candidate-v4.md) bulunur. Aşağıdaki sayılar ve açık bulgular v3 zamanındaki durumdur.

Bu kayıt önceki [11 Eylül uygulama raporunun](2026-09-11-delivery-verification.md) devamıdır. İlk müşteri için taşınabilir kurulum, yönetim, politika dağıtımı, dışa aktarım ve yedekten dönüş akışları yerel ortamda doğrulanmıştır. Ticari genel kullanıma açılma kararı **NO-GO** olarak korunur; eksik ürün özellikleri, yayıncı imzası ve müşteri ortamında kabul tamamlanmamıştır.

## Tamamlanan müşteri akışları

- Self-hosted ve cloud için taşınabilir kurulum hazırlama, ilk yönetici/ekip/kota sağlama, SMTP gerektirmeyen parolalı giriş, tekrar denenebilir bootstrap ve başlangıç politikası.
- Onaylı ekibin çalışanı için kişisel pilot başvurusu gerektirmeyen cihaz eşleştirme. Cihaz onay ekranı hedef ekibi gösterir; aktif üyelik ve yazma yetkisi hem onayda hem token değişiminde doğrulanır.
- Seçili ekibe bağlı API anahtarı/token yönetimi. Ekip değişince tek seferlik sırlar temizlenir; görüntüleyici yazamaz, normal üye başka kullanıcının anahtarını iptal edemez, askıya alınmış ekip yeni kimlik bilgisi çıkaramaz. Doğrudan veritabanı yazmaları kapatıldı.
- Merkezi politika sürümleri, seçili ajanlarda deneme, geçmiş sürümü inceleyerek tüm filoya yayınlama ve geri alma. Yayınlama işlemiyle denetim kaydı aynı veritabanı işlemi içindedir.
- Ajan anahtarıyla bağlı politika yükleme bildirimleri; hedef/yüklenen sürüm, Unknown/Stale durumları ve büyük filo için sayfalama. Bildirim, hostun her eylemi engellediğine dair bağımsız kanıt değildir.
- Zorunlu merkezi politikada sabit çevrimdışı tolerans süresi. Önbellek okuma süreyi uzatmaz; süre bitince, yetki reddinde veya bozuk politikada yerel kurallara sessiz düşüş yapılmaz. Kayıtsız uçta yerel tespit devam eder.
- 500 satırlık sayfalarla CSV/JSON dışa aktarımı; imzalı kullanıcı/ekip/format imleci, başlangıç anı sınırı, özel kısa süreli indirme ve CSV formül kaçışı. Tarayıcı 100.000 kayıt/64 MB sınırında eksik dosyayı başarı gibi sunmaz.
- Geçici dışa aktarım dosyalarının 24 saatlik ömrü; önce ölçen, sonra Storage API üzerinden dosya baytlarını silen tekrar çalıştırılabilir bakım komutu ve saatlik Linux zamanlayıcı şablonları. Kaynak denetim kayıtları değişmez.
- Şifreli soğuk veritabanı/nesne/yapılandırma yedeği, yanlış anahtar/değiştirilmiş yedek reddi ve bağımsız Docker volume'larına geri dönüş.
- Her kurulum için ayrı rastgele S3 protokol kimlik bilgileri. Kurulum kontrolü upstream örnek parolasını reddeder; teslim paketinde özel prova sırları bulunmadığı sıkıştırılmış paketlerin içeriğinde de denetlenir.
- MCP taşıma bileşeninde değişen şemanın tekrar gönderilerek kabul edilmesi ve gözlenmiş şemanın sonraki çağrıdan çıkarılması reddedilir. Bu süreç içi referans kontrolüdür; imzalı araç onayı veya tamamlanmış bir gateway değildir.

## Doğrulama kaydı

Son toplu kayıt: [candidate-verification.json](evidence/2026-09-12-candidate-verification.json). Kod testi, gerçek yerel servis provası ve dış kabul kapsamları bu kayıtta ayrıdır.

- Son seri test: **174 dosya, 2.755 başarılı test, 0 hata, 1 atlanan canlı reputation senaryosu**. Atlanan senaryo başarıya dahil değildir.
- [Müşteri başlangıcı](evidence/2026-09-12-customer-onboarding.json): 9 kontrol.
- [Politika dağıtımı](evidence/2026-09-12-policy-rollout.json): 11 kontrol; gerçek HTTP/veritabanı ve derlenmiş Claude kancası.
- [Kurumsal operasyonlar](evidence/2026-09-12-enterprise-operations.json): 8 kontrol; 1.005 eş zaman damgalı kayıt, eksiksiz üç sayfa, geç gelen kaydın hariç tutulması, yetki sınırları, gerçek dosya silme ve ekip çalışanının tam kaydı.
- Paket tüketicileri: 9; yerel engelleme matrisi: 72; Codex kancası: 11; kurulum araçları: 9.
- [Filo sayfalama](evidence/2026-09-12-fleet-pagination.json): 4 kontrol; 501 sentetik veritabanı kaydıyla sayfa geçişi ve hedef politikanın korunması. Bu, 501 gerçek ajan için yük testi değildir.
- [Kurulum kontrolü](evidence/2026-09-12-doctor.json): 29 kontrol; 18 migration ve çalışan yerel servisler.
- [Geri dönüş](evidence/2026-09-12-customer-recovery.json): 16 tablonun kayıt ve içerikleri, politika özeti ve nesne dosyaları için 18 eşleşme. API yazıcıları durdurularak alınan tutarlı anlık görüntü karşılaştırılmıştır. Daha sonra yapılan S3 parola değişimi ayrıca kurucu ve doctor ile doğrulanmıştır.
- [Taşınabilir paket](evidence/2026-09-12-customer-kit.json): 7 kontrol; dosya özetleri, 13 dağıtım arşivi, sır taraması ve her iki kurulum modelinin Git/pnpm bulunmayan ortamda hazırlanması.
- Bağımlılık taraması: 0 üretim advisory. Statik kapı geçer; 132 lint uyarısı ve raporlanan kullanılmayan kod borcu sürer.

Dört işçiyle yapılan önceki toplu testte bir OpenCode senaryosu 30 saniye sınırına takıldı. Windows kapısı, derlenmiş bağlayıcıların alt süreç başlatma rekabetini önlemek için seri çalışır. Testler, senaryolar ve süre sınırları azaltılmadı. Hatalı koşunun JSON kaydı özel `.release-evidence/final-four-worker-failure.json` dosyasında tutulur; seri koşu başarılıdır.

Daha sonraki koşu, aynı HMAC baytlarının standart dışı Base64 yazımını kabul eden imleç kontrolünü yakaladı. İmza veya tenant yetkisi aşılmadı; değiştirilen imleç metninin reddi tutarsızdı. Standart dışı yazım artık reddedilir; üç alternatif yazımın tamamını sınayan test dahil dört cursor testi ve son toplu koşu geçti. Başarısız koşu `.release-evidence/v3-cursor-noncanonical-failure.json` içinde korunur.

## Teslim ve açık işler

[71 alt özellik envanteri](../../FEATURE_INVENTORY.md): 41 çalışan akış, 21 kısmi, 7 eksik, 2 dış kabul başlığı. Bunlar üretim etkinliği veya tespit başarım oranı değildir. Paket denetiminde gerçek bağlayıcı kapsam boşluğu bulunduğu için DET-12 kısmiye çekildi. [Bulgu defteri](../../READINESS_BACKLOG.json): 63 kayıt, 47 doğrulanmış kapanış, 16 açık/devam eden/dış bağımlı kayıt.

[Ayrıntılı üretim ve satış eksikleri](../../PRODUCTION_SALES_GAPS.md), 41 teknik/operasyon işini ve 13 ticari/dış kanıt kapısını mevcut durum, müşteri etkisi, uygulama, kabul testi ve sorumlusuyla açıklar. Öncelikli açıklar: OpenCode araç/girdi normalizasyonu, paket denetimi exception'larının sessiz kaybolması, reputation API'lerinde aktif ekip/üyelik kontrolü ve MCP taşıma sınırları. [Reputation yaşam döngüsü provasında](evidence/2026-09-12-reputation-lifecycle-audit.json) dört yetki değişimi sonrası istek kabulü yeniden üretildi. Bu açıklar v3 adayında da giderilmiş sayılmaz.

Kurulum işlemleri [ilk müşteri kılavuzundadır](../../deploy/FIRST_CUSTOMER.md). `package:customer` komutu dokümanları, hazırlanmış dashboard'u, kanonik backend'i, migration'ları, kurulum/bakım/geri dönüş araçlarını, Claude bağlayıcısını ve istenirse dokuz paketin arşivlerini toplar. Özel prova dizini; parolalar, service key ve test hesapları içerir, teslimata kopyalanmaz. SHA256SUMS değişikliği tespit eder; yayıncı imzasının yerini almaz.

Güncel mühendislik adayı: `.release-evidence/aidr-customer-kit-20260912-v3.tar.gz`; özet dosyası aynı ada `.sha256` eklenmiş yoldadır. İlk v1 adayı upstream örnek S3 parolası yüzünden reddedildi; v2 bu sorunu düzeltti, v3 MCP referans ve cursor kod düzeltmeleriyle güncel envanteri içerir. Hiçbiri genel üretim/satış onayı değildir.

Kalan ürün işleri: MCP tool description/schema güveni ve kimlik ilişkileri, inline MCP gateway, sürekli filo keşfi, SCIM/directory yaşam döngüsü, tüm hostlarda imzalı MDM dağıtımı/güncelleme/geri alma, diğer bağlayıcılarda model tüketiminden önce çıktı denetimi, HA ve yük/uzun süre ölçümleri. Otomatik ödeme portalı satılacaksa ayrıca uygulanmalıdır; mevcut ticari model kurum faturasıdır.

Dış kabul işleri: gerçek cloud hesabı/bölge ve HTTPS alanları, SSO/SMTP/MFA ve hesap kurtarma, satış/destek hedefleri, özel registry ve yayıncı imza anahtarı, müşteri host/OS/sürüm testleri, bağımsız güvenlik değerlendirmesi, sözleşme/veri yerleşimi/SLA ve offsite RPO/RTO tatbikatı. Zamanlayıcıların ve izleme alarmlarının müşteride etkinleştirilmesi de kurulum kabulüne dahildir. Bu şartlar belirsizken bütün ürünün üretim onayını kapatmak mümkün değildir.
