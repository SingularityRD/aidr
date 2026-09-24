# Üretime alma kapıları — 0.2.0-rc.1

## Teslim edilen / teslim edilmeyen

Teslim: SDK, CLI, local OCR process worker, koordinat/redaksiyon/çıktı kontrolleri, atomic image/multimodal gate, kaynak ve derlenmiş kod, native bağımlılık envanteri oluşturucu, sentetik gerçek OCR örnekleri ve testler.

Teslim edilmedi: kurulmuş tarayıcı uzantısı, OS screen-capture hook'u, native-messaging host, network gateway, SSO/RBAC dashboard, admin review kuyruğu, onaylı gerçek TR/EN NER modeli, container/base-image sertifikasyonu, dış güvenlik denetimi veya BMC müşteri kabulü. Bunlara hazırmış gibi davranmayın.

## 1. Gönderim sınırını gerçekten kapatın

Tarayıcı paste, drag/drop, dosya seçimi, desktop attachment, tool/API image payload ve pre-signed upload yollarını tek kontrol noktasına getirin. PII temizlenmeden önce CDN/object-store'a orijinal yüklenmişse sonradan maskeleme sızıntıyı geri alamaz. Önce temizleyin; yalnız temiz artifact'i yükleyin. Orijinal URL, thumbnail, dosya adı, kullanıcı caption ve mesaj metni ayrıca taşınmamalıdır.

`protectMultimodal` yalnız ona verilen text + image bytes'ı işler. Uygulamanın diğer metadata alanlarını otomatik keşfetmez. Prompt/tool envelope, filename, MIME, image_url/base64 ve provider-specific alanlar için explicit schema-routing yapın. Ham URL fetch eden bir fallback eklemeyin; kurum içi fetch gerekiyorsa SSRF/redirect/auth sınırı ayrıca tasarlanmalıdır.

İstemci uzantısındaki JavaScript'in değiştirilmesi, alternate API veya yönetilmeyen cihaz çıkışlarını gerçek endpoint/network kontrolleri ile sınayın. Herhangi bir egress route kontrol noktasını atlayabiliyorsa “screenshot bypass kapandı” kabulü vermeyin.

## 2. Onaylı OCR/NER ve supply chain

Tesseract/Pillow/pyzbar/libzbar, sistem kütüphaneleri ve modeller için SBOM, izin verilen lisanslar, sürüm/digest kilidi, onaylı offline paket deposu ve kritik yama süreci sağlayın. Runtime binary ve eng/tur model hash'lerini sabitleyin; manifest imzasını kurumun güven köküyle ayrıca kontrol edin. Hash envanteri üretmek kimlik doğrulama değildir.

Öğrenilmiş NER için önceki `ner/` protokolünü kullanın; TR/EN kişi+adres dahil beklenen sınıfları gerçek veri üzerinde ölçün. Modelin “destekliyorum” demesi yeterli değildir. Otomatik savunma profili `profile:'defense'` + onaylı NER + `requireNer:true` ile kapalıdan açılmalıdır.

## 3. Bağımsız kabul verisi

Geliştirici tarafından hazırlanan beş okunaklı screenshot/sekiz pipeline testi genellenebilir başarı yüzdesi değildir. Kurumun izinli/de-identified örneklerinden, eğitimden ayrı test havuzu kurun: TR/EN isim/adres, alan etiketli/etiketsiz içerik, chat/email/CRM/tablo/kod/terminal, farklı ekran DPI, koyu/açık tema, farklı font, kompresyon, düşük kontrast, küçük yazı, rotation, alt alta/parçalı numara, QR/barkod, içerik olmayan görüntü ve kasıtlı kaçırma denemeleri.

Ölçümler: alan/sınıf bazında kaçırma, yanlış maskeleme, hiç görülmeyen metin, hassas glifin dışarı kalan pikseli, hatalı serbest bırakma, karantina oranı ve kullanıcı iş akışı etkisi. OCR confidence ile recall yerine geçmeyin. Bu sürümün hangi eşiklerle üretime kabul edileceği müşteri tarafından belirlenmeli; burada karşılanmış bir SLO verilmez.

## 4. Zorunlu arıza ve izolasyon testleri

Decoder bomb/malformed input, model/binary kaybı ve değişimi, stderr/stdout taşması, timeout, iptal, worker kill, restart, queue dolması, maximum image, aynı anda farklı tenant istekleri, tenant policy rollover, attach-swap ve provider upload retry. Her senaryoda ham byte çıkmadığını gerçek entegrasyon sınırında yakalanan trafiğe karşı doğrulayın.

Ayrı worker kimliği, ağ kapatma, read-only modeller/config, cgroups/PID/CPU/memory, core dump/swap politikası, secret-free environment ve disk policy gereklidir. App-level concurrency yalnız paylaşılan engine örneği içinde geçerlidir; cluster genelinde sınır sağlamaz. Queue dolduğunda orijinali yollamayın.

## 5. Gözlem ve açılış

İlk aşama: `mode:'block'` veya `release:'manual'`. Sadece statik hata kodu, policy sürümü ve izin verilen sayısal audit alanları. OCR metni, QR payload, orijinal dosya adı/hash ve görüntüleri normal telemetriye yazmayın. İnceleme deposu gerekiyorsa ayrıca şifreleme, RBAC, tutulma süresi ve denetim uygulayın; pakette böyle bir depo yoktur.

İkinci aşama: müşteri holdout ve gerçek egress fault testlerinden sonra sınırlı tenant/kullanıcı grubunda automatic. Gerçek yük altında p50/p95/p99, memory, CPU, concurrency, reject oranı ve UI bekleme davranışı ölçün. Mevcut sentetik 1200×620 örneklerde yaklaşık 6,3–7,0 saniyelik OCR+mask+yeniden tarama süresi görüldü; bu frontier latency veya üretim SLO kanıtı değildir. GPU zorunlu değil; performans ücretsiz değil.

Son aşama: bağımsız güvenlik incelemesi, değişiklik onayı, rollback (korumayı atlamayan), incident prosedürü ve müşteri kabul imzası. “Production ready” etiketi ancak bu kanıtlara dayanmalıdır.
