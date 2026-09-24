# Visual Privacy: güven modeli ve kabul edilmeyen iddialar

## Güvenilen bileşenler

Yönetici politikası, Node/Python runtime, onaylı metin motoru/NER sağlayıcısı, Tesseract dil dosyaları, native decoder'lar, pyzbar/libzbar, işletim sistemi ve yerel backend güvenilen hesaplama tabanıdır. İstemcinin yolladığı OCR, koordinatlar, MIME, uzantı, URL veya “zaten temizlendi” beyanı güvenilmez. Custom ImageBackend yalnız yönetici tarafından sağlanan kod olabilir.

Hash bağı, aynı byte snapshot'ın taranıp işlendiğini kontrol eder; kök yetkili saldırgana karşı güven veya imzalı yazılım kanıtı değildir. Manifestin kendisi ve native shared library'ler salt okunur ve dışarıdan doğrulanmış deployment içinde tutulmalıdır. Bu sürüm tüm shared library'leri hash'leyip imzalamaz.

## Önlenen hata sınıfları

Orijinal byte'ın tarama sonrası değiştirilmesi; parça parça erken yayın; bir ek reddedildiği halde diğer ekleri yayınlama; maskelenecek alanların yanlış/bounds dışı/taşan koordinatları; renderer'ın maskelemeyip başarılı demesi; PNG metadatası/trailer/alpha aktarılması; decoder ve OCR limitlerinin aşılması; worker timeout/çökmesinde orijinale dönme; uygulama API anahtarlarının child env'ye aktarılması; içeriğin raw exception veya OCR stdout üzerinden audit'e yazılması.

Piksel doğrulayıcı planlanan kutulardaki siyah RGB değerlerini bağımsız denetler. Kutunun OCR/PII açısından doğru ve yeterli bulunduğunu matematiksel olarak kanıtlamaz. Komşu piksel/bağlam, farklı kaynak kopyaları veya maskelenmeyen alanlar veri içerebilir.

## Kapsam dışında veya yetersiz doğrulanmış

- OCR'ın hiç bulamadığı, yanlış okuduğu veya yüksek güvenle yanlış sınıflandırdığı metin. Güven puanı gerçek başarım garantisi değildir. Kalan içerik taraması aynı motoru kullandığı için aynı kör noktaları paylaşabilir.
- El yazısı; düşük çözünürlük; çok küçük/eğik/karışık döndürülmüş yazı; karmaşık tablo/sütun ilişkilendirme; fotoğraflanmış ekran perspektifi. EXIF yönü uygulanır, genel deskew/perspektif düzeltici uygulanmaz.
- Yüz, imza, biyometri, kimlik fotoğrafı, çizim/CAD, harita, tıbbi görüntü veya metin olmayan kurumsal sır. `all-text` bu sınıfları temizlemez.
- Steganografi, düşük bit düzlemleri veya maskelenmeyen RGB piksellerine kodlanan veri. Metadata kaldırma, kapsamlı steganografi silme değildir.
- Data Matrix/PDF417 gibi kullanılmakta olan libzbar sürümünün tanımadığı kodlar; bozuk/örtülü/küçük kodlar. QR payload yorumlanmaz; tanınan kodlar konumsal olarak ele alınır.
- Animasyon, PDF/SVG/Office içine gömülü görüntü, video, HEIC, desteklenmeyen dosyalar. Bu fonksiyona geldiklerinde engellenir; başka upload yoluna yönlendirilip atlanmamalıdır.
- Yönetilmeyen endpointler, kişisel telefonla ekran fotoğrafı, ekran kayıtları, izin verilmiş alternatif çıkışlar, bu SDK'yı çağırmayan istemciler.

## Üretim güvenliği

Process sınırı sandbox değildir. Native decoder/OCR bug'ları için ayrı kullanıcı, read-only root, network deny, seccomp/AppArmor/SELinux, cgroups/PID limits, host izolasyonu ve güvenlik yamaları gerekir. Worker'ın SIGKILL/CPU/address-space limitleri bu kontrollerin yerine geçmez. Linux test edilmiştir; Windows/macOS production davranışı doğrulanmamıştır.

Python/JavaScript string ve GC bellekleri deterministik olarak güvenli silinemez. Buffer temizlemeleri best-effort'tür. Swap/core dump/diagnostic/heap snapshot politikası gerekir. Worker görüntü temp dosyası yazmaz; host crash/swap/EDR dump politikasını modül tek başına yönetemez.

Varsayılan `manual`, OCR hatalarını “temiz” sayıp otomatik veri çıkarmamayı amaçlar. Onay workflow'u ve güvenli insan inceleme arayüzü ayrıca uygulanmalıdır. Kapsam dışı veride hata toleransı olmayan çıkışlar için `mode:'block'` gerekir. Buradaki öneri bir sertifikasyon veya hukuki uyum sonucu değildir.
