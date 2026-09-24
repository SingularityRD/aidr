# 0.3.0 için tespit edilen boşluklar, eklenenler ve kalan kabul kapıları

Bu belge bir pazar üstünlüğü/uyumluluk sertifikası değil, kaynak koduna dayalı kapsam haritasıdır.

## Eklenmiş boşluk kapatmaları

| Önceki eksik/risk | 0.3.0 uygulaması | Önemli sınır |
|---|---|---|
| Çalışan modül var, tarayıcı giriş noktası yok | Chrome MV3 + ChatGPT/Gemini/Claude adaptörleri | Gerçek kurulu MV3/canlı arayüz doğrulaması bekliyor |
| Ham yazı site editöründe okunabilir | Ayrı eklenti kökenli Güvenli Yaz; secure-compose kilidi | Guard kipi ham DOM'u gizlemez; başka uygulamaları kapsamaz |
| Görsel gönder düğmesinden önce yüklenebilir | Doğrudan file input/paste/drop engellemesi; yalnız temiz dosya aktarımı | Bilinmeyen/programatik ağ yolları için gateway/endpoint gerekir |
| Tarayıcı ve Node kuralları ayrışabilir | Dedektör, normalizasyon, doğrulayıcı ve span birleştirme ortak kaynak | Tarayıcı çekirdeğinde gerçek öğrenilmiş NER veya HMAC tokenizasyon yok |
| Aynı temiz karar farklı veriye uygulanabilir | Tek kullanımlık, sekme/köken/doküman/politika bağlı aktarım yetkisi | Worker kapanırsa yeniden tarama gerekir |
| Yönetilen politika hatası sessiz izin açabilir | Karantina DNR kuralları, strict parser, yönetilen politika kaybolma kilidi | Eklentinin kaldırılmasını MDM zorunlu kurulum önlemeli |
| OCR'a web sayfasından izinsiz erişim | UI-only dosya RPC, doğrulanmış sender, native allowed_origins, stdio | Aynı kullanıcıdaki zararlı native süreçlere karşı OS izolasyonu gerekir |
| Native büyük dosya/bozuk chunk | 192 KiB chunk, sıralama, boyut/hash/kimlik denetimi | Trafik yükü / cgroup / Windows Job Object dağıtım kapısı |
| JSON/CSV anahtarları hassas içerik taşıyabilir | Strict JSON, başlık duyarlı CSV/TSV, formül başlangıcı blok | PDF/Office/arşiv parsers yok; tip değiştiren maske sonrası şema doğrulaması gerekir |
| API anahtarı ve kurum projesi PII dışındadır | SECRET/PRIVATE_KEY/INTERNAL/CLASSIFIED varsayılan blok; özel literal sözlük | Kaynak kodu/sınıflandırılmış belgeyi semantik olarak tam tanıma yok |
| Görüntüde okunabilen bilgi kodlanmış olabilir | Önceki QR/barkod ve piksel doğrulama motoruna gerçek native bağlantı | Barkod kapsamı libzbar'ın algılama desteğiyle sınırlı; steganografi yok |
| Audit ikinci bir veri sızıntısı kaynağı olabilir | İçeriksiz, sabit şemalı, süreli sayaç; Sync yok | Merkezi, imzalı değişmez SIEM deposu/kimlik ilişkisi eklenmedi |
| Zengin metin HTML'i kod çalıştırabilir | Düz metin node'ları/setter; innerHTML kullanılmaz | Zengin biçimlendirme/özelleşmiş editör eklentileri korunmaz |
| Ses kanalı metin taramasını atlayabilir | Tanınan ses/mikrofon kontrolünün engellenmesi | ASR uygulanmadı, tüm WebRTC/medya çıkışını engelleme iddiası yok |

## Kabul edilmeden üretim açılamayan alanlar

### A. Kurulu eklenti ve sağlayıcı sürümleri

Yönetici izinli Windows/macOS/Linux Chrome test matrisi oluştur. İmzalı dağıtım kimliği, CSP, gerçek isolated-world mesajlaşması, worker uyuma/uyanma, native-host kayıtları ve kurum politikalarını test et. Oturum açılmış ChatGPT/Gemini/Claude için paste, drag/drop, yerel dosya, buluttan dosya, düzenleme, yeniden gönderme, dallanma, ses ve A/B editör varyantlarını kapsa. Bilinen adaptör değişince otomatik sözleşme testi durumu kırmızıya dönmeli; güncel adaptör yayımlanmadan izin verilmemeli.

Bu ortamda bunların kurulu MV3 bölümü kurumsal Chrome politikası nedeniyle çalıştırılamadı. Chromium DOM fixture'ları bu açığı kapatmış sayılmaz. Eklenti/gateway dışında web, API, mobil veya desktop istemciyle yapılan çıkışlar bu paketin kapsaması değildir.

### B. Gerçek NER ve OCR doğruluğu

Türkçe/İngilizce, etiketli ve etiketsiz kişi/adres, yanlış yazım, Unicode, tablo, dark mode, düşük çözünürlük, eğiklik, farklı DPI ve çapraz dil verileriyle bağımsız holdout kümesi gerekir. Kurumun toleransına göre sızıntı recall'ı, aşırı maskeleme, risk düzeyine göre hatalar ve manuel inceleme oranı ölçülmeli. Model deklarasyonundaki dil/tür listesi gerçek başarı kanıtı değildir.

Tam otomatik görsel yayını için yalnız OCR güven puanı veya aynı motorla ikinci tarama yeterli kalite kanıtı değildir. Bu teslimde yeni Native Messaging yolunda yalnız **bir Türkçe sentetik OCR örneği ve altı bilinen hassas satır** yeniden doğrulandı. Önceki 0.2 görsel değerlendirmesi ayrı tarihsel kanıttır; yeni bağımsız bir benchmark diye sayılmadı. Hiçbir gerçek NER ağırlığı bu teslimde çalıştırılmadı.

### C. Native dağıtım ve sistem güvenliği

Node/Python/Tesseract/Pillow/libzbar bağımlılıklarını onaylı depolardan kilitle, hash ve dijital imza kontrolünü güvenilir köke bağla. npm audit bu ortamda ağ/DNS erişimi nedeniyle çalıştırılamadı; zafiyet yokluğu iddiası yoktur. OCR çalıştırıcısı ayrı bir OS sandbox değildir. Ağ çıkışı yasağı, syscall kısıtları, cgroups/Job Objects, kaynak limitleri, crash-dump/swap politikaları, geçici dosya konumları ve kaldırma/güncelleme akışı gerekir.

Windows launcher kaynak ve derleme betiği sağlandı, bu ortamda derlenmedi/çalıştırılmadı. macOS native çalışma zamanı da test edilmedi. Hazırlayıcı yalnız dosya üretir, kendiliğinden sistem politikası/registry değiştirmez. Üretim dağıtımında kullanıcı tarafından değiştirilemeyen launcher/config/model yolu gerekir.

### D. Merkezi yönetim ve kalıcı yetkilendirme

Bu pakette hazır SaaS dashboard, SSO/SCIM, tenant backend, olay webhook'u, SIEM konektörü, imzalı audit zinciri ve insan onay kuyruğu yoktur. Yerel sayaç ve policy şeması bunlar için entegrasyon noktasıdır. Gerçek cihaz/kullanıcı kimliği MDM ve AIDR backend'den gelmelidir; web sayfasının gönderdiği kullanıcı beyanına güvenilmemelidir.

### E. Başka veri kanalları

PDF/Office/arşiv açma, yüz/imza/el yazısı, ses, video, CAD, ekran paylaşımı, clipboard geçmişi, canvas, şifreli arşiv ve steganografi bu teslimin kapsamı değildir. Reddedilen dosyayı orijinal olarak gönderme fallback'i eklenmemelidir. Kurum bu kanalları istiyorsa ayrı parser/sandbox/policy hattı ve gerçek gönderim öncesi kapı gerekir. Kabulden önce desteklenmeyen kanallar ağ/endpoint politikasıyla kapatılmalıdır.

## Üretim öncesi karar

BMC benzeri hassas kurumda başlangıç: yönetilen profil, zorunlu eklenti, secure-compose, onaylı TR/EN NER gereksinimi, görüntülerde inceleme/engelleme ve ayrıca gateway/endpoint egress kontrolü. Bunlar bir mimari öneridir; müşteri kabulü yerine geçmez. Bu paket **çalıştırılmış testleri bulunan üretim adayıdır**, mutlak sızıntısızlık veya mevzuata kendiliğinden uyum garantisi değildir.
