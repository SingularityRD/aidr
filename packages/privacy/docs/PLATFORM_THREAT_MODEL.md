# 0.5 güven sınırları ve modalite tehdit modelleri

## Ortak güven sınırı

Güvenilmeyenler: prompt, OCR metni, dosya/gövde/başlık, model çıktısı, araç cevabı, browser page DOM, kullanıcı tarafından beyan edilen rol/tenant/hedef, ağ response'ları. Güvenilir olması gerekenler: pinned broker public keys, hesap/cihaz iddialarını üreten gerçek broker'lar, yönetici konfigürasyonu, server runtime/OS, private state dizini ve key management, callback/taşıyıcı implementasyonları.

mTLS, device tokenını doğru bağlantı sertifikasına bağlar; CA'nın yanlış kişiye sertifika vermesi, cihaz private key'inin çalınması veya yetkili broker'ın yalan beyanı çözülmez. Same-process arbitrary code veya root, bellekten anahtar okuyabilir ve servisi bypass edebilir. Python libseccomp belirli syscall sınıflarını sınırlar, çekirdek açıklarına karşı kanıt veya tam sandbox sertifikası değildir. OCR worker'ı ayrıca no-network OS/container sınırına alınmalıdır.

At-most-once yerel dispatch kaydı, exactly-once uzak tool/provider etkisi değildir. Ağ kopuşunda durum unknown olur; reconciliation gerekir. Yerel append-only trigger ve HMAC chain, WORM/object-lock depolamanın yerine geçmez. Whole-DB rollback harici anchor ile sınanmıştır; yetkili DB yöneticisinin seçici valid-cell replay'ine karşı bağımsız tamlık kanıtı yoktur.

Düşük güvenli veya desteklenmeyen içerik engellenir. Genel PII gizleme, dokümanın bütün gizlilik derecesini düşürmez. Kaynak/provenance politikası ve kurum veri sınıfı ayrıca taşınmalıdır. “Sıfır sızıntı”, “tüm prompt injection'ları önler”, “savunma sertifikalı” veya “rakip ürünlerle eşdeğer” iddiası yapılmaz.

## Modalite başına ayrı değerlendirme

| Modalite | Kaçırma/zarar | Bu paketteki kontrol | Yayınlama kararı / eksik |
|---|---|---|---|
| Ses | ASR yanlış tanıma, overlapped konuşma, sessiz/düşük ses, çok kanal, voice biometric, metadata | Gerçek PCM16 WAV decode/rebuild, bütün kanalları susturma, kaynak/model hash'i ve timestamp/confidence kontrolü; 150 ms pay | Tam sessizleştirme sesi kaldırır. PII aralıkları `review` + `output:null`; `reviewArtifact` sadece yetkili incelemeye aittir. ASR modeli ve gerçek konuşma değerlendirmesi yok |
| Video | Bir karelik sızıntı, altyazı/ek track, ses, keyframe-only tarama, değişken frame rate | `requireCompleteVideoCoverage` eksik kare/ses bildirimi reddeder | Bu sadece adapter sözleşmesidir; gerçek decode/OCR/ASR/transcode yok. Video engellenir |
| Yüz | İsim olmasa da tanınabilirlik; profil/occlusion; model false negative | Uzman dedektör olmadan blok | Yüz dedektörü/blur/redaction kalite testi yapılmadı; kimlik tanıma amacı yok |
| El yazısı | OCR'ın emin şekilde yanlış okuması, birleşik karakterler, çok dil | Uzman dedektör olmadan blok | Typed OCR başarımını el yazısı başarımı diye taşımayın |
| İmza | Biyometrik/kimlik doğrulama bilgisi, taranmış sayfada küçük işaretler | Uzman dedektör olmadan blok | Gerçek imza localization ve bağımsız mask coverage gerek |
| CAD/teknik çizim | Geometri, ölçü, layer, parça numarası ve embedded object; yalnız yazı OCR'ı yetersiz | Format/policy blok | CAD parser, geometri sınıflaması ve kuruma özgü IP politikası yok |
| Steganografi | Piksel LSB/frekans/renk kanalı, ses/format gizli yükleri, kasıtlı dağıtılmış veri | Görseller fresh opaque PNG, metadata/container artıkları atılır; uzman gerektiren mod explicit block | Re-encode, bütün steganografiyi temizlemez. Güvenilmeyen raster içindeki gizli veriye tolerans yoksa tüm görsel gönderimini engelleyin |
| PDF/Office | Macro/JS, OLE, attachment, external relation, image/scanned page, hidden/customXML, ZIP bomb | Güvenli subset, boyut/expansion/depth, yeni plain TXT, seccomp | Formatı korumaz; scanned/image/unknown/legacy/encrypted/customXML reddedilir. PII doğruluğu ayrıca gerekli |

## Sahada yapılacak negatif testler

Kişisel sağlayıcı hesabı, oturumu kapatılmış kullanıcı, stale token, farklı TLS sertifikası, yeni sekme/provider URL, prompt->ilk-upload yarışı, clipboard image, drag/drop, dosya input'u, direct API/CLI, yönetilmeyen browser, extension devre dışı, native eksik, log diski dolu, cihaz saati geri, eski DB geri yükleme, retry storm ve kısmi kaynak listesi ayrı senaryolardır. Bu pakette bir kısmı unit/yerel süreç düzeyinde test edildi; kurumdaki bütün rotalarda kabul yerine geçmez.

Belirsizlikte review/block açık tutulmalıdır. İnsan incelemesi bulunmadan “review” durumunu allow'a dönüştürmek bu tasarımın dışında ve tehlikelidir.
