# AIDR Visual Privacy — Test ve teslim raporu

Sürüm: **0.2.0-rc.1**. Rapor: **24 Eylül 2026**. Durum: test edilmiş entegrasyon/üretim adayı; müşteri üretim kabulü veya bağımsız doğruluk sertifikası değil.

## Sonuç özeti

| Test grubu | Geçen / toplam |
|---|---:|
| Önceki metin modülünün Node regresyonları | 330 / 330 |
| Yeni görsel modülünün Node testleri | 188 / 188 |
| Önceki Python NER protokol/artefakt testleri | 38 / 38 |
| Yeni Python görsel/worker testleri | 72 / 72 |
| **Birim + entegrasyon toplamı** | **628 / 628** |
| Gerçek yerel OCR ile ayrı sentetik pipeline senaryoları | **8 / 8** |
| Beş gerçek görsel çıktısında hassas glif satırlarının piksel kontrolü | **29 / 29** |

628'e OCR pipeline senaryoları veya property loop iterasyonları eklenmedi. Node toplamı 518'dir. Testler sıfır başarısız ve sıfır atlanan sonuçla tamamlandı. `npm run check` başarılı.

Derlenmiş `dist/**/*.js` için ölçülen kapsam: satır **%99,03**, dal **%93,04**, fonksiyon **%96,20**. Bunlar Python kapsamı, PII recall, OCR başarımı veya kaçırma oranı değildir. Bazı süreç/CLI hata dalları çalıştırılmamıştır; tabloda toplam kapsam bununla birlikte verilir.

Ham kanıt: `all-node-coverage.txt`, `baseline-ner-tests.txt`, `python-tests.txt`, `typescript-check.txt`, `test-summary.json`.

## Neler sınandı?

Kaynak byte snapshot/mutation; hash ve geometry uyuşmazlıkları; emoji/Türkçe UTF-16 offset; bütün kelime/satır maskelemesi; bağlama ve satır düzenine bağlı PII; özel sır/gizlilik engelleme politikaları; eksik NER beyanı; düşük güvenli/küçük kelimeler; hiç OCR çıkmaması; görünür QR engelleme/maskeleme; model/binary manifest bozulması; worker timeout, iptal, stderr/stdout sınırı ve uygulama secret env'sinin aktarılmaması; malformed/animasyonlu/büyük/unsupported görseller; EXIF yönleri; alpha/metadata temizliği; bağımsız CRC/PNG filtre/maske pikseli; CLI güvenli ve üzerine yazmayan yayın; image stream erken çıkış önleme; tüm mesaj/çoklu ek için toplu ret.

Yeni property döngüleri: 10.000 geometri/containment vakası, 1.000 PNG corruption vakası ve 2.000 Python piksel kutusu. Önceki metin testlerindeki üretilmiş vakalar korunmuştur. Bunlar bağımsız etiketlenmiş gerçek dünya görüntüleri değildir.

Node visual unit testlerinde OCR açıkça fake backend/worker ile izole edilir. Python 72 test gerçek Pillow işlemleri ve QR decode/piksel işleme içerir, Tesseract çıkarımı içermez. Gerçek Tesseract aşağıdaki ayrı pipeline testlerindedir. Önceki 38 NER testi gerçek öğrenilmiş model çıkarımı anlamına gelmez.

## Gerçek OCR pipeline sonuçları

Tesseract **5.5.0**, yerel `eng+tur`, `psm 11 + 6`; Python Pillow **12.3.0**, pyzbar **0.1.9**. Sonuçlar kurallı PrivacyEngine ile alındı; öğrenilmiş NER modeli yok. Test politikası açıkça `release:'automatic'` ve `uncertainText:'redact-line'` olarak ayarlandı; ürünün varsayılanı manual/review'dur.

| Senaryo | Karar | Maske sayısı | Uçtan uca süre |
|---|---|---:|---:|
| Türkçe PNG, 1200×620 | redact | 6 | 6.907,180 ms |
| İngilizce koyu tema PNG, 1200×620 | redact | 5 | 6.972,805 ms |
| Türkçe JPEG, 1200×620 | redact | 6 | 6.464,637 ms |
| EXIF ile yön düzeltilen JPEG | redact | 6 | 6.278,984 ms |
| Türkçe lossless WebP | redact | 6 | 7.034,186 ms |
| QR, varsayılan politika | block | 0 | 2.773,145 ms |
| QR, açık maskeleme politikası | redact | 1 | 5.963,469 ms |
| Boş/okunamayan görüntü | block | 0 | 2.602,124 ms |

Süreler aynı geliştirici test ortamında az sayıda tekil çağrıdan gelir; kuyruk ve gerçek eşzamanlı trafik yoktur. OCR+mask+aynı motorla tekrar OCR/native process başlatma dahil. OCR/PII SOTA karşılaştırması, p95/p99, üretim throughput'u veya kapasite garantisi çıkarılamaz. GPU kullanılmadı. Tüm işlem ağacının tamamlanmış RSS ölçümü elde edilmedi; toplam bellek iddiası yapılmıyor.

İlk toplu test komutu araç wall-clock limitinde dört başarılı vakanın ardından kesildi. Bu dört vakanın tamamlanan assertion'ları/çıktıları ve konsol kayıtları saklandı; WebP ile kalan üç vaka ayrı kısa çalıştırmalarda tamamlandı. Birleştirilmiş rapor `e2e-combined.json`; kaynakları `e2e-console.txt`, `webp-test.json`, `e2e-final-three.json`. Bu kesinti model/test assertion başarısızlığı olarak sayılmadı; suite'in tek uninterrupted load test olduğu da iddia edilmiyor.

Beş PII görselindeki Türkçe kişi/e-posta/telefon/T.C. kimlik/IBAN/adres ve İngilizce kişi/e-posta/telefon/kart/adres satırları beklenen türlerde bulundu. Font renderer'ın bilinen hassas glif sınırları gerçek çıktı PNG'lerinde tamamen RGB(0,0,0) idi; **29/29 satır**. Piksel karşılaştırması OCR'ın kendisine değil sentetik ground truth'a dayanır. `pixel-ground-truth.json` kanıtı ve `.truth.json` kaynakları dahil.

## Anlamı ve sınırlar

Gerçek OCR çalıştırıldı ve metin PII motoru gerçek görüntü koordinatlarına bağlandı. Bu, yalnız mock demo değildir. Ancak örnekler geliştirici tarafından hazırlanmış okunaklı sentetik görüntülerdir. Zor/adversarial kurumsal dataset, etiketsiz serbest isim/adres NER doğruluğu, her barkod ailesi, yüz/imza, el yazısı, steganografi, küçük/eğik/bölünmüş yazı ve kaçırma oranı kanıtlanmadı.

Savunma müşterisine otomatik açılış için önce `docs/VISUAL_DEPLOYMENT.md` kapıları tamamlanmalıdır. Tarayıcı/endpoint/gateway yakalama katmanı bu pakette kurulmuş değildir. Bu modüle verilmemiş görüntülerin gönderimini engelleyemez.

## Paket kurulum kontrolü

TGZ boş bir dizine `npm install --offline --ignore-scripts --no-audit --no-fund` ile kuruldu. Metin API'si ve dört yeni visual export import edildi. Kurulan paketin CLI'si kendi paket içindeki worker yolu üzerinden gerçek Türkçe OCR çalıştırdı; altı hassas satırı maskeledi. Çıktı referans temiz PNG ile byte-for-byte eşleşti. Bu ek smoke çalıştırması, yukarıdaki sekiz senaryodan ayrı bir dağıtım kontrolüdür (sekiz test sayısı artırılmadı). Kanıtlar: `installed-package-cli.json` ve `package-smoke.json`.
