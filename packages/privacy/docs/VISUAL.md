# AIDR Visual Privacy 0.2.0-rc.1

Ekran görüntüsü ve görsel eklerini metin PII motoruna bağlayan, yerel OCR kullanan kontrol katmanı. Bu sürüm çalışan bir üretim adayıdır; bağımsız denetlenmiş veya savunma müşterisi tarafından kabul edilmiş nihai ürün değildir. Önceki metin motoru korunmuştur. Yeni API `@singularity/aidr-privacy/visual` altındadır.

## Güven sınırı

Yakalanması gereken şey ekran görüntüsünün alınması değil, görüntünün kurum sınırı dışına gönderilmesidir. SDK kendiliğinden tarayıcıya, işletim sistemine, dosya yükleme alanına veya ağ geçidine kurulmaz. İlgili gönderim noktasından çağrılmadığı trafiği göremez. Yönetilmeyen cihazlar ve telefon kamerası kapsam dışıdır.

İşlem sırası:

`Orijinal byte snapshot → format/boyut kontrolü → EXIF yön düzeltme ve RGB oluşturma → yerel eng+tur OCR → mevcut PII/politika motoru → koordinat eşleme → siyah piksel maskelemesi → kalan metin/kod taraması → bağımsız PNG/piksel doğrulaması → yeniden oluşturulmuş PNG`

Orijinal dosya ASLA başarılı sonuç yerine fallback değildir. `result.output === null` olduğunda hiçbir görüntü gönderilemez. `review`, gönderme izni değildir.

## Uygulanan yetenekler

- Tek kare PNG, JPEG ve WebP. Başlık baytları ve gerçek decoder çıktısı kullanılır; dosya uzantısı veya istemci MIME beyanı yetki kaynağı değildir. APNG, animasyonlu WebP ve diğer formatlar engellenir. PDF/SVG/TIFF/GIF/HEIC/video desteği yoktur.
- Tesseract LSTM, `eng+tur`, varsayılan `--psm 11` ve `--psm 6`. Bunlar aynı motorun iki yerleşim denemesidir; bağımsız iki model değildir. GPU veya bulut OCR servisi gerekmez. Model yükleme/çalıştırma maliyeti vardır.
- Türkçe karakterleri koruyan kelime konumları; JavaScript UTF-16 metin aralıklarından kaynak kutularına eşleme. Yerel OCR sırası ve geometrik satır sırası incelenir; bu genel tablo anlama modeli değildir.
- Mevcut kurallarla kişi/adres alanları, e-posta, telefon, T.C. kimlik, IBAN, kart, sır ve kurum sözlüğü. Serbest metinde kişi/adres başarımı önceki NER katmanının sınırlarını taşır.
- Varsayılan bütün satır maskelemesi ve kenar payı. `granularity:'word'` daha az alanı kapatır; kelime sınırı/komşu içerik riski değerlendirilmelidir.
- Piksel değerlerini opak siyaha değiştirme. Blur, pixelation, CSS kutusu veya ayrı üst katman kullanılmaz. Maskenin dışında kalan içerik korunur; bunun tüm görüntünün anonim olduğu anlamına gelmediğine dikkat edin.
- Node tarafında bağımsız PNG CRC/decompression/filtre ve siyah piksel kontrolü; yalnız RGB8 IHDR/IDAT/IEND çıktısı. EXIF/XMP/ICC/açıklama/thumbnail/alpha ve trailing dosya verisi aktarılmaz. Maskelerden sonra kalan PII/kod bulgusu çıkarsa çıktı engellenir.
- pyzbar/libzbar ile tanınabilen QR ve barkodlar. Varsayılan herhangi bir kod bulgusunda engelleme. Açık `barcodeAction:'redact'` kod alanını tümden kapatır. Payload Node'a veya audit'e gönderilmez. Tüm barkod aileleri/döndürülmüş/bozuk kodlar kapsanmaz.
- Girdi boyutu, piksel/dimension, OCR metni, stdout/stderr, süre, işlem eşzamanlılığı ve bölge sayısı limitleri. Aşım/hata durumunda kapalı kalır.
- `AtomicImageGate`: bütün görüntü incelenmeden byte yayımlamaz. `protectMultimodal`: mesajın bir eki reddedilirse mesaj ve diğer ekler de yayımlanmaz.

## Yerel kurulum

Node 22.16+; Python ortamında test edilen sürümler `Pillow==12.3.0`, `pyzbar==0.1.9`. Ayrıca onaylı Tesseract 5 kurulumu, `eng.traineddata`, `tur.traineddata` ve native libzbar gerekir. Test ortamında Tesseract 5.5.0 kullanıldı. Bu bağımlılıkların veya modellerin byte'ları pakette yoktur. `npm install` Python/native bileşenleri indirmez.

```sh
npm install ./singularity-aidr-privacy-0.2.0-rc.1.tgz
# Python wheel'larını kurumun onaylı çevrimdışı wheel deposundan kurun:
/opt/aidr/venv/bin/python3 -m pip install --no-index --find-links /opt/approved-wheels \
  -r node_modules/@singularity/aidr-privacy/vision/requirements.txt
# Onaylı native program/model kurulumu tamamlandıktan sonra envanter oluşturun:
/opt/aidr/venv/bin/python3 node_modules/@singularity/aidr-privacy/vision/build_manifest.py \
  --tesseract /usr/bin/tesseract \
  --tessdata /usr/share/tesseract-ocr/5/tessdata \
  --output /etc/aidr/ocr-manifest.json
```

Manifest, halihazırda güvenilir kabul edilen kurulumun fingerprint envanteridir; kendi oluşturduğu imza/güven kanıtı değildir. Kök dizinleri ve dosyalar çalışan kullanıcı için salt okunur olmalıdır. Örnekteki yol ve paket kurulumları müşterinin işletim sistemine uyarlanmalıdır.

## CLI

`vision/config.example.json` dosyasını yönetici kontrolünde konuma kopyalayın, mutlak yolları düzenleyin. CLI yerel kural tabanlı metin motorunu kullanır; öğrenilmiş NER kurulumu SDK ile yapılır.

```sh
npx --no-install aidr-visual \
  --config /etc/aidr/visual.json \
  --input /private/inbox/screenshot.png \
  --output /private/outbox/sanitized.png
```

Varsayılan config `release:'manual'`: tespit yapılır ama dosya oluşturulmaz; exit code 2 ve `review` kararı döner. Bu pakette onay ekranı/insan inceleme servisi yoktur. Bu bir karantina/inceleme entegrasyon sinyalidir. Sadece onaylı test/politika için config içindeki `release` değerini `automatic` yapın. `uncertainText:'redact-line'`, bulunan düşük güvenli satırları da kapatabilir; hiç bulunmamış yazıyı kapatamaz.

CLI başarıda exit 0; engelleme/inceleme/I/O hatasında 2; kullanım hatasında 64. Çıktıyı tamamlandıktan sonra 0600 izinle yayımlar, mevcut dosyanın üzerine yazmaz. Kaynak ve hedef üst dizinleri güvenilir/özel olmalıdır. Yerel filesystem hard-link desteklemiyorsa yayın başarısız olur; orijinale dönmez. Kaynak sembolik bağlantıları desteklenmez; Windows dosya sistemi davranışı bu teslimde sınanmadı.

## SDK örneği

```ts
import { readFile } from 'node:fs/promises';
import { PrivacyEngine } from '@singularity/aidr-privacy';
import { LocalImageProcess, VisualPrivacyEngine } from '@singularity/aidr-privacy/visual';

const textEngine = new PrivacyEngine({profile:'strict', maxInputBytes:262144});
const visual = new VisualPrivacyEngine({
  textEngine,
  backend: new LocalImageProcess({
    python:'/opt/aidr/venv/bin/python3',
    tesseract:'/usr/bin/tesseract',
    tessdata:'/usr/share/tesseract-ocr/5/tessdata',
    manifest:'/etc/aidr/ocr-manifest.json',
  }),
  release:'manual',
  barcodeAction:'block',
  granularity:'line',
  policyId:'aidr-image-review-v1',
});
const result = await visual.protect(await readFile('/private/screenshot.png'));
if (result.output === null) {
  // BLOCK / REVIEW: kaynak görüntüyü göndermeyin.
} else {
  // Dış servise yalnız result.output + image/png + sabit dosya adı gönderilebilir.
}
visual.dispose();
textEngine.dispose();
```

Gerçek servis içinde motorları her istek için yeniden kurmayın; tek kontrollü servis/pool yaşam döngüsü kullanın. Her istek başına ayrı VisualPrivacyEngine yaratmak uygulama genelindeki `maxConcurrent` sınırını etkisizleştirir. Birden fazla replica için ayrıca toplam concurrency/queue/rate limiti gerekir.

## Politika seçenekleri

| Seçenek | Davranış |
|---|---|
| `mode:'block'` | Görseli parse etmeden reddeder. Kapsam dışı veri kabul edilemeyen çıkışlar için. |
| `release:'manual'` | İnceler, fakat gönderilebilir byte üretmez. Varsayılan. |
| `release:'automatic'` | Kontrolleri geçen maskelenmiş/yeniden oluşturulmuş PNG'yi verir. Yönetici onayı gerektiren seçim. |
| `mode:'all-text'` | OCR tarafından bulunan yazı satırlarını tümden kapatır. Bütün olası yazıyı/fotoğrafı bulma garantisi değildir. |
| `requireNer:true` | Metin motoru `rules-and-ner` kapsamı bildirmiyorsa reddeder. Bu, gerçek doğruluk sertifikası değildir. |

Kurumsal otomatik kullanımda `PrivacyEngine({profile:'defense', ner: approvedLocalNer})` ile birlikte `requireNer:true` kullanılabilir. Onaylı gerçek TR/EN NER modeli, kendi etiket eşlemeleri ve alan testleri ayrıca gerekir; bu sürümde öğrenilmiş NER çıkarımı doğrulanmadı.

## Testleri çalıştırma

```sh
npm run build
npm test
npm run test:coverage
python3 -m unittest discover -s ner -p 'test_*.py' -v
python3 -m unittest discover -s vision -p 'test_*.py' -v
```

`tests/visual/local-process.test.mjs` saf Python IPC testleri için `/usr/bin/python3` kullanır; başka platformda `AIDR_TEST_PYTHON` mutlak yolunu ayarlayın. Pillow testlerini onaylı venv Python'u ile çalıştırın. Gerçek OCR testleri ayrı tutuldu:

```sh
# Buradaki config sadece backend nesnesidir (CLI config içindeki backend alanı).
AIDR_VISION_CONFIG=/private/approved-backend.json npm run test:visual:e2e
# Kısıtlı test koşucularında parçalayabilirsiniz; [from,to) indeksleri:
AIDR_VISION_CONFIG=/private/approved-backend.json AIDR_E2E_FROM=0 AIDR_E2E_TO=4 \
  AIDR_E2E_REPORT=e2e-part1.json npm run test:visual:e2e
```

Test raporu: `reports/visual/TEST_REPORT.md`. Üretim kapıları: `docs/VISUAL_DEPLOYMENT.md`. Güven sınırları: `docs/VISUAL_THREAT_MODEL.md`.
