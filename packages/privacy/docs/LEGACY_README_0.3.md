# Singularity AIDR Privacy — 0.3.0-rc.1

Yerel Türkçe/İngilizce PII ve sır kontrolü, ekran görüntüsü maskeleme, yapılandırılmış dosya temizleme ve **Chrome Manifest V3 AI Privacy Guard**.

**[Eklenti kurulumu ve API](BROWSER.md)** · **[Güncel test raporu](../reports/browser/TEST_REPORT.md)** · **[Eklenenler ve üretim kabul kapıları](BROWSER_GAPS_AND_GATES.md)** · **[Görsel motoru](VISUAL.md)**

## Neler eklendi?

ChatGPT, Gemini ve Claude için yerel ön tarama, gönderim kontrolü, yapıştırma ve dosya kapıları; ayrı eklenti kökenli **Güvenli Yaz**; yönetici PolicyJSON politikası; tek kullanımlık/sekme bağlı aktarım; TXT/JSON/CSV/TSV temizleme; yerel Native Messaging OCR/NER bağlantısı; ham içerik içermeyen süreli sayaçlar.

`extension/chrome/` derlenmiş eklentidir. Yönetici izinli geliştirme profilinde paketlenmemiş eklenti olarak yüklenir. Tarayıcıdaki metin kuralları için Node/Python/GPU gerekmez. Görseller için ayrı onaylı yerel OCR kurulumu gerekir; yoksa görsel gönderilmez. Kaynak, derlenmiş npm dağıtımı, testler ve yerel host hazırlama araçları bu pakette bulunur.

## Güven ve doğrulama sınırı

Bu teslim **test edilmiş bir üretim adayıdır**; imzalı mağaza/MDM yayını veya savunma kurumu kabulü değildir. Gerçek Chromium DOM ve gerçek native süreç/OCR testleri çalıştırıldı. Runner'ın kurumsal Chrome politikası nedeniyle kurulu MV3 eklentisi çalıştırılamadı; Chrome API sınırları DOM testinde açıkça taklit edildi. Canlı oturum açılmış ChatGPT/Gemini/Claude, Windows/macOS native runtime ve gerçek öğrenilmiş NER modelleri ayrıca doğrulanmalıdır.

Guard kipinde site editörüne yazılmış ham içerik ortak DOM'dadır. Onu sayfadan gizlediği iddia edilmez. Hassas işletim için ayrı Güvenli Yaz akışı, yönetilen secure-compose politikası ve ayrıca gerçek endpoint/gateway çıkış kontrolü gerekir. Dosyanın taramadan önce dışarı yüklenmesine izin verilmemelidir.

## Kaynaktan çalıştır

```sh
npm install --offline --ignore-scripts --no-audit --no-fund
npm run build:all
npm run test:all
npm run test:python
npm run test:vision-python
```

Node.js 22.16.0, TypeScript 5.8.3 ile bu ortamda doğrulandı. Tam kaynak ZIP'inde geliştirme bağımlılıkları `tools/vendor` içinde bulunur. Runtime npm paketi ve Chrome ZIP'i bu geliştirme araçlarına ihtiyaç duymaz. Native OCR bağımlılıkları/model ağırlıkları ayrıca kurulur; **font veya model ağırlığı teslim edilmez**.

## Programatik kullanım

```ts
import { BrowserPrivacyEngine } from '@singularityrd/aidr-privacy/browser';
import { protectDocument } from '@singularityrd/aidr-privacy/documents';

const scanner = new BrowserPrivacyEngine();
const result = scanner.protect('E-posta: synthetic@example.com');
if (result.output === null) throw new Error('AIDR_EGRESS_DENIED');
// Dış servise yalnız result.output verilebilir; orijinale fallback yok.

const csv = await protectDocument(
  'name,email\nJane Doe,jane@example.com',
  'csv',
  scanner,
);
if (csv.output === null) throw new Error('AIDR_DOCUMENT_DENIED');
```

BrowserPrivacyEngine kurallı çekirdektir, gerçek NER modeli değildir. Tam Node motoru (`@singularityrd/aidr-privacy`) önceki NER/HMAC/JSON/atomic text özelliklerini korur. Görsel modülü `@singularityrd/aidr-privacy/visual` altında kalır. Ayrıntılı Node/metin kullanımı [0.2 tarihsel README](LEGACY_README_0.2.md) ve mevcut docs altında yer alır.

## Kod haritası

| Dizin | Görevi |
|---|---|
| `src/` | Ortak Node PII motoru ve doğrulayıcılar |
| `src/browser/` | Tarayıcı motoru, dokümanlar, politikalar, biletler, audit |
| `extension/src/` | Service worker, içerik betiği, güvenli yazım arayüzü, native istemci |
| `extension/chrome/` | Yüklenmeye hazır MV3 dizini |
| `src/native/`, `native/` | Binary framing, stdio host, hazırlama araçları ve örnek politikalar |
| `src/visual/`, `vision/`, `ner/` | Önceki görüntü/OCR/yerel NER motorları |
| `tests/`, `scripts/extension/` | Birim, protokol, DOM fixture ve opt-in kurulu eklenti testleri |
| `reports/browser/` | Bu sürümün gerçek çalıştırma kanıtları |

`reports/visual/` 0.2.0 tarihsel sonuçlarını, doğrudan `reports/` altındaki eski dosyalar 0.1.0 sonuçlarını korur. Bunlar 0.3.0'ın yeni koşusu gibi sunulmaz. Güncel kaynak hash'lerini `npm run verify:release` ile doğrula. Bundled manifest bütünlüğü gösterir, dijital imza veya özgünlük kanıtı değildir. Test/benchmark raporlarını yeniden çalıştırmak hash farkı oluşturur.
