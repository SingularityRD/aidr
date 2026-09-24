# AIDR 0.4.0-rc.1 — Güncel test ve ölçüm raporu

**Çalışma tarihi:** 24 Eylül 2026. **Kapsam:** Önceki 0.3.0 modülünün üzerine eklenen enterprise kontrolleri ve kümülatif regresyon.

## Gerçekten çalıştırılan doğrulamalar

| Grup | Sonuç | Ham kanıt |
|---|---:|---|
| Değişiklik öncesi 0.3 Node baseline | 856 / 856 | `reports/enterprise/baseline-node.tap` |
| Yeni enterprise Node testleri | 325 / 325 | `reports/enterprise/enterprise-node.tap` |
| Bütün güncel Node testleri | **1.181 / 1.181** | `reports/enterprise/final-node.tap` |
| Python NER protokol/artefakt testleri | 38 / 38 | `reports/enterprise/python-ner.txt` |
| Python görsel worker testleri | 72 / 72 | `reports/enterprise/python-vision.txt` |
| Birim/entegrasyon toplamı | **1.291 geçti, 0 başarısız** | Yukarıdaki Node + Python; baseline tekrar eklenmez |
| Gerçek Chromium DOM, Chrome API sınırı test taklidi | **39 / 39** | `reports/browser/dom-e2e.json` |
| Gerçek native stdio/istemci, Chrome port'u test adaptörü | **13 / 13** | `reports/browser/native-e2e.json` |
| Yeni enterprise adapter + gerçek OCR + fsync audit | **1 / 1** | `reports/enterprise/visual-e2e.json` |
| Offline demo | 7 beklenen senaryo | `reports/enterprise/demo.json` |

Ayrı 53 DOM/native/görsel senaryosu, 1.291 Node/Python testine ek olarak raporlanır. Offline demodaki yedi örnek bağımsız test suite sayısına eklenmedi. Test döngülerindeki binlerce varyant da ayrı birim test gibi sayılmadı. Örneğin bir yeni test içinde 1.000 sentetik kayıt için 1.000 doğru kayıt eşleşmesi ve 1.000 yanlış çapraz-satır eşleşmesinin reddi denendi.

## Yeni testlerde neler kontrol edildi?

İmzalı politika değişikliği, yanlış tenant/anahtar, imza bozulması, sürüm düşürme, expiry, saat geri gitmesi, aktif tarama/yazı sırasında politika değişimi, kalıcı checkpoint yazısı ve timeout; normalleştirilmiş aynı-kayıt eşleştirmesi, belge parmak izi eşikleri, indeks tenant ayrımı ve kaynak sınırları; kaynak sınıfının türetmede korunması, yanlış/eksik/eski makbuz; kullanıcı/hesap/cihaz/grup/hedef reddi; içeriksiz audit, zincir değiştirme/sıralama/suffix kesme, fsync dosya yazısı, eski dosyayı/symlink'i ezmeme ve dosya sınırı; onay süre/oturum/kullanıcı/argüman/tenant bağları, paralel tek kullanım, araç tanım değişikliği, scope/şema/URL engeli ve executor hatası; TR/EN sinyaller, browser politika seçenekleri ve Türkçe kullanıcı açıklaması.

Bütün araç etkileri test callback'lerinde simüle edildi; gerçek bankacılık, savunma veya başka iş sistemi eylemi yapılmadı. Gerçek Ed25519, HMAC, dosya yazımı, Chromium DOM, native stdio ve OCR ayrı olarak çalıştı. Kimlik sağlayıcı/MDM/SaaS hesabı doğrulaması gerçek dış sisteme bağlanmadı.

## Kapsam ölçümü

Node `--experimental-test-coverage`, `dist/**/*.js` için:

- Satır kapsamı: **%98,70**
- Dal kapsamı: **%92,27**
- Fonksiyon kapsamı: **%96,84**

Bu yüzdeler PII yakalama doğruluğu, saldırı engelleme oranı, bütün platform kapsamı veya OCR recall değildir. Ayrı Chrome bundle, Python ve native binary coverage bu yüzdelere dahil değildir. Dosya adaptörünün gerçek donanım güç kaybı gibi bütün IO hata dalları test edilmedi. Ham tablo `reports/enterprise/coverage.txt` içindedir.

## Gerçek görsel doğrulaması

Mevcut native yol üzerinden Türkçe sentetik PNG tekrar işlendi: altı hassas satır maskelendi, çıktı piksel sınırları doğrulandı. Ayrıca yeni `EnterprisePrivacyGate.textAdapter()` doğrudan `VisualPrivacyEngine` içine bağlanarak aynı test görüntüsü işlendi. Bu yeni koşuda:

| Özellik | Ölçüm |
|---|---:|
| Girdi | 1.200 × 620 PNG, 39,810 byte |
| Çıktı | Yeni PNG, 8,370 byte |
| Bağımsız doğrulanan bilinen hassas satır | 6 / 6 |
| Gerçek, doğrulanan fsync audit kaydı | 4 |
| OCR + enterprise gate + yeniden tarama + piksel doğrulama | 2.365 saniye |

Bu tek sentetik görüntü doğrulaması; öğrenilmiş NER veya saha doğruluğu değerlendirmesi değildir. Tek görsel süresi p95/p99 üretim ölçümü değildir. Eski sürüm başka CPU'da ölçüldüğünden buradan sürümler arası hızlanma iddiası çıkarılmamalıdır.

## Yeni modülün yerel mikro ölçümleri

AMD EPYC 9V74 80-Core Processor, Node v22.16.0, Linux. Sıralı/ısınmış çağrılar. Her durumda beklenen allow/eşleşmeme kararı ayrıca assert edildi. İndeks testi 1.000 sentetik kayıt içerir. Gate ölçümünde indeks yoktur; indeks ve gate süreleri tek bir ölçüm gibi toplanıp sunulmaz.

| İşlem | Girdi byte | Örnek | Medyan ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| keyed record scan | 4096 | 200 | 2.412 | 2.989 | 3.366 |
| enterprise gate with in-memory acknowledged audit | 1024 | 200 | 0.518 | 0.816 | 1.082 |
| enterprise gate with in-memory acknowledged audit | 4096 | 200 | 1.123 | 1.620 | 2.582 |
| enterprise gate with in-memory acknowledged audit | 16384 | 200 | 3.839 | 4.785 | 6.428 |
| enterprise gate with local file fsync audit | 4096 | 100 | 1.447 | 2.169 | 3.163 |
| approved read-tool inspection | — | 200 | 0.159 | 0.357 | 0.602 |

Bellek için yalnız test sonunda toplam Node RSS örneği alındı: 56.88 MiB. Bu peak, artımlı modül belleği veya OCR süreç ağacının belleği değildir. Belleğe onay veren audit yazıcısı kalıcı değildir; tabloda gerçek yerel fsync kullanan ölçüm ayrı gösterilmiştir. Bu mikro ölçümler ağ, gerçek NER, yük altındaki eşzamanlı trafik, dağıtık veri deposu ve müşteri iş yükünü kapsamaz.

## Derleme ve paket kontrolleri

`npm ci --offline --ignore-scripts`, TypeScript strict build, extension typecheck ve bundle derlemesi çalıştırıldı. Yeni modül Node built-in kütüphanelerini kullanır; yeni üçüncü taraf runtime npm bağımlılığı yok. Yüklenebilir Chrome bundle'ı hem eski kimliği hem 0.4 manifest sürümünü korur.

Yayın doğrulama kanıtları ayrıca `package-smoke.json`, `extension-reproducibility.json` ve `release-verification.txt` dosyalarına yazılır. Paket temiz bir dizine çevrimdışı kurulup public export'lar ve paketlenmiş offline demo üzerinden kontrol edilir. Bu, npm registry'ye yayın veya kurulu MV3 doğrulaması değildir. Kaynak hash manifest'i bütünlük kontrolüdür; yayın imzası veya tedarik zinciri güven sertifikası değildir.

## Tekrarlama komutları

```bash
npm ci --offline --ignore-scripts
npm run build:all
npm run test:all
npm run test:coverage
npm run test:python
npm run test:vision-python
npm run test:extension:e2e
npm run demo:enterprise
npm run benchmark:enterprise
```

Gerçek OCR testleri için önce `vision/build_manifest.py` ile **önceden onayladığınız** OCR kurulumunun hash envanterini çıkarın. Bu işlem kendi başına o kurulumun güvenilir olduğunu kanıtlamaz. Yerel absolute path içeren backend JSON'unu hazırlayıp aşağıdaki ortam değişkenini verin:

```bash
AIDR_VISION_CONFIG=/absolute/path/to/backend.json npm run test:native:e2e
AIDR_VISION_CONFIG=/absolute/path/to/backend.json npm run test:enterprise:visual
```

Yerel çalışma ortamının absolute path içeren config'i taşınabilir olmadığı için yayımlanan kaynak paketine konulmaz. `vision/config.example.json` biçimi ve MERGE.md kullanılır. Raporlardaki çalıştırma zamanı hash/model bilgileri bir test ortamı envanteridir, üretim approval listesi değildir.

## Sınırlar

Kurulu MV3 ve canlı oturum açılmış ChatGPT/Gemini/Claude doğrulanmadı. Windows/macOS native kurulum, gerçek SSO/SCIM/MDM, gerçek çok tenant'lı AIDR uygulaması, dağıtık onay/kota/checkpoint deposu, öğrenilmiş TR/EN model çıkarımı ve bağımsız adversarial değerlendirme bu çalışmada yok. Önceki sürümden kalan tarihsel raporlar ayrıca durur; 0.4 için bu rapor ve `reports/enterprise` kanıtları esas alınmalıdır.
