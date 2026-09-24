# AIDR Browser Privacy 0.3.0-rc.1 — test raporu

## Sonuç ve kapsam

**966 birim/entegrasyon test girdisi geçti.** Ayrıca **33/33 gerçek Chromium DOM senaryosu** ve **13/13 gerçek native süreç/istemci senaryosu** geçti. Bu kategoriler birlikte 1012 yürütülmüş test girdisidir. Bu sayı bağımsız müşteri verisi, doğruluk yüzdesi veya tüm kaçırma yöntemlerinin denendiği anlamına gelmez.

| Test grubu | Geçen / toplam | Kapsam |
|---|---:|---|
| Önceki metin + görsel Node regresyonu | 518 / 518 | Önceki 0.2 kaynak davranışı yeniden çalıştırıldı |
| Yeni browser/native Node | 338 / 338 | Ortak kurallar, politikalar, dokümanlar, service worker API sınırı taklidi, framing ve host hazırlama |
| Birleşik Node koşusu | 856 / 856 | Tek güncel coverage koşusu; 0 başarısız, 0 atlandı |
| Önceki NER Python testleri | 38 / 38 | Artefakt/manifest/protokol testleri; gerçek NER çıkarımı değil |
| Önceki görsel Python testleri | 72 / 72 | Worker/görüntü/piksel hata koşulları |
| Gerçek Chromium DOM | 33 / 33 | Gerçek DOM ve uygulama bundle'ları; Chrome API broker'ı taklit |
| Gerçek native stdio + production istemci | 13 / 13 | Gerçek Node alt süreçleri; Chrome port'u shim; bir gerçek yerel OCR örneği dahil |

## Tarayıcıda ne gerçekten çalıştırıldı?

Chromium **144.0.7559.96** içinde ChatGPT textarea, Gemini rich-textarea/contenteditable ve Claude ProseMirror fixture'ları kullanıldı. Üretim service-worker/compose bundle'ları ve içerik betiğinin aynı kaynak kodu çalıştı. İlk gönderme engelleme, ikinci açık gönderim, PII uyarısı, düz metin yapıştırmadan önce maskeleme, görsel paste/drop/file input reddi, yönetici politika değişimi, bilinmeyen/çift editör, IME/Shift+Enter, sekmeye bağlı çıktı ve UI akışı denendi. Önizleme ekranı `secure-composer-fixture.png` dosyasıdır; canlı sağlayıcı oturumu değildir.

**Chrome API'leri test broker'ı ile taklit edildi.** about:blank güvenli bağlam olmadığı için testte UUID Chromium'un gerçek CSPRNG'siyle, SHA-256 Python hashlib köprüsüyle sağlandı. Node protokol testleri gerçek WebCrypto kullanır. Bu yaklaşım Chrome'un gerçek isolated-world/CSP, installed-service-worker yaşam döngüsü, DNR uygulaması veya native-host OS kaydını doğrulamaz.

Kurulu eklenti yükleme girişimi ortamın yönetilen `ExtensionInstallBlocklist:["*"]` politikasıyla engellendi; `URLBlocklist:["*"]` de etkindir. Politikalar değiştirilmedi. Gerçek kurulum/live site sonucunu geçti diye saymadık. `installed-extension-status.json` bu sınırlamayı kaydeder. İzinli makinede çalıştırılacak ayrı opt-in installed smoke script'i teslimde var.

## Gerçek native/OCR hattı

Production Native Messaging istemci kodu, Chrome port nesnesini gerçek Node child stdin/stdout'una bağlayan test adaptörüyle çalıştı. UTF-8/JSON framing, host köken kontrolü, politika hash'i, offset'ler, kaynak/çıktı hash'i ve yanıt kimliği gerçek akışta doğrulandı. 315.000 byte belge birden fazla parçada gidip geldi. Yanlış eklenti kökeni, politika farkı, yok OCR, tahrif edilmiş digest ve correlation ID reddedildi.

Yeni native hatta `fixtures/visual/turkish.png` gerçek yerel Tesseract `eng+tur` ile işlendi. **6 bilinen hassas satırın tüm sınırları siyah piksel olarak ayrıca doğrulandı.** 39810 byte girdi, 8370 byte yeni PNG çıktı; süre **2.845 saniye**. Bu tek bir sentetik örnektir, gecikme SLA'sı veya genel OCR başarım ölçümü değildir. Görsel kapatmalar Node PNG doğrulayıcısından geçti. Model kapsamı `rules-only`; gerçek öğrenilmiş NER kullanılmadı.

Önceki 0.2 gerçek görsel denemeleri `reports/visual` altında tarihsel olarak bulunur; bu koşuda yeniden yapılmış yeni bağımsız benchmark diye sayılmaz. Görsel altmotorunun audit sürüm kimliği 0.2.0-rc.1 olarak korunur; dağıtım/Chrome/metin katmanı 0.3.0-rc.1'dir.

## Kod kapsamı

Birleşik Node coverage koşusunda ölçülen derlenmiş modüller için satır **%98,75**, dal **%92,33**, fonksiyon **%97,00**. Rapor `node-coverage.tap` içindedir. Filtre `dist/**/*.js` olup **çalıştırılan Node modüllerini** kapsar; bütün depo, browser IIFE bundle'ları, Python, Windows launcher, native host'un bütün satırları veya canlı sağlayıcı adaptörü için aynı oran iddia edilmez. Hiçbir kapsam yüzdesi PII/OCR recall'ı değildir.

Deterministik üretilmiş örnekler bazı testlerin içinde döngü olarak çalışır. Örneğin yeni portable IP testi 5.000 varyant içerir; bunlar 5.000 ayrı test girdisi olarak sayılmadı. Önceki fuzz/property döngüleri de önceki Node test sayısının içindedir.

## Kurallı çekirdek ölçümü

Aşağıdaki ölçüm Node v22.16.0 üzerinde, tarayıcıda kullanılabilen kurallı çekirdeğin ısınmış/sıralı çalışmasıdır. Her boyutta 100 ısınma ve 1.000 ölçüm; sentetik iki hassas alan içerir. Browser IPC, 250 ms debounce, UI, native bağlantı, NER/OCR ve eşzamanlı kullanıcı yükü dahil değildir.

| Girdi | Medyan | p95 | p99 |
|---|---:|---:|---:|
| 1 KiB | 0.213 ms | 0.373 ms | 0.471 ms |
| 4 KiB | 0.715 ms | 0.918 ms | 1.021 ms |
| 16 KiB | 2.771 ms | 3.486 ms | 4.042 ms |

Örneklenen en yüksek toplam Node RSS'i **58.72 MiB**; yalnız modülün ek belleği değildir ve çağrı içi her anın tepe değeri değildir. CPU `AMD EPYC 9V74 80-Core Processor`. Bu ölçümler son kullanıcı Windows bilgisayarına otomatik taşınamaz. Chrome dağıtımının yedi dosyası toplam **129,529 byte** (sıkıştırılmamış); OCR/model/Node/Python bu boyuta dahil değil.

## Tekrar üretim

`npm run test:coverage`, `npm run test:python`, `npm run test:vision-python`, `npm run test:extension:e2e` ve onaylı OCR backend yapılandırmasıyla `npm run test:native:e2e`. Doküman: `docs/BROWSER.md`. Geliştirme bağımlılıklarının çevrimdışı kurulumu, build/typecheck ve dağıtım smoke kontrolleri ayrı loglara yazılır.

## Geçmiş sayılmayan kapılar

Kurulu MV3; gerçek oturum açılmış sağlayıcı arayüzleri; Windows/macOS native kurulum/işleyiş; gerçek NER model çıkarımı ve bağımsız TR/EN başarı ölçümü; mağaza/kurumsal imza; gerçek çok kullanıcılı yük/soak/chaos; bağımsız güvenlik incelemesi; npm audit (registry DNS/ağ erişimi yoktu); AIDR backend/gateway/endpoint entegrasyonu ve müşteri kabulü tamamlanmadı. Zafiyet yokluğu, %100 yakalama veya mevzuat sertifikası iddiası yoktur.

## Dağıtım kontrolleri

Runtime TGZ temiz bir dizine çevrimdışı, `--ignore-scripts --omit=dev` ile kuruldu. Dört dışa aktarılan API (`.`, `./browser`, `./documents`, `./visual`), sentetik metin/CSV çıktıları, native/OCR kaynakları ve Chrome manifesti doğrulandı; runtime npm bağımlılığı 0. `package-smoke.json` gerçek çıktıdır. Chrome bundle envanteri iki derlemede byte düzeyinde aynı çıktı. Yalnız üç izin, dört host pattern, kapalı ağ CSP'si, uygulama ağ çağrısı bulunmaması ve production bundle içinde test hook'u bulunmaması statik olarak kontrol edildi. Bunlar kurulu eklenti doğrulamasının yerine geçmez.
