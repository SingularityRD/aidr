# AIDR Platform Privacy 0.5.0-rc.1 — çalıştırılan testler

Rapor: 2026-09-24T10:48:50.003149+00:00. Platform: v22.16.0, Linux x64; Python 3.13.5. Node `node:sqlite` deneysel uyarı verir; bu test sürümündeki SQLite 3.49.1 nedeniyle depoda varsayılan DELETE journal kullanıldı. Bu seçim diğer native bağımlılıkların güvenlik onayı değildir.

## Sonuç

| Grup | Geçen / toplam | Sınır |
|---|---:|---|
| Bütün Node testleri | 1302 / 1302 | Önceki 1181 dahil; yeni platform 121 test. Yeni sayı ayrıca toplama eklenmez |
| Python NER protokol/manifest | 38 / 38 | Gerçek öğrenilmiş NER çıkarımı yok |
| Python görsel worker | 72 / 72 | Alt bileşen testleri |
| Python yeni belge parser | 33 / 33 | Seccomp dahil gerçek alt süreçler |
| **Birim/entegrasyon toplamı** | **1445 geçti** | **0 başarısız; saha doğruluğu yüzdesi değildir** |
| Chrome davranış DOM senaryoları | 39 / 39 | Gerçek Chromium, Chrome API sınırı test taklidi; kurulu MV3 değil |
| Native client/host | 13 / 13 | Gerçek stdio, Chrome port'u shim; bir gerçek OCR görüntüsü dahil |
| Portal arayüzü | 4 / 4 | Gerçek Chromium DOM, mock fetch; canlı SSO değil |
| Belge uçtan uca | 5 / 5 | Dijital PDF, sade Word, EML, ZIP: 4 temiz TXT. CustomXML'li normal Word paketi: 1 beklenen blok |
| Yeni kalıcı audit + OCR | 1 / 1 | Gerçek Tesseract eng+tur; sentetik görselde altı satırın bilinen pikselleri |

Ayrı gerçek HTTPS portal API ve gerçek mTLS ingress testleri Node toplamının içindedir; tekrar sayılmaz. Aynı Türkçe görüntünün native ve platform yollarında kullanılması iki bağımsız veri kümesi veya on iki farklı kişisel veri örneği değildir.

## Gerçekten sınanan güven sınırları

Altı ayrı süreç, aynı SQLite dosyasında ortak kotaya yarıştı; limit aşılmadı. Tenant ayrımı, şifreli yeniden açma, sürümlü silme/CAS, tek kullanımlık onay, anahtar rotasyonu ve eski tam DB snapshot'ına dönüş/harici anchor testleri çalıştı. Seçici geçerli hücre rollback'ine karşı root/DB yöneticisi savunması veya dağıtık HA test edilmedi.

Kullanıcı/cihaz/sağlayıcı JWT'leri ayrı anahtarlarla kontrol edildi. RealmTLS denemesinde doğru peer certificate geçti; farklı ama CA tarafından yetkilendirilmiş sertifika ve sertifikasız tekrar başarısızdı. Test sertifikaları yerel ve geçiciydi. Canlı kurum hesabı/MDM/hardware attestation yoktu. HTTP istemcisi yerel self-signed server sertifikası için test istisnası kullandı; production taşıyıcıları bu istisnayı içermez.

Gönderim öncesi asenkron iptal, stale policy, byte snapshot, değiştirilmiş requestId, aynı onayın tekrar kullanımı, output withheld, no-original-fallback ve belirsiz dispatch kontrolleri çalıştı. Dış OpenAI/Gemini/upstream MCP çağrıları kontrollü taşıyıcı taklidiydi; gerçek müşteriye veya modele veri gönderilmedi. Yeni network modülünün gerçek dış HTTPS dispatch yolu bu ortamda çalıştırılmadı.

Parser alt sürecinde gerçek `socket()` ve `/etc/passwd` için yeni `open()` çağrıları EPERM aldı. Makro/embedded/şifreli içerik, DTD, path traversal, symlink, CRC, expansion/file-count/depth limitleri sınandı. Bunlar bağımsız parser güvenlik denetimi veya fuzzing kampanyası değildir. Default python-docx paketi customXML içerdiğinden bilinçli olarak reddedildi; ayrıca bu part'ları olmayan geçerli sade Word girdisi gerçekten temizlendi.

## Doğruluk: başarısız kabul kapısı rapordan çıkarılmadı

Kurallı TR/EN değerlendirmede 16 sentetik metin, 14 gold PII span vardır. İki etiketsiz kişi adı (`Ahmet`, `Jane`) kaçırıldı; her dilde PERSON recall **1/2** oldu. Diğer türlerde tekil olumlu örnekler başarılı olsa da örnek sayısı yeterli değildir. İki clean örnekte alarm çıkmaması false-positive başarımını kanıtlamaz.

`qualified:false`: bağımsız kurumsal veri, yeterli tür/dil örneği ve yeterli negatif örnek yok. `scripts/platform/evaluate-corpus.mjs` ile JSONL değerlendirmesi gerçekten çalıştırıldı ve beklenen nonqualification exit code **3** döndü. Dataset'in bağımsızlık alanı operatör beyanıdır; kurum etiketi kendiliğinden bağımsızlık kanıtı sayılmamalıdır.

Gerçekten eğitilen küçük model 80 özgün sentetik eğitim ve 18 ayrı sentetik örnek kullandı; 17 top-1 eşleşme. Bu oranı saha başarımı, kalibre risk skoru veya güvenilir prompt-injection/NER performansı diye yorumlamayın. Python ve TypeScript çıkarım olasılıkları karşılaştırıldı. Model, yalnız ek review sinyali verir; default defense NER kapısını açmaz.

## Kod kapsamı ve önemli boşluk

Tüm derlenmiş JavaScript: satır **%97.04**, dal **%87.00**, fonksiyon **%95.50**. Bu rakamlar bütün eski/yeni dosyaların birleşimidir. Özellikle yeni `network.js` satır kapsamı yaklaşık %54,63, `mcp-egress.js` dal kapsamı %40'tır. Dış network taşıyıcısının bütün akışları veya her MCP hata modu çalıştırılmadı. Yüksek toplam yüzdeyi bu boşlukların kapanması olarak sunmuyoruz. Dosya bazlı ayrıntı `all-node-coverage.txt` içindedir.

## Yerel performans

4054 byte sentetik metin; 20 ısınma, 200 sıralı çağrı. Farklı bileşen ölçümleri; birbirine toplanmış uçtan uca gecikme değildir.

| Bileşen | Medyan | p95 |
|---|---:|---:|
| Küçük character-linear sınıflandırıcı | 1.696 ms | 2.880 ms |
| PII + enterprise gate + gerçek SQLite FULLsync audit | 1.845 ms | 2.772 ms |

Yeni gerçek OCR pipeline tek çalıştırmada **2.368 saniye** sürdü. İşlem sonunda örneklenen Node RSS 58.98 MiB; peak bellek, Python/native süreç belleği veya yalnız modül ek maliyeti değildir. Gerçek NER, network provider, çok kullanıcılı trafik ve HA maliyetleri bu ölçümlerde yoktur.

## Çalıştırılamayanlar

Bu ortamda gerçek portal HTTPS navigasyonu `ERR_BLOCKED_BY_ADMINISTRATOR` ile durdu: 0 browser/HTTPS senaryosu çalıştı. Bu başarısız deneme `portal-e2e.json` içinde korunuyor. API'nin gerçek HTTPS testi ve DOM fixture testi ayrı olarak geçti; bunları tek gerçek browser->SSO->portal akışı diye birleştirmiyoruz. Kurulu Chrome MV3, gerçek canlı oturumlu ChatGPT/Gemini/Claude ve Windows/macOS kurumsal native dağıtım doğrulanmadı.

Bağımsız müşteri veri kümesi, gerçek NER/ASR modelleri, signed corporate CRX/MDM, canlı DSPM kaynakları, model vulnerability DB ve full multimodal dedektörler yok. Bunlar `docs/PLATFORM_FEATURE_STATUS.md` içinde ayrı işaretli.

## Kanıt dosyaları

`all-node-coverage.txt`, `node-tests.txt`, `ner-tests.txt`, `vision-tests.txt`, `parser-tests.txt`, `mtls-tests.txt`, `portal-http-tests.txt`, `portal-dom-e2e.json`, `portal-e2e.json`, `documents-e2e.json`, `visual-e2e.json`, `benchmark.json`, `pii-evaluation.json`, `corpus-cli-report.json` ve `COMPONENT-INVENTORY.json`; model kanıtı `models/training-report.json`. Browser/native raporları `reports/browser/dom-e2e.json` ve `native-e2e.json` içindedir.

Bu rapor, BMC veya başka bir kurumun kabulü, KVKK/GDPR/SOC 2 sertifikasyonu, üçüncü taraf pentest ya da kusursuz PII yakalama iddiası değildir.

## Paket ve birleştirme doğrulaması

`0.5.0-rc.1` npm arşivi temiz bir projeye çevrimdışı ve kurulum scriptleri kapalı olarak yüklendi. Public export'lar, metin maskeleme, gerçek küçük model çıkarımı, SQLite yazma/okuma, runtime dosyaları ve paket içindeki `demo:platform` çalıştı. Üçüncü taraf **runtime npm bağımlılığı yok**; Node, Python, OCR/parser ve native sistem bağımlılıkları bu ifade dışında tutulur.

Ayrı 0.4 kaynak kopyasına `git apply --check` ve yama uygulaması çalıştı; **250 dahil kaynak dosyasının tüm byte'ları** hedefle eşleşti. Bu kopyada vendored geliştirme bağımlılıkları çevrimdışı kuruldu; `build:all` ve `demo:platform` geçti. Kaynak yaması üretilmiş `dist`, Chrome bundle ve raporları içermez; bunlar tam ZIP içindedir. Ana AIDR uygulama deposunda merge yapılmadı.

Kanıtlar: `package-install.txt`, `merge-check.json`, `merge-build.txt`. Sürüm dosya hash manifesti bütünlük kontrolüdür, yayıncı dijital imzası değildir. Chrome arşivi imzalı CRX veya kurumsal kurulum onayı sayılmaz.
