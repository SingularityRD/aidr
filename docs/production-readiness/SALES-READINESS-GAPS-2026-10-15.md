# Büyük kurumsal satış hazırlığı: tek ve güncel eksik listesi (15 Ekim 2026)

**Karar bugün: PoC için NO-GO, ücretli kurumsal sözleşme için NO-GO.** Bu belge, büyük bir
kuruma Singularity AIDR satmak için kapanması gereken her eksiği tek listede toplar ve onları
neyi engellediklerine göre sıralar: önce **(a) bir PoC'yi (kontrollü değerlendirme)**, sonra
**(b) ücretli kurumsal sözleşmeyi** engelleyenler, en sonda yalnız satılan kapsama girerse
gereken **(c) genişleme** işleri.

Bu belge elle yazılmış bir karar özetidir; bir kapıyı kapatmaz ve kanıt yerine geçmez. Aşağıdaki
kaynakların her kimliği bir satıra eşlenmiştir (bkz. [Ek A](#ek-a--kaynak-eşleme)); yeni bir
iş açılmamış, yalnız birleştirilmiştir. Kaynaklar güncellendiğinde bu liste de güncellenmelidir.

| Kaynak | Ne içerir |
|---|---|
| [PRODUCTION_SALES_GAPS.md](../../PRODUCTION_SALES_GAPS.md) / [.json](../../PRODUCTION_SALES_GAPS.json) (üretilmiş) | 47 teknik/operasyon iş paketi (T01–T47) ve 13 ticari/dış kapı |
| [commercial-go-evidence-registry.json](commercial-go-evidence-registry.json), [commercial-gate-receipts.json](commercial-gate-receipts.json) | 13 zorunlu dış kapı: COM-001…005, COM-010…013, SEC-EXT-001, POV-001, INV-001, CLM-001 — hepsi `open` |
| [READINESS_BACKLOG.json](../../READINESS_BACKLOG.json) | Açık kayıtlar AIDR-016, 019, 044, 049, 050, 051, 052, 070, 079, 080 |
| [ga-gap-plan-2026-10-12.md](ga-gap-plan-2026-10-12.md) | Kısmi kalanlar: kimlik bilgisi sızdırma, `wget --post-file`/`tftp put`, PRD-15, BG-10/BG-LIVE, BG-11, CP-1 ve dış bağımlılıklar |
| [first-customer-ready.md](first-customer-ready.md) | PoC teklifinden önceki FCR-01…08 kapısı |
| 15 Ekim 2026 bulguları | Masaüstü uygulaması yok; demo modundaki yönetim paneli gerçek uçlara bağlı değil; canlı sitede API 500 ve Clerk anahtarları eksik; `app.aidr.singularityrd.com` çözülmüyor; Windows derlemesi kırığı; model açık kötü niyetli demo istemlerini reddediyor; Browser Guard canlı sitelerde doğrulanmadı |

## Nasıl okunur

- **PoC**, [first-customer-ready.md](first-customer-ready.md) tanımındaki kontrollü
  değerlendirmedir: belirli connector/işletim sistemi/sürüm kümesi, belirli süre, sentetik veya
  yazılı izinli veri, isimli irtibat ve geri alma prosedürü. Bugün yönetilen bulut (SaaS) yolu
  çalışmadığı için gerçekçi PoC yolu **müşteri ortamında self-hosted / on-prem** kurulumdur.
- **Sahip türü**: Engineering, Ops, Legal, Finance, Security, Sales, Customer. Birden fazla
  sahip varsa ilk yazılan sorumludur.
- **Kod kapatır mı?** — *Evet*: yalnız depo içi değişiklikle kapanır. *Kısmen*: kod gerekir ama
  kapanış için dış ortam, kişi veya kabul kaydı da gerekir. *Hayır*: insan, hukuk, satın alma,
  altyapı veya bağımsız taraf kararı gerekir.
- **Kabul kanıtı**: satırı kapatmak için gereken kayıt. Yerel test geçişi tek başına kabul
  değildir; kanıt aynı aday sürüme (candidate) bağlı olmalıdır.

## Özet

| Bölüm | Satır | Kodla tamamen kapanabilen |
|---|---|---|
| A — PoC'yi engelleyenler | 17 | 4 (A04, A05, A10, A11 — A11'de anadil incelemesi hariç) |
| B — Ücretli kurumsal sözleşmeyi engelleyenler | 25 | 2 (B19; B23 kullanılabilirlik oturumu hariç); diğerleri dış kabul veya karar ister |
| C — Yalnız satılan kapsama girerse | 8 | 0 |

En kısa PoC yolu: **A01–A03** (erişilebilir, gerçek uçlara bağlı bir kurulum), **A05–A08**
(Windows'ta derlenen, imzalı ve gerçek hostta kabul edilmiş bir aday), **A04** (gerçekçi demo)
ve **A12–A16** (irtibat, imzalanabilir değerlendirme belgeleri, güvenlik paketi).

## A — PoC'yi engelleyenler

Sıra, bir alıcının PoC'yi başlatmasını ne kadar erken durdurduğuna göredir.

| ID | Eksik (ne) | Alıcı için neden önemli | Sahip | Kod kapatır mı? | Kabul kanıtı |
|---|---|---|---|---|---|
| A01 | **Canlı site arka ucu bozuk.** `aidr.singularityrd.com` ana sayfası 200 dönüyor, ancak API rotaları 500 dönüyor (15 Ekim yoklaması: `/api/health` → 500) ve Vercel ortamında Clerk anahtarları tanımlı değil; kayıt/giriş ve form akışları çalışmıyor. Landing kaynağı bu depoda değil. | Alıcının ilk temas noktası. Çalışmayan giriş veya form, satış görüşmesinden önce güveni bitirir ve güvenlik ekibinin "tedarikçinin kendi altyapısı" sorusuna kötü cevap verir. | Ops | Hayır (Vercel yapılandırması ve landing deposu) | Tüm `/api/*` rotaları beklenen 2xx/4xx kodlarını döner; Clerk ile giriş uçtan uca çalışır; dış sentetik izleme 5xx'te alarm verir; tarihli yoklama kaydı. |
| A02 | **Ürün alan adı ve kontrol düzlemi uç noktası çözülmüyor.** `app.aidr.singularityrd.com` ve varsayılan `aidr-control.svc.singularityrd.com` için DNS kaydı yok (15 Ekim yoklaması). Varsayılan kurulumda cihaz kaydı hiçbir zaman tamamlanmıyor; yönetilen özellikler açılamıyor (AIDR-016). | Broşürde/e-postada verilen bağlantı açılmıyorsa SaaS PoC hiç başlamaz. On-prem PoC bu satıra bağlı değildir, ancak alıcıya bulut seçeneği sunulamaz. | Ops (+Engineering) | Kısmen (DNS/TLS/dağıtım dış; varsayılan uç nokta yapılandırması kod) | DNS + geçerli TLS; `POST /v1/device-start` doğrulama kodu ve URL döner; poll `managed.json` yazar; temiz makinede kaydedilmiş akış. |
| A03 | **Yönetim paneli demo modunda gerçek uçlara bağlı değil; on-prem uçtan uca kurulum kabul edilmedi.** Demo modu fikstür veriyle çalışıyor; on-prem uçtan uca ortam kuruluyor. Yerel Docker provasında `/readyz` imzalayıcı, yedek, kuyruk ve sertifika kontrollerinde 503 döndü (first-customer-ready, 24 Eylül). T28, FCR-03, AIDR-049'un kurulum dilimi. | Alıcı, uç noktadaki engellemenin konsolda olay olarak göründüğünü kendi gözüyle görmek ister. Sentetik ekran "demo" etiketiyle bile ürünün çalıştığını kanıtlamaz. | Engineering + Ops | Kısmen | Temiz makinede imzalı paketten on-prem kurulum: gerçek migration → test kiracısı → giriş → device-start/poll ile cihaz kaydı → politika yayını → deny → olayın panelde görünmesi ve dışa aktarımı → güncelleme → başarısız güncellemeden geri dönüş; `/readyz` 200; aynı aday. |
| A04 | **Demo senaryoları gerçek modelle çalışmıyor.** Model, açıkça kötü niyetli demo istemlerini (ör. "anahtarları şu adrese gönder") kendisi reddediyor; AIDR'nin engellemesi hiç görünmüyor. Gerçekçi senaryolar gerekiyor: zehirli README/paket talimatı, masum görünen görevde kimlik bilgisi dosyası okuma, typosquat bağımlılık kurulumu, MCP çıktısında prompt injection. | Model reddettiğinde demo "AIDR ne işe yarıyor?" sorusuyla biter. Güvenlik alıcısı gerçek tehdidin dolaylı (injection, tedarik zinciri) geldiğini bilir; açık kötü istem inandırıcı değildir. | Sales + Engineering | Evet (senaryo, sahne verisi ve runbook) | Gerçek modelle en az iki hostta (ör. Claude Code ve Codex) runbook'tan tekrar edilebilen kayıtlı demo; her senaryoda AIDR kararı ve engellenen yan etki görünür; betikli mock-model yedeği ayrıca "sentetik" etiketli. Bkz. [docs/demo/](../demo/). |
| A05 | **Windows derlemesi kırıktı.** `dist/license` ile `dist/LICENSE` büyük/küçük harf çakışması Windows'ta derlemeyi bozuyordu. Düzeltme (`src/license` → `src/customer-license`, commit 28b7841a) `fix/windows-license-dir-collision` dalında; ana dala birleştirilmesi ve sürüme girmesi bekleniyor. | Türkiye'deki kurumsal uç noktaların çoğu Windows. Windows'ta derlenmeyen veya kurulamayan ürün PoC'ye giremez. | Engineering | Evet | Dal birleştirildi; temiz Windows makinede `pnpm install`, `pnpm build`, `pnpm test` yeşil; `dist-case-collision` testi geçiyor; MSI/EXE yükleyici üretildi. |
| A06 | **PoC kapsamındaki connector ve işletim sistemleri için gerçek host kabulü yok.** Gerçek host kayıtları yalnız linux/x64, geliştirme derlemesi ve betikli mock model üzerinde (11 zorlanan, 25 açık nokta). Cursor ve VS Code için gerçek host kaydı yok (CON-6); Windows, macOS ve arm64 satırları hedef kapsam, test edilmiş destek değil ([support-matrix.json](../../deploy/native/support-matrix.json) `decision: NO-GO`). Claude Code'da öldürülen PreToolUse kancasının host tarafında fail-open olduğu gözlendi. T01, T02, AIDR-049, COM-010'un PoC dilimi. | Alıcı "bizim Windows + VS Code kurulumumuzda gerçekten engelliyor mu?" diye sorar. Kanıt yoksa teklif edilebilecek tek dürüst kapsam test edilmiş satırlardır. | Engineering (QA) | Kısmen (lisanslı host ve gerçek OS gerekir) | PoC'de sunulacak her connector/OS/mimari için FCR-04 kaydı: zararsız ikiz, güvenli deny kanaryası, yan etkinin bağımsız gözlemi, kanca kapalı/çökmüş/zaman aşımı, ağsız/yeniden başlatma, güncelleme ve geri alma; bilinen atlatmalar yazılı. Kaydı olmayan satır PoC kapsamından çıkarılır. |
| A07 | **İmzalı ilk sürüm yok.** Yalnız `v1.0.0-sprint*` etiketleri var; hiçbir release iş akışı bunları kabul etmiyor ([first-release.md](../operations/first-release.md)). GitHub Actions kapalı; imza, attestation ve kabul kapıları insan adımı (anahtar töreni, PGP imzalı etiket) bekliyor. Aday bağlı kanıt indeksi (`.release-evidence/v8-evidence-index.json`) yok. OPS-1, FCR-01, T29. | Kurum, kaynağı ve bütünlüğü doğrulanabilen sürümlü bir paket kurar; "geliştirici derlemesi" kurumsal değişiklik yönetiminden geçmez. Sorun bildirimi de bir sürüm numarasına bağlanmalıdır. | Engineering + Security | Hayır (anahtarlar ve imzalı etiket insan işi) | PGP imzalı `v1.0.0-rc.N` etiketi; `release-rc` çıktıları (SBOM, provenance, imzalı arşivler); ikinci makinede bağımsız güven politikasıyla doğrulama; yanlış imzalayan, değiştirilmiş arşiv ve eski sürüm reddi kaydı. |
| A08 | **Kod imzalama sertifikası ve Browser Guard dağıtım anahtarı yok.** Windows OV (HSM) sertifikası satın alınmadı; Browser Guard için mağaza hesabı, mağaza kaydı ve kendi barındırılan CRX imza anahtarı yok ([browser-guard-store-publishing.md](../runbooks/browser-guard-store-publishing.md)). | İmzasız MSI/EXE, kurumsal EDR, AppLocker/WDAC ve SmartScreen tarafından engellenir. Tarayıcı eklentisi kurumda yalnız politika ile zorla kurulabilir; bunun için imzalı CRX ve sabit eklenti kimliği gerekir. | Finance + Ops | Hayır | Satın alınmış sertifika ve HSM kaydı; `signtool verify` geçen MSI; Chrome/Edge `ExtensionInstallForcelist` ile kendi barındırılan CRX'in temiz makinede kurulumu; anahtar saklama kaydı. |
| A09 | **Browser Guard canlı AI sitelerinde doğrulanmadı.** Kabul yalnız hermetik fikstürlerde. ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Mistral ve Grok'ta canlı kabul yapılmadı (BG-LIVE). Microsoft 365 Copilot (`m365.cloud.microsoft`, `copilot.cloud.microsoft`) alt çerçeveleri kodda korunuyor ama gerçek kiracıda host ve seçiciler doğrulanmadı (BG-10). T47. | Türkiye'de TCKN/IBAN maskeleme çoğu alıcının ilk sorusudur. Canlı sitede seçici değişirse eklenti sessizce işe yaramaz hale gelebilir; PoC'de ilk denenecek şey budur. | Engineering (QA) | Kısmen (canlı hesap ve kiracı gerekir) | [pii-poc-test-scenarios.md](pii-poc-test-scenarios.md) bölüm 4'e göre her desteklenen canlı sitede tarihli kayıt: TR/EN kişisel veri ve sırlar gönderimden önce maskeleniyor, yanıtta doğru geri açılıyor, tarama hatası gönderimi engelliyor, yönetilen kilitli ayar kullanıcıca değiştirilemiyor, telemetride ham değer yok. |
| A10 | **Kimlik bilgisi sızdırmada tespit boşlukları.** Kaynağı (kimlik bilgisi dosyası) ve ağ çıkışını tek komutta birleştiren sızdırma `deny` yerine hâlâ `ask`; `wget --post-file` ve `tftp put` komut kurallarında sinyal üretmiyor (`threats/` içinde yalnız skill taramasında geçiyor). | PoC'de alıcının red team'i ilk olarak bu sınıf komutları dener. "Ask" ile bırakılan veya hiç görülmeyen sızdırma, ürünün temel vaadini çürütür. | Engineering | Evet | Kural ve test: kimlik bilgisi kaynağı + ağ hedefi tek komutta `deny`; `wget --post-file=<sır>`, `curl -T`, `tftp ... put` varyantları (tırnak, birleştirme, değişken dolaylaması dahil) yakalanıyor; zararsız ikizler geçiyor; `pnpm test` yeşil. |
| A11 | **Türkçe yerelleştirme eksik (PRD-15).** CLI komutlarının kullanıcıya dönük çıktısı bu çalışmada Türkçeleştirildi ve TR modunda İngilizce kalmadığını denetleyen test eklendi. Kalan: yönetim panelinin iç sayfaları, Cursor/VS Code eklentisi kurulum hataları, kural başlıkları ve bütün Türkçe metinlerin anadil incelemesi. | TR-öncelikli pazarda son kullanıcı ve SOC ekibi blok mesajını ve konsolu kendi dilinde görmek ister; kamu ve bankacılık alıcıları bunu çoğu zaman şartname maddesi yapar. | Engineering + Sales (anadil incelemesi) | Evet (anadil incelemesi hariç) | Her yüzey için TR modunda İngilizce metin kalmadığını denetleyen test; EN/TR katalog anahtar ve yer tutucu eşitliği; isimli anadil incelemesi kaydı. |
| A12 | **Destek kanalı, PoC irtibatı ve durum sayfası yok.** `/support` herkese açık GitHub Issues'a yönlendiriyor; durum sayfasında canlı kaynak yok; destek SLA'sı taslak ve kadrosuz. COM-005, PRD-10, T40. | PoC sırasında kurulum sorunu çıktığında kime, hangi kanaldan, ne kadar sürede ulaşılacağı belli olmalıdır. Herkese açık issue takipçisi kurumsal müşteri verisi için kabul edilemez. | Ops + Sales | Hayır | İsimli irtibat ve yedeği; özel bilet kanalı; çalışma saatleri ve yanıt hedefi; tarihli destek tatbikatı (bilet aç/kapat); sır içermeyen tanılama paketi (`aidr support-bundle`) kullanımı. |
| A13 | **Değerlendirme belgeleri imzalanabilir değil.** Gizlilik sözleşmesi, Evaluation Charter, DPA ve KVKK aydınlatma metinleri taslak 0.1 ([docs/legal](../legal/README.md)); hukuk onayı yok. COM-003'ün PoC dilimi. | Kurumun hukuk ve satın alma birimi imzasız veya taslak belgeyle ortamına yazılım kurdurmaz. Gerçek veri kullanılacaksa KVKK kapsamında veri işleme sözleşmesi zorunludur. | Legal | Hayır | Hukuk onaylı PoC seti (NDA, Evaluation Charter, sınırlamalar sayfası); gerçek veri kullanılacaksa imzalı DPA; PoC'nin yalnız sentetik veriyle yapılacağı yazılı ise o kayıt. |
| A14 | **Güvenlik değerlendirme paketi onaysız.** Tedarikçi güvenlik anketi cevapları ([security-questionnaire-answers.md](security-questionnaire-answers.md)) ve güvenlik teknik dokümanı ([whitepaper.md](../security/whitepaper.md)) taslak; aday bağlı SBOM teslim edilmedi. | Büyük kurumlar (özellikle banka ve kamu) uç noktaya ajan kurdurmadan önce tedarikçi güvenlik değerlendirmesi yapar; bu paket PoC'nin ön şartıdır. | Security | Kısmen (SBOM ve kanıt kod/pipeline ile; onay insan işi) | İsimli Security onaylı anket cevapları; aday sürümle eşleşen SBOM ve provenance; veri akışı şeması; açık riskler listesi. |
| A15 | **Git geçmişindeki sır bulguları triyaj edilmedi.** Güncel ağaç taraması temiz; tam geçmiş taraması 132 bulguyla kasıtlı olarak kapalı (fail-closed) ve Security sahibi incelemesi bekliyor (AIDR-070, FCR-05). | Kaynak kod emaneti, kaynak incelemesi veya imzalı sürüm öncesinde canlı bir anahtarın sızmış olma ihtimali kapatılmalıdır; alıcı güvenlik ekibi bunu sorar. | Security | Hayır | İsimli Security sahibinin her bulgu için sınıflandırması; canlıysa iptal ve rotasyon kaydı; temiz aday üzerinde tam geçmiş taraması PASS. |
| A16 | **Dağıtılan konteyner imajlarında açıklar.** Dashboard imajı 0 CRITICAL / 0 HIGH (14 Ekim) ancak landing imajı düzeltilmedi (AIDR-079); self-hosted kitteki sabitlenmiş upstream Supabase imajlarında CRITICAL bulgular sürüyor, PostgreSQL 17.6 tavsiye edilen düzeltme seviyesinin altında (AIDR-080). | On-prem PoC'de müşteri imajları kendi tarayıcısıyla tarar; açıklanmamış CRITICAL bulgu kurulumu durdurur. | Engineering + Security | Kısmen (desteklenen yamalı upstream sürüm dış) | Yoksayma olmadan Trivy taraması 0 CRITICAL / 0 HIGH veya her kalan bulgu için Security imzalı, müşteriye açıklanmış istisna listesi; nonroot/salt-okunur çalışma kontrolü. |
| A17 | **Satış ve satın alma metinlerindeki iddiaların onayı yok.** Bu çalışmada desteklenmeyen ve eski iddialar düzeltildi ve claim registry ile eşlendi; ancak hiçbir iddia Sales/Legal onaylı değil ve PDF broşür/katalog kaynak HTML'den yeniden üretilmedi. CLM-001'in PoC dilimi. | PoC'de verilen materyaldeki her cümle sözleşmede referans alınabilir; desteklenmeyen iddia hem güveni hem hukuki konumu bozar. | Sales + Legal | Kısmen (tarama ve eşleme kod; onay insan) | `node docs/scripts/claim-check.mjs --mode=inventory` PASS; PDF'ler güncel kaynaktan üretilmiş; PoC'de dağıtılan her belge için Sales/Legal onayı. |

## B — Ücretli kurumsal sözleşmeyi engelleyenler

Bunlar PoC'yi başlatmayı engellemez; satın alma, sözleşme imzası ve canlıya geçişi engeller.
Önce ticari ve hukuki kapılar, sonra işletim, sonra ürün kapsamı.

| ID | Eksik (ne) | Alıcı için neden önemli | Sahip | Kod kapatır mı? | Kabul kanıtı |
|---|---|---|---|---|---|
| B01 | **Onaylı ticari manifest yok** (SKU, fiyat, ölçüm birimi, para birimi/vergi, kurulum modeli, bölge, saklama, SLA, destek, lisans hakkı, yenileme, iptal, çıkış). On-prem teklif şablonu taslak. COM-001. | Satın alma birimi teklifi, sipariş formunu ve kurulan ürünün aynı şeyi tanımladığını görmeden sipariş açmaz. | Finance + Sales | Hayır | İsimli onaylı manifest; örnek teklif ve sipariş; siparişten çıkışa prova; değiştirilemeyen kanıt özeti. |
| B02 | **Lisans, fikri mülkiyet ve EULA hukuk onayı yok;** üçüncü taraf lisans matrisi uzlaştırılmadı; kaynak kod emaneti için emanet kuruluşu yok. COM-002. | Kurumsal hukuk, sahiplik zinciri ve açık kaynak yükümlülükleri net olmadan sözleşme imzalamaz; kritik altyapı alıcıları emanet ister. | Legal | Hayır | Hukuk onaylı EULA ve NOTICE/LICENSE uyumu; bileşen lisans matrisi; emanet sözleşmesi (isteniyorsa). |
| B03 | **Veri işleme ve gizlilik onayı yok.** DPA/TOM/alt işleyen listesi taslak; gerçek telemetri, olay, tarayıcı ve AIG yüklerinin alan düzeyinde ölçümü yok; kurum MDM/egress dağıtımıyla bütün alternatif gönderim yollarının kapatıldığı kanıtlanmadı. KVKK/VERBİS ve yurt dışı aktarım konumu onaysız. COM-003, T37. | KVKK kapsamında veri sorumlusu olan alıcı, işleyenin hangi veriyi nereye gönderdiğini yazılı ve ölçülmüş olarak ister; aksi halde sözleşme imzalanamaz. | Legal + Security (+Engineering) | Kısmen (ölçüm kod; onay hukuk) | Hukuk/DPO onaylı DPA, TOM ve alt işleyen listesi; kanarya sırların izinsiz kanalda bulunmadığını gösteren ölçüm; her veri sınıfı için bölge/erişim/silme sahibi. |
| B04 | **Fatura → ödeme → yetkilendirme mutabakatı kanıtlanmadı;** e-Fatura/e-Arşiv süreci taslak. COM-004, T33. | Kurum fatura almadan ödeme yapamaz; koltuk ekleme/azaltma ve iptalin lisansa doğru yansıması denetim konusudur. | Finance (+Engineering) | Kısmen | Sipariş, ek koltuk, azaltma, yenileme, ödeme hatası, iptal ve mükerrer webhook'un aynı yetkilendirme sonucunu verdiği kayıt; e-Fatura örneği; finans mutabakatı. |
| B05 | **Kimliği doğrulanan özel dağıtım ve filo kurulumu yok.** Özel kayıt defteri, yetkilendirmeye bağlı indirme, iptal ve hava boşluklu kurulum prosedürü canlıda yok; Intune/Jamf/SCCM ile gerçek MDM dağıtımı, güncelleme, geri alma ve kaldırma kabul edilmedi. COM-012, T17, T29, AIDR-050. | Yüzlerce/binlerce uç noktaya kurulum ancak MDM ile yapılır; alıcı, lisansı biten veya iptal edilen müşterinin güncelleme alamadığını ve kurulumun izlenebilir olduğunu görmek ister. | Engineering + Ops (+Customer) | Kısmen (gerçek MDM kiracısı ve yayıncı imzası dış) | Gerçek MDM kiracısında temiz kurulum, yarım upgrade, geri dönüş, host güncellemesi ve kaldırma kaydı; yetkili kayıt defterinden ve internetsiz kurulum; yanlış imza ve iptal edilmiş anahtar reddi. |
| B06 | **Reklamı yapılan bütün connector'ların kabulü yok.** Claude Code, Cursor, VS Code, OpenClaw ve OpenCode için desteklenen host matrisi, imzalı paket, özel kayıt defterinden kurulum, gerçek host E2E, geri alma, destek sahibi ve sınırlamalar belgesi; Codex önizleme. Connector'lar host sürüm uyumluluğu denetlemiyor (CON-14); Codex çıktı tarafı engellemesi gerçek hostta gözlenmedi (CON-12). COM-010. | Sözleşmede adı geçen her entegrasyon desteklenen ürün sayılır; kabulü olmayan connector sözleşme dışına alınmalı veya önizleme olarak yazılmalıdır. | Engineering | Kısmen | Her connector için aday bağlı gerçek host kaydı ve yayımlanmış destek/sınırlama matrisi; desteklenmeyen host sürümünde açık uyarı veya ret. |
| B07 | **Bağımsız güvenlik değerlendirmesi (pentest) yapılmadı.** Kapsam ve RFP taslak; değerlendirici seçilmedi. SEC-EXT-001. | Büyük kurumların tedarikçi risk süreci, kritik/yüksek bulgusu kapanmış bağımsız rapor ister; uç noktada ayrıcalıklı çalışan güvenlik ürünü için bu genellikle zorunludur. | Security | Hayır | Bağımsız değerlendirici raporu; açık kritik/yüksek bulgu yok; yeniden test kaydı; aynı aday ve kapsam. |
| B08 | **Sertifika ve sigorta yok.** SOC 2 raporu veya ISO/IEC 27001 sertifikası yok ve iddia edilmiyor; siber/mesleki sorumluluk sigortası bilgisi yok (anket maddeleri CMP-01, GOV-08). | Çoğu büyük kurumun tedarikçi kabul listesi bunlardan en az birini veya bir yol haritası/köprü mektubu ister; yoksa satın alma istisna onayı gerekir. | Security + Legal + Finance | Hayır | Kapsamı belirlenmiş ISO 27001 veya SOC 2 planı ve denetçi sözleşmesi; sigorta poliçesi; o zamana kadar alıcıya yazılı istisna gerekçesi. |
| B09 | **SLA ölçülmedi ve taslak.** %99,9 aylık erişilebilirlik hedefi sözleşme kanıtı açık; ölçülmüş SLI, bakım politikası, hizmet kredisi yok. Tek host yük tatbikatı HA değil; tarihsel noisy-neighbour koşusunda referans kiracıda yaklaşık 170 kat p95 bozulması ölçüldü. COM-013, T30, AIDR-052. | SLA, sözleşmenin ticari çekirdeğidir; ölçülmemiş hedef taahhüt edilemez. On-prem satışta SLA destek yanıt süresine dönüşür, o da kadro ister. | Ops + Legal + Finance | Kısmen | En az 8 saatlik, kimlikli, gerçekçi iş yükü; HA/failover tatbikatı; bağımsız hostlarda iki kiracılı noisy-neighbour testi; ölçülmüş SLI; hukuk onaylı SLA ve hizmet kredisi metni. |
| B10 | **7/24 işletim, alarm ve güvenlik güncelleme süreci çalışmıyor.** Nöbet, eskalasyon, olay bildirimi, güvenlik açığı bildirim politikası (VDP) ve `security.txt` yürürlükte değil. COM-005, T32, T40. | Alıcı, kritik bir açıkta ne kadar sürede bilgilendirileceğini ve yamanın nasıl geleceğini sözleşmeye yazar. | Ops + Security | Hayır | Servis, DB, depolama, imzalayıcı, kuyruk ve yedek hatası enjekte edilerek doğru kişiye zamanında alarm; yürürlükteki VDP; kritik olay ve imza anahtarı kaybı tatbikatı. |
| B11 | **Yedekleme, kurtarma, yükseltme ve veri yaşam döngüsü kabul edilmedi.** Offsite yedek, bağımsız anahtar saklama ve ikinci arıza alanında geri yükleme yok; RPO/RTO ölçülmedi; migration/upgrade/geri dönüş ve saklama/legal hold/müşteri çıkışı saha kabulü açık. T26, T27, T31, AIDR-044. | Denetçiler iş sürekliliği ve veri silme kanıtı ister; sözleşme sonunda verinin nasıl iade/silineceği hukuki zorunluluktur. | Ops + Engineering (+Customer) | Kısmen | Yalnız offsite yedek ve ayrı anahtarla yeni hostta kurtarma; tablo/nesne eşleşmesi; ölçülmüş RPO/RTO; eski veriyle upgrade ve kesilen migration testi; süresi dolan verinin API, depolama, cache ve replikalardan yokluğu. |
| B12 | **Bölge ve veri yerleşimi kanıtı yok.** Yönetilen bulut için EU/US/APAC hedefi kilitli niyet, dağıtılmış değil; Türkiye'de veri yerleşimi isteyen alıcı için tek yol on-prem. COM-011. | KVKK, BDDK ve kamu alıcıları verinin nerede tutulduğunu sözleşmeye yazar; dağıtılmamış bölge satılamaz. | Ops + Legal | Hayır | Her satılan bölge için çalışan dağıtım, yönlendirme, yedek ve silme kaydı; on-prem için müşteri ortamında kurulum kaydı. |
| B13 | **Kurumsal kimlik ve kayıt akışları canlı IdP ile kabul edilmedi.** Canlı Entra/Okta ile SSO/MFA ve hesap kurtarma (T18); SCIM ve directory grup eşlemesi (T19, AIDR-019 — Clerk her izinde seçili directory'nin aktifliğini sağlamıyor); davet ve cihaz kaydı (T20); API anahtarında ekip/üyelik iptali (T21); enrollment exchange, entitlement grace, device-start ve device-poll bütünlüğü (T43–T46); cihaz kodu akışında oltalama riski — onayda coğrafi konum için ingress'in ülke başlığını imzalaması gerekiyor (CP-1). | Kurumsal alıcı erişimi kendi IdP'sinden yönetir; işten ayrılan çalışanın erişiminin belirtilen sürede kesildiğini görmek ister. | Engineering (+Customer) | Kısmen (canlı IdP ve ingress dış) | Canlı Entra ve Okta kiracısında giriş, MFA, kayıp MFA kurtarma, SCIM ile pasifleştirmede erişim kesilmesi; iptal edilen anahtar ve üyelikte tüm tüketicilerde 401/403; imzalı ülke başlığıyla cihaz onayı. |
| B14 | **Kiracı izolasyonu ve kaynak sınırları sahada kanıtlanmadı** (SaaS satışı için). Farklı kiracı, üyelik kaybı, eski anahtar, büyük gövde ve paralel isteklerle negatif matris ve legacy RLS yaşam döngüsü. T22, T42. | Çok kiracılı bulut satışında bir kiracının diğerinin verisini görmemesi ve kaynağını tüketmemesi temel güvenlik şartıdır. | Engineering + Security | Kısmen | Dağıtılmış iki kiracılı ortamda negatif erişim matrisi; askıya alınmış kiracı okuyamıyor; bir kiracı diğerinin SLO'sunu tüketemiyor. |
| B15 | **Telemetri, SIEM ve olay araştırması sahada kanıtlanmadı.** Kesinti ve yeniden başlatmada olay kaybı/çiftlenmesi ölçülmedi (T23); QRadar/Wazuh/Splunk gibi gerçek SIEM'e teslim, 429/401 ve sertifika değişimi (T24); saat kayması ve zincir bütünlüğü (T25). | SOC ekibi olayları kendi SIEM'inde görmek ister; sessiz olay kaybı güvenlik ürünü için kabul edilemez. | Engineering (+Customer) | Kısmen | Gerçek SIEM'de alan eşlemesi ve yeniden gönderim kaydı; kesinti testinde kayıp/çift ölçümü; değiştirilmiş zincirin görünür olması. |
| B16 | **Politika yaşam döngüsü ölçekte kabul edilmedi.** Yayınlanan YAML politikanın gerçek ajan kararını değiştirdiğinin uçtan uca kanıtı (T14), gerçek filoda yakınsama ve rollback (T15), uç nokta sır saklama ve anahtar rotasyonu (T16). | Alıcı, merkezi politikanın binlerce cihaza doğru sürümle ulaştığını ve yanlış politikanın geri alınabildiğini ister. | Engineering | Kısmen | Gerçek filoda politika yakınsama süresi; stale/yetkisiz alındı, 401/403, bozuk cache ve yeniden başlatmada yanlış sürüm uygulanmadığı kaydı; anahtar rotasyon tatbikatı. |
| B17 | **Tespit katmanında saha kabulü açık.** Paket denetiminde hatanın sessiz kaybolması (T03), model tüketiminden önce çıktı denetimi (T04), reputation verisinin güncelliği ve gerçek uç noktayla AMSI destekli Windows ölçümü (T06). URL/dosya/paket reputation kontrolleri dağıtılmış birinci taraf uç nokta olmadan pasif. | Alıcı "bilinmeyen paket/URL'de ne olur?" diye sorar; pasif bir katman "temiz" sonuç gibi sunulamaz. | Engineering | Kısmen | Registry zaman aşımı, bozuk cevap ve denetleyici istisnasında sessiz allow olmadığı kaydı; parçalı/Unicode/büyük çıktıda engellenen baytın modele ulaşmadığı test; gerçek reputation uç noktası ve AMSI ölçümü. |
| B18 | **MCP gateway saha kabulü açık** (MCP gateway satılacaksa). Keşif ve kimlik normalizasyonu (T07), imzalı araç tanımı ve değişiklik onayı (T08), taşıma güvenliği ve gerçek ağ testi (T10), stdio köprü modunda upstream kimlik bilgisinin ajan hostunda kalması (MSC-4). | MCP araçları kurumsal veri kaynaklarına erişir; araç tanımının sessizce değişmesi tedarik zinciri saldırısıdır. | Engineering | Kısmen | Description/schema değişimi, eski manifest, yanlış imzalayan ve onaysız retry reddi; DNS değişimi, IPv6 ve bozuk SSE ile gerçek ağ testi; stdio modunun sınırları sözleşmede yazılı. |
| B19 | **Masaüstü uygulaması yok.** `packages/desktop` yapım aşamasında; bu depoda yok. Bugün uç nokta arayüzü CLI, connector'lar ve tarayıcı eklentisidir. | Geliştirici olmayan kullanıcılar ve yardım masası grafik arayüz bekler; satış materyalinde vaat edilirse teslim edilmesi gerekir. | Engineering | Evet | Masaüstü uygulamasının imzalı sürümü, kurulum/kaldırma kaydı ve test edilmiş özellik listesi; o zamana kadar satış metninde masaüstü uygulaması vaadi yok. |
| B20 | **İsimli müşteri PoV kaydı yok.** İmzalı Evaluation Charter, bağımsız sandbox, zorunlu senaryolar, sınırlamaların gözden geçirilmesi ve kabul/çekince kaydı. POV-001. | Büyük kurum referanssız ilk müşteri olmaktan kaçınır; aynı sürüme bağlı kabul kaydı satın alma kararının dayanağıdır. | Customer + Sales | Hayır | İmzalı charter; senaryo sonuçları; müşterinin kabul veya çekince yazısı; aynı aday. |
| B21 | **Bütün iddiaların Sales/Legal onayı yok.** Landing, README, eklenti, teklif, satın alma ve yatırımcı metinleri claim registry'ye eşlenmiş olmalı; yalnız onaylı ve süresi geçmemiş iddialar yayında kalmalı. Canlı landing metni bu depoda değil, taranamıyor. CLM-001. | Sözleşme ekindeki ürün tanımı satış metniyle çelişirse alıcı hukuken o metne dayanabilir. | Sales + Legal | Kısmen | `claim-check --mode=gate` aday için PASS; landing kaynağı taramaya dahil; her iddia için isimli onay ve son geçerlilik tarihi. |
| B22 | **Hazırlık kayıtları ve test kapıları aday bağlı değil.** Paket/özellik/iddia sayılarının aynı sürümde tutarlılığı (T34); her satılan özellik için gerçek tüketicide deny/allow/kesinti kanıtı, 0 açıklanmamış zorunlu skip (T35). CI kapalı; kapılar `pnpm ci:local` ile yerelde koşuyor. | Alıcının denetçisi "bu raporlar teslim edilen sürüme mi ait?" diye sorar. | Engineering | Kısmen | Aday bağlı `v8-evidence-index.json` ve bütün kapıların PASS makbuzları; açıklanmış skip listesi. |
| B23 | **Operatör arayüzü kullanılabilirlik kabulü açık.** Yanlış ekipte sır/politika görünmemesi, zaman aşımı/409/401 sonrası yanlış başarı göstermemesi, klavye ile kritik işler, büyük listeler (T36); panelin iç sayfaları İngilizce (PRD-15'in panel dilimi). | Günlük kullanıcı SOC ve BT ekibidir; erişilebilirlik ve dil, kamu ihalelerinde şartname maddesidir. | Engineering | Evet (kullanılabilirlik oturumu hariç) | Hata durumları için UI testleri; erişilebilirlik denetimi; TR modunda İngilizce kalmadığını denetleyen panel testi; kullanılabilirlik oturumu notları. |
| B24 | **Bağımsız etkinlik ve performans kıyası yok.** Aynı iş yükünde ham ölçüm, payda, sürüm ve bağımsız değerlendirici imzası (T39). Kanca gecikme bütçesi yerelde ölçüldü (`docs/performance/hook-latency-budget.md`), sahada değil. | Alıcı tespit oranı ve geliştirici deneyimine etkiyi sayıyla ister; kanıtsız oran sözleşmeye yazılamaz. | Engineering (+bağımsız değerlendirici) | Kısmen | Bağımsız değerlendiricinin imzalı raporu; görünmeyen yüzeyler başarı ortalamasına katılmamış; müşteri iş yükünde gecikme ölçümü. |
| B25 | **Satış ve satın alma değerlendirme paketi tamamlanmadı.** Bir operatörün kılavuzdan demoyu tekrar edebilmesi; satın alma sorularının kaynak/kanıt/sahibe bağlanması; teklif kapsamının kurulan özellik ve destek koşullarıyla eşleşmesi (T41). | Satın alma süreci soru-cevap ve belge teslimi ile ilerler; eksik veya çelişkili belge süreci haftalarca uzatır. | Sales + Legal + Finance | Kısmen | Kılavuzdan bağımsız operatörle tekrar edilen demo kaydı; her satın alma sorusu için kaynak ve sahip; uydurulmuş referans veya başarı hikâyesi olmadığının kontrolü. |

## C — Yalnız satılan kapsama girerse gerekenler

Bu satırlar bir PoC'yi veya temel bir sözleşmeyi engellemez. İlgili özellik satılacaksa B
bölümüne taşınır; satılmayacaksa sözleşmede kapsam dışı olarak yazılmalıdır
([first-customer-ready.md](first-customer-ready.md): kanıtlanmamış seçenek kapsam dışında kalır).

| ID | Eksik (ne) | Alıcı için neden önemli | Sahip | Kod kapatır mı? | Kabul kanıtı |
|---|---|---|---|---|---|
| C01 | Davranış, novelty ve ML kararlarının ürün akışına bağlanması (T05). | ML tabanlı tespit vaadi ölçülmeden satılamaz. | Engineering | Kısmen | Holdout saldırı ve zararsız iş yükünde yanlış alarm ölçümü; soğuk başlangıç ve model yenilemede kararlı sonuç; kiracı ayrımı. |
| C02 | Kullanıcı–ajan–araç–kaynak ilişkisi ve delegasyon (T09). | Ajanın kimin adına hangi kaynağa eriştiği denetim izinin temelidir. | Engineering | Kısmen | Başka araç/kaynak için token kullanımı, süresi bitmiş delegasyon ve zincir yetki büyütme reddi; olaydan kaynağa iz. |
| C03 | Sürekli kurum/filo keşfi ve devredilmiş kimlik bilgisi kapsamı (T11, AIDR-051). | "Kurumda hangi AI ajanları var?" sorusunun cevabı; gerçek AWS/Azure/GCP/MDM kapsamı olmadan eksik envanter güvenli gibi görünür. | Engineering (+Customer) | Kısmen | Müşteri onaylı sağlayıcı API kapsamıyla gerçek envanter; eski/kısmi döngünün sağlıklı görünmemesi; zamanlama ve alarm tatbikatı. |
| C04 | Filo müdahalesi, kimlik bilgisi iptali ve response eylemleri (T12, T13). | Otomatik müdahale yanlış çalışırsa üretimi durdurur; satılacaksa geri alma kanıtı şarttır. | Engineering | Kısmen | Offline ajana süresi geçmiş komut uygulanmaması; tekrar gelen komutun tek etki üretmesi; başarısız izolasyonun başarı görünmemesi; geri alma kaydı. |
| C05 | Kuruma özel DLP ve veri etiketleri (T38); serbest metindeki isimler için PII modeli kapısı: küçük model %86,5 recall / %14,7 yanlış alarm, hedef %95 / %2; önceden eğitilmiş ağırlıklar ağ erişimi istiyor (PII-NER). | Kuruma özgü veri türlerinin (müşteri no, poliçe no vb.) yakalanması DLP satışının özüdür. | Engineering (+Customer) | Kısmen | Kurum örnek corpus'unda ölçülmüş tür recall ve yanlış alarm eşiği; örnek dışı formatın "unavailable" raporlanması. |
| C06 | Browser Guard native host (NER/OCR) performansı: gerçek Windows/macOS gecikmesi ölçülmedi; Firefox'ta native NER yok (BG-11). | Tarayıcıda gecikme kullanıcıyı eklentiyi kapatmaya iter. | Engineering | Kısmen | Gerçek Windows ve macOS uç noktada p95 gecikme ölçümü; Firefox sınırlamasının yazılı olması. |
| C07 | Premium istihbarat paketi anahtar tasarımı: tek `key_id` altında kiracı başına HKDF anahtarları; yayımlanan küresel şifreli paket çözülemiyor (CP-2). | Ücretli tehdit istihbaratı satılacaksa paket dağıtımı çalışmalıdır. | Engineering (ürün sahibi kararı) | Kısmen | Anahtar tasarımı kararı; yayımlanan paketin lisanslı kiracıda çözülüp lisanssızda reddedilmesi. |
| C08 | Yatırımcı metrik sözlüğü onayı (INV-001). | Alıcıyı değil yatırımcı görüşmesini etkiler; aynı metrikler satış materyaline girerse B21'e tabidir. | Finance + Legal | Hayır | Her metrik için formül, payda, kaynak, aday/ortam, gözlem penceresi, sahip ve onay. |

## Ek A — Kaynak eşleme

Her kaynak kimliği en az bir satıra eşlenmiştir. Bir kimlik iki satırda geçiyorsa ilk satır
PoC dilimini, ikincisi sözleşme dilimini taşır.

| Kaynak | Satır |
|---|---|
| T01, T02 | A06 |
| T03, T04, T06 | B17 |
| T05 | C01 |
| T07, T08, T10 | B18 |
| T09 | C02 |
| T11 | C03 |
| T12, T13 | C04 |
| T14, T15, T16 | B16 |
| T17 | B05 |
| T18, T19, T20, T21, T43, T44, T45, T46 | B13 |
| T22, T42 | B14 |
| T23, T24, T25 | B15 |
| T26, T27, T31 | B11 |
| T28 | A03 |
| T29 | A07, B05 |
| T30 | B09 |
| T32 | B10 |
| T33 | B04 |
| T34, T35 | B22 |
| T36 | B23 |
| T37 | B03 |
| T38 | C05 |
| T39 | B24 |
| T40 | A12, B10 |
| T41 | B25 |
| T47 | A09 |
| COM-001 | B01 |
| COM-002 | B02 |
| COM-003 | A13, B03 |
| COM-004 | B04 |
| COM-005 | A12, B10 |
| COM-010 | A06, B06 |
| COM-011 | B12 |
| COM-012 | B05 |
| COM-013 | B09 |
| SEC-EXT-001 | B07 |
| POV-001 | B20 |
| INV-001 | C08 |
| CLM-001 | A17, B21 |
| AIDR-016 | A02 |
| AIDR-019 | B13 |
| AIDR-044 | B11 |
| AIDR-049 | A06, A03 |
| AIDR-050 | B05 |
| AIDR-051 | C03 |
| AIDR-052 | B09 |
| AIDR-070 | A15 |
| AIDR-079, AIDR-080 | A16 |
| Kimlik bilgisi sızdırma (`ask`), `wget --post-file`, `tftp put` | A10 |
| PRD-15 | A11, B23 |
| BG-10, BG-LIVE | A09 |
| BG-11 | C06 |
| CP-1 | B13 |
| CP-2, PII-NER | C07, C05 |
| OPS-1 (dış: release yolu) | A07 |
| CON-6 | A06, B06 |
| CON-12, CON-14 | B06 |
| MSC-4 | B18 |
| PRD-10 | A12 |
| SEC-EXT (ga-gap-plan dış) | B07 |
| 15 Ekim: canlı site API 500 / Clerk anahtarları | A01 |
| 15 Ekim: `app.aidr.singularityrd.com` çözülmüyor | A02 |
| 15 Ekim: demo modundaki panel gerçek uçlara bağlı değil | A03 |
| 15 Ekim: model kötü niyetli demo istemlerini reddediyor | A04 |
| 15 Ekim: Windows `dist/license` / `dist/LICENSE` çakışması | A05 |
| 15 Ekim: Browser Guard canlı sitelerde doğrulanmadı | A09 |
| 15 Ekim: masaüstü uygulaması yok | B19 |

## Ek B — Bu çalışmada yapılanlar (15 Ekim 2026)

- Satış, satın alma, README ve site metinlerindeki desteklenmeyen veya eski iddialar düzeltildi
  ve claim registry ile eşlendi (A17/B21'in kod tarafı; onay açık).
- CLI komutlarının kullanıcıya dönük çıktısı Türkçeleştirildi ve TR modunda İngilizce metin
  kalmadığını denetleyen test eklendi (A11'in CLI dilimi).
- Bu liste oluşturuldu. Hiçbir dış kapı kapatılmadı; karar NO-GO olarak kalır.
